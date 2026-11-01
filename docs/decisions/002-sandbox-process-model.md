# 002 — Sandbox process model (Milestone 1)

Status: accepted for Milestone 1. Decision record `001` is reserved for the
Milestone 3 monitoring design.

## Context

`sbx` must build a rootless sandbox and then run an untrusted target without
ever letting the target influence setup. The work has to happen while the
process is still single-threaded, because `unshare(CLONE_NEWUSER)`, `fork()` and
seccomp filter installation all have thread-related failure modes. Error
reporting also has to survive a child that is already inside a chroot-like
environment and has no useful `/proc`.

## Decision: three processes

```
P  CLI process, trusted, outside every namespace
└── A  supervisor, first child; enters user namespace, builds the root
    └── B  target, PID 1 in the new pid namespace; execs the program
```

1. **`P` validates everything first.** It canonicalises `--ro`/`--rw` paths,
   applies the path policy, resolves the command against the sandbox `PATH`,
   builds the mount plan, environment vector and every `CString`/pointer array,
   probes required kernel mechanics, then and only then forks. After the fork
   `A` never allocates, formats, locks or calls `std::fs`.
2. **`A` enters the user namespace.** `P` writes `/proc/<A>/setgroups` =
   `deny`, then `uid_map` and `gid_map`, mapping the invoking uid/gid to the
   same ids. A handshake pipe makes `A` wait until both maps are written.
3. **`A` creates mount, uts, ipc and net namespaces together**, makes
   propagation private, builds the tmpfs root and its bind mounts, calls
   `pivot_root`, detaches the old root, and only then unshares the PID
   namespace.
4. **`A` forks `B`.** `B` is PID 1 in the new PID namespace, mounts the fresh
   `/proc` (which must happen from inside that namespace), closes inherited
   descriptors, drops capabilities, sets `no_new_privs`, installs the seccomp
   guard, changes directory and `execve`s the target.
5. **`A` relays `B`'s raw wait status to `P`** over a close-on-exec pipe. `P`
   decodes it into the exit code (`N`, or `128+N` for a signal). `A` and `B`
   both set `PR_SET_PDEATHSIG(SIGKILL)`; if `P` dies, the tree dies.

Errors are fixed-size frames, not formatted strings: `A` and `B` send a stage
byte plus a little-endian errno. `P` turns those into a readable message and
exit code. This keeps the post-fork path to async-signal-safe syscalls.

## Why `pivot_root` instead of `chroot`

`chroot` changes the root only for path resolution. A process that keeps a
descriptor to the old root, or that can mount, can escape it. `pivot_root` moves
the old root under the new one and `A` immediately detaches it with
`umount2(MNT_DETACH)`, so the old host root is no longer reachable by path. The
runner still installs a seccomp guard afterwards, so the target cannot reverse
the operation.

## Why the target is PID 1

A new PID namespace needs an init process. Making the target PID 1 gives it a
private `/proc` with no host pids visible, and it means the kernel kills every
remaining process in the namespace when PID 1 exits. The trade-off is that PID 1
has special signal semantics inside its own namespace: signals sent by processes
*inside* the namespace that PID 1 does not handle are ignored by the kernel.
Signals delivered from the host supervisor still terminate it and are relayed
as `128+N`. This is documented in `docs/EXIT_CODES.md`.

## Capability drop and the `capset` buffer

Ambient capabilities are cleared first, then the bounding set is dropped one
capability at a time (`PR_CAPBSET_DROP` has no set-wide form), then `capset`
clears effective, permitted and inheritable.

`capset` with `_LINUX_CAPABILITY_VERSION_3` requires **two** 12-byte
`__user_cap_data_struct` values (24 bytes total), one for capabilities 0–31 and
one for 32–63. The first implementation passed a shorter buffer; the kernel
rejected it with `EPERM` and the sandbox failed closed with exit `124`. The
buffer size is now explicit in `sbx-sys::drop_all_capabilities`.

## Device-node bind mounts

All ordinary bind mounts use `MS_NOSUID | MS_NODEV`. The minimal `/dev` binds
(`null`, `zero`, `full`, `random`, `urandom`, `tty`) are the one documented
exception: they are mounted `MS_NOSUID` **without** `MS_NODEV`, because a
device node mounted `nodev` cannot be opened through that mount. The containing
`/dev` tmpfs is `MS_NOSUID`. No other host device node is exposed.

## Seccomp guard in Milestone 1

The guard is deliberately narrow: it denies `unshare`, `setns`, `mount`,
`umount2`, `pivot_root`, `chroot`, `clone` with namespace flags, and returns
`ENOSYS` for `clone3` so libc falls back to `clone`, whose flags are checked.
Everything else is allowed. This is a *denylist*, not the full Milestone 2
profile; the mount namespace and capability drop are the primary enforcement.
The architecture check kills a process using a non-native syscall ABI instead
of misinterpreting syscall numbers.

## Defaults

- Sandbox cwd: `/home/sbx` (created mode `0700` inside the tmpfs root).
- Hostname: `sbx`, unless `--hostname` supplies a validated name.
- `HOME`: always `/home/sbx`; `--env HOME` is refused so a grant cannot
  silently redefine the target's home.
- Environment: empty base plus `PATH`, `HOME`, `TERM`, `LANG`, and exactly the
  `--env` names the user asks for.

## Known gaps

- Landlock is not active in Milestone 1; the protection summary says so.
- Seccomp user-notify monitoring is not active in Milestone 1.
- The seccomp denylist does not yet cover `ptrace`, `pidfd_*`, modules, kexec,
  bpf, io_uring and the rest of the Milestone 2 design.
- Host-side path canonicalisation races with a same-uid process are outside the
  threat model and are documented in `docs/THREAT_MODEL.md`.
