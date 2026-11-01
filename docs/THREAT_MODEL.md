# sbx threat model

Status: **Milestone 2**. This document is updated at the end of every
milestone. An entry in the matrix becomes `enforced` only when the stated test
has actually passed.

## 1. Assets

The sandbox exists to protect the host user's data and environment from code
they chose to run but do not trust. Assets include:

- SSH private keys, GPG keys and agent sockets.
- Cloud, API, package-registry and source-control credentials.
- Browser profiles, cookies, session tokens and password-manager databases.
- Tokens and secrets present in the invoking environment or command line.
- Other projects' source, documents, mail, chat history and personal files.
- The host's LAN, local services, router and internet access.
- Host process integrity: the user's shell, editor, agent processes and
  terminal session.
- Host system state: hostname, time, mounts, kernel modules, firewall.
- The integrity of read-only system files used to run the target.

## 2. Adversary

The adversary is **the program(s) the user asks sbx to run**, including code
they download or generate. Assumed capabilities:

- Runs with the invoking user's uid/gid (mapped to the same ids inside the
  sandbox), can make arbitrary Linux syscalls, allocate memory, create threads,
  fork, exec other programs, open/read/write files, create symlinks and
  hardlinks, race operations, and send signals inside its own namespace.
- May deliberately probe for holes: `/proc`, `/sys`, inherited descriptors,
  environment, argv, cwd, terminal ioctls, abstract unix sockets, `..`
  traversal, symlinks that point outside allowed trees, hardlinks, setuid
  binaries, namespace and mount syscalls, `ptrace`, and malformed/oversized
  arguments to any sbx-provided interface.
- May try to exploit a bug in sbx, in the way sbx builds the sandbox, or in the
  observer that reads event data.

The adversary **does not**:

- Have a kernel or hardware exploit.
- Have root on the host, or any host capability the invoking user lacks.
- Control the invoking shell, the sbx binary, or the contents of read-only
  system directories before sbx starts.
- Have physical access to the machine.

## 3. Security goals (testable)

The allowed set for filesystem goals is defined as: the minimal runtime
directories mounted read-only by sbx, the synthesized sandbox `/etc`, the
sandbox-private `/tmp`, the sandbox `/proc` belonging to its own pid namespace,
the minimal `/dev`, and exactly the paths the user granted with `--ro`/`--rw`.
Anything else is outside the allowed set.

- **G1 — Filesystem confinement.** A target process cannot read a host file
  outside the allowed set, and cannot modify a host file outside `--rw` paths.
  In particular it cannot read the invoking user's home, SSH/GPG/cloud/browser
  data, another project, the host's `/etc`, host `/proc`, or host `/sys`;
  cannot escape through `..` or a symlink; and cannot read secrets from the
  environment or from inherited file descriptors that sbx failed to close.
  *Tests:* canary reads (direct, traversal, symlink), host-vs-synthesized
  `/etc/passwd`, env-secret read, inherited-fd read.
- **G2 — Network isolation.** By default a target cannot reach the host
  loopback, LAN, internet, host abstract unix sockets, or unix sockets on the
  host filesystem. Only a sandbox-private loopback exists, and it is not the
  host's loopback. *Tests:* connect to a host TCP listener, connect to an
  external-style address, connect to a host-created abstract unix socket,
  verify only sandbox loopback is configured.
- **G3 — Process and terminal isolation.** A target cannot list, signal,
  trace, inspect, or inject input into host processes. It sees only its own
  pid namespace; `/proc` exposes only that namespace; it has no controlling
  terminal from the host, so `TIOCSTI` cannot type into the host terminal.
  *Tests:* enumerate `/proc`, signal a host pid, `ptrace` a host pid,
  `process_vm_readv`, `pidfd_open`/`pidfd_getfd`, `TIOCSTI` when a pty is
  available.
- **G4 — No persistent host changes.** A target cannot write outside `--rw`
  paths, cannot write into `--ro` paths or read-only system mounts, and cannot
  change host system state (hostname, domain name, time, mounts, modules).
  Sandbox `/tmp` and the new root are ephemeral. *Tests:* write outside/inside
  `--ro`, verify host files unchanged, hostname change does not affect host.
- **G5 — No privilege gain.** A target cannot gain uid/gid/capabilities,
  cannot benefit from setuid/setgid or file capabilities, and cannot create
  new namespaces, mount, `setns`, `chroot`, load modules, kexec, or otherwise
  acquire authority over the host. `CapEff`, `CapPrm`, `CapBnd`, `CapInh` and
  `CapAmb` are zero and `NoNewPrivs` is 1. *Tests:* parse `/proc/self/status`,
  run a setuid binary, call `mount`/`unshare`/`setns`/`chroot`, module and
  kexec syscalls, plus `bpf`, `perf_event_open`, `userfaultfd`, `io_uring`,
  keyring and `open_by_handle_at` probes.
- **G6 — Bounded lifetime.** When `sbx` exits or is killed, every process it
  started is gone; no target process survives as an orphan with access to host
  resources. *Tests:* kill `sbx` while a target spawns children and assert the
  whole tree is gone; parent-death signal and pid-namespace init behaviour.

Every future test names the goal it covers. A test that cannot run prints
`SKIPPED: <reason>` and is not counted as passing.

## 4. Non-goals

- **Kernel vulnerabilities.** A bug in the kernel, an LSM, seccomp, or a
  filesystem that lets the adversary escape is outside this threat model. sbx
  reduces attack surface; it cannot make a buggy kernel safe.
- **Hardware side channels** (Spectre-class, cache, power, electromagnetic)
  and microarchitectural leakage.
- **Covert channels** through timing, shared caches, disk state, or
  intentionally writable paths.
- **Resource exhaustion / denial of service.** CPU, memory, fork bombs, inode
  and disk exhaustion are not bounded yet. cgroup limits are informational in
  `sbx doctor` only.
- **GUI, Wayland, X11, D-Bus, GPU, audio and input devices.** None are exposed
  by the sandbox; displaying a GUI program is out of scope.
- **A malicious host user with the same uid.** Another process running as the
  invoking user can inspect the sbx supervisor or race host-side path
  resolution. The invoking user and their other processes are trusted.
- **Protecting data the user explicitly grants** with `--ro`/`--rw`, including
  the confused-deputy case where the grant is a sensitive directory. The
  dangerous-path check is a guardrail, not a new security boundary once
  explicitly overridden.
- **Terminal output control.** sbx forwards the target's stdout/stderr; it does
  not filter terminal escape sequences. `TIOCSTI` input injection is blocked,
  but output-based terminal manipulation is not.
- **Supply-chain compromise** of host binaries, the Rust toolchain, or the
  read-only system directories that are bind-mounted.
- **Physical access**, firmware, and offline attacks.
- **Running sbx as root.** Rootless operation is the supported mode; running as
  root would invalidate the mapping and capability assumptions. sbx must refuse
  or clearly warn (Milestone 1).

## 5. Trust boundaries and sequence of trust

### Boundaries

| Boundary | Trust |
|---|---|
| Host user and the sbx binary | Trusted. The user chooses the command and grants paths. |
| Host kernel and LSMs | Trusted for isolation, but **shared** and therefore an escape surface if buggy. |
| sbx supervisor (parent, outside the target's namespaces) | Trusted. It must not make enforcement decisions from target-controlled memory. |
| Target process and everything it spawns | **Untrusted.** All arguments, paths, memory, output and event data are untrusted. |
| Read-only host system mounts (`/usr`, `/lib*`, ...) | Trusted content for execution, still mounted `ro,nosuid,nodev`. |
| Invoking environment | Trusted source, but **not inherited**; only an allowlist is passed. |
| Host terminal | Trusted, but target has no controlling terminal; target output is untrusted data. |
| Event stream (`--events`) | Produced from untrusted target behaviour; consumers must treat it as observations, not verdicts. |

### Sequence before the sandbox exists

Everything in this list happens in the trusted parent, before the target can
run. The target must not be able to influence any of it:

1. Parse CLI arguments; reject unknown/malformed values.
2. Resolve and canonicalise requested host paths; reject missing paths and
   dangerous locations unless explicitly overridden.
3. Probe required kernel features and build the protection plan; fail closed
   with exit `124` if a required mechanism is unavailable.
4. Build the complete mount table, environment vector, seccomp program,
   Landlock ruleset, and all `CString`/argv buffers.
5. `fork()` while single-threaded.
6. Create the user namespace and have the parent write `setgroups=deny`,
   `uid_map`, `gid_map` (host uid/gid mapped to the same ids).
7. Create mount, pid, net, ipc and uts namespaces together.
8. Build the new root on tmpfs: read-only system binds, synthesized `/etc`,
   fresh `/proc`, minimal `/dev`, private `/tmp`, user `--ro`/`--rw` mounts.
9. `pivot_root` into it and detach the old root.
10. Drop every capability, set `no_new_privs`, apply Landlock, install the
    seccomp filter, start a new session, close inherited descriptors, set
    `PDEATHSIG`.
11. `execve` the target.

After step 11 the target is untrusted. The supervisor only waits, forwards
signals, reaps, and (Milestone 3) observes events. It never asks the target
"may I?" and never treats target memory as a policy input.

## 6. Known weak spots (stated honestly)

- **Shared kernel.** Namespaces, Landlock and seccomp are kernel features. A
  kernel bug is a complete escape. sbx narrows the interface but cannot fix the
  kernel.
- **User namespaces enlarge kernel attack surface.** They let an unprivileged
  user exercise filesystem, networking and mount code that was historically
  root-only. This is a deliberate trade for rootlessness.
- **TOCTOU in seccomp user-notify.** The target can change memory between the
  syscall and the supervisor reading it, and between two supervisor reads.
  Therefore user-notify is **observation only**: sbx always resumes the syscall
  (or lets the enforcement layers decide) and never makes an allow/deny
  decision from a path pointer. Notification ids are re-validated before and
  after reads.
- **Confused deputy in bind mounts.** Mounting a user-supplied path exposes
  exactly that subtree. If the user grants `~/.ssh`, the target can read it.
  The dangerous-path list reduces accidents; `--i-know-this-is-dangerous` is an
  explicit transfer of risk.
- **Host-side path races.** Canonicalisation happens before the sandbox is
  built. A same-uid host process could swap a path component between
  canonicalisation and mount. Same-uid host processes are outside the threat
  model, but the race is real; future hardening could use `openat2` with
  `RESOLVE_*` and mount by fd.
- **Seccomp is a denylist.** Unknown future syscalls and unlisted interfaces
  are allowed by default. The list is reviewed against the running kernel's
  syscall table (`docs/SECCOMP.md`) and backed by Landlock/mount/namespace
  layers rather than trusted alone. Conditional rules cover `ioctl`
  (`TIOCSTI`), `clone` (`CLONE_NEW*`) and `clone3` (`ENOSYS`). Non-native and
  x32 syscall ABIs are refused with `EPERM` rather than interpreted through
  the native table; 32-bit programs therefore do not run.
- **Landlock ABI coverage varies.** Older ABIs cannot restrict every access
  right (for example `REFER` or `TRUNCATE`). sbx uses only what the running
  kernel advertises and refuses when Landlock is absent unless the user
  explicitly passes `--allow-degraded=landlock`, in which case the summary
  reports the layer as off. `IOCTL_DEV` is deliberately not handled because
  inherited terminal descriptors point outside the sandbox hierarchy;
  `TIOCSTI` is blocked by seccomp instead.
- **No resource limits yet.** A target can consume all CPU/memory/disk and
  deny service to the host. This is an explicit current non-goal.
- **Fresh `/proc` still exposes kernel interfaces.** sbx mounts a private
  `/proc`; it must be reviewed for writable sysctls and information leaks.
  Until that review and its tests pass, G3 is only partial.
- **Terminal output is untrusted.** Escape sequences can manipulate the user's
  terminal; sbx does not sanitise output.
- **The observer can be attacked.** Milestone 3's supervisor parses
  target-controlled memory and must bound buffers, validate ids, and count
  drops. Observation failure must never become a sandbox escape.

## 7. Protections vs goals matrix

Legend: **enforced** = implemented and proven by a test; **planned** = designed
for a later milestone; **partial** = implemented but with a documented gap;
**observation** = records attempts but does not enforce.

Milestone 2 status: the Landlock and seccomp layers and their tests pass on the
development host (kernel `7.3.0-4-cachyos`, Landlock ABI 11). The evidence is
`crates/sbx-sys` filter unit tests, `crates/sbx-cli/tests/escape_battery.rs`
with `crates/sbx-escape`, `crates/sbx-cli/tests/compatibility.rs`, and the
test-only `crates/sbx-cli/tests/landlock_only.rs` build. G3 remains **partial**
because no pty was available, so the live `TIOCSTI` attempt printed `SKIPPED`;
the seccomp filter's `TIOCSTI` rule is unit-tested, but that is not a
replacement for the live attempt. `ptrace`, `process_vm_readv`, `pidfd_open`
and the other seccomp probes are now covered by positive controls outside and
`EPERM` inside.

| Protection | G1 files | G2 net | G3 proc/tty | G4 persistence | G5 privilege | G6 lifetime |
|---|---|---|---|---|---|---|
| User namespace + uid/gid map | enforced | — | enforced | enforced | enforced | — |
| Mount namespace + `pivot_root` new root | enforced | — | — | enforced | — | — |
| Read-only `nosuid,nodev` system binds | enforced | — | — | enforced | enforced | — |
| Synthesized `/etc` (no host `/etc`) | enforced | — | — | enforced | — | — |
| Private `/tmp` tmpfs | enforced | — | — | enforced | — | — |
| Net namespace, loopback only | — | enforced | — | — | — | — |
| Pid namespace + private `/proc` | enforced | — | enforced | — | — | enforced |
| Close inherited fds | enforced | enforced | enforced | — | — | — |
| New session, no host controlling tty | — | — | partial | — | — | — |
| Environment allowlist | enforced | — | — | — | — | — |
| Drop all capabilities | — | — | — | — | enforced | — |
| `PR_SET_NO_NEW_PRIVS` | — | — | — | — | enforced | — |
| `PDEATHSIG` + pidns init/reaping | — | — | — | — | — | enforced |
| Path canonicalisation + dangerous-path guard | enforced | — | — | enforced | — | — |
| Landlock ruleset mirroring mounts | enforced | — | — | enforced | — | — |
| Seccomp denylist (`EPERM`) | enforced | — | enforced | — | enforced | — |
| Seccomp user-notify supervisor | planned | planned | planned | planned | — | — |

Milestone 2 enforces G1, G2, G4, G5 and G6 for the tested attacks, and adds a
second, independent filesystem layer for G1/G4. G3 is partial for the reason
above. The seccomp row covers the tested syscall families; it is a denylist and
does not claim to cover every future syscall. G5 no longer has a partial
seccomp row: the previous Milestone 1 namespace guard has been replaced by the
broader profile documented in `docs/SECCOMP.md`.
