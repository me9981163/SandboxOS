# Seccomp profile

Status: **Milestone 2**. The profile is a default-deny-by-list, installed in the
target after `PR_SET_NO_NEW_PRIVS` and after Landlock, immediately before
`execve`. If installation fails, the target is not executed and `sbx` exits
`124`. There is no best-effort mode.

The filter returns `EPERM`, not `SECCOMP_RET_KILL_PROCESS`. A denied program can
report the failure and continue, which keeps ordinary tools from dying without
explanation. `EPERM` is also the errno the kernel itself uses for many of these
operations when the caller lacks privilege, so a sandboxed program sees a
familiar refusal rather than a crash.

This layer is **defence in depth**. The mount, PID, network, IPC and user
namespaces, capability dropping and Landlock are the primary boundaries. The
filter exists so that one mistake in the namespace or mount setup is not enough
to reach a dangerous interface.

## Filter layout

The BPF program is built in the parent before `fork()` and installed in the
target. It performs these checks in order:

1. **Foreign syscall ABI.** If `seccomp_data.arch` is not `AUDIT_ARCH_X86_64`,
   return `EPERM`. This is a fail-closed refusal, not an attempt to filter a
   table sbx has not verified.
2. **x32 ABI.** On x86-64, x32 syscall numbers set bit 30. If that bit is set,
   return `EPERM`. Otherwise a process could use the native arch value with a
   different numbering and bypass the denylist.
3. **Denylist.** Compare the syscall number against the list below; match
   returns `EPERM`.
4. **`clone3`.** Return `ENOSYS`. Current glibc probes `clone3`, and `ENOSYS`
   makes it fall back to `clone`, whose flags the next rule can inspect.
5. **`ioctl`.** Allow everything except `TIOCSTI`, which returns `EPERM`.
   Argument 1 (the request) is read from `seccomp_data.args[1]`.
6. **`clone`.** Allow unless argument 0 contains any `CLONE_NEW*` namespace
   flag (`NEWNS`, `NEWUTS`, `NEWIPC`, `NEWUSER`, `NEWPID`, `NEWNET`,
   `NEWCGROUP`, `NEWTIME`); those return `EPERM`.
7. Everything else is allowed.

`SECCOMP_RET_USER_NOTIF` is not used in this milestone. Observation arrives in
Milestone 3 and never decides access.

## Denylist, group by group

Every syscall below returns `EPERM`. The reason is the capability the call
would give the target if the other layers were absent or mistaken.

### Tracing and cross-process memory

| Syscall | Why it is denied |
|---|---|
| `ptrace` | Attach to, read, write or single-step another process. Within the sandbox that is still a route to the supervisor or to another sandboxed process. |
| `process_vm_readv` | Read another process's memory without `ptrace`. |
| `process_vm_writev` | Write another process's memory without `ptrace`. |
| `kcmp` | Compare kernel resources between processes; a side channel for identifying shared objects and inferring host state. |
| `pidfd_open` | Obtain a descriptor for an arbitrary PID. |
| `pidfd_getfd` | Duplicate another process's file descriptor, including a host descriptor if a pid were reachable. |
| `pidfd_send_signal` | Signal a process through a pidfd without the usual PID-namespace path. |

### Namespace, mount and file-handle manipulation

| Syscall | Why it is denied |
|---|---|
| `unshare` | Create further namespaces, including a user namespace that would re-open privileged kernel paths. |
| `setns` | Join another namespace, including a host namespace if a descriptor leaked. |
| `mount`, `umount2` | Change the mount table; the mount namespace is private, but a mistake must not be enough. |
| `pivot_root` | Replace the root; only the supervisor should do this. |
| `chroot` | Substitute a root without the kernel's `pivot_root` guarantees. |
| `fsopen`, `fsconfig`, `fsmount`, `fspick`, `move_mount`, `open_tree`, `mount_setattr` | The new mount API, which can create and move mounts without the legacy `mount` entry point. |
| `open_by_handle_at` | Open a file from a file handle, bypassing path-based checks and potentially crossing mount boundaries. |
| `name_to_handle_at` | Obtain a file handle usable with `open_by_handle_at`. |

### Kernel modules and kexec

| Syscall | Why it is denied |
|---|---|
| `init_module`, `finit_module`, `delete_module` | Load or unload kernel code. Rootless callers cannot normally succeed, but the call must not be reachable. |
| `kexec_load`, `kexec_file_load` | Replace the running kernel. |

### BPF, perf, userfaultfd, io_uring and keyrings

| Syscall | Why it is denied |
|---|---|
| `bpf` | Load eBPF programs and maps; a large, historically bug-prone kernel surface. |
| `perf_event_open` | Create performance counters that can observe other processes and the host. |
| `userfaultfd` | Manipulate page faults; useful for heap exploits and for racing kernel copies. |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | A second, asynchronous syscall surface with a history of kernel bugs. The target does not need it. |
| `keyctl`, `add_key`, `request_key` | Access the kernel keyring, which can hold host credentials and persistent keys. |

### Host system state

| Syscall | Why it is denied |
|---|---|
| `reboot` | Reboot or halt the host. |
| `swapon`, `swapoff` | Change swap, exposing or corrupting memory. |
| `acct` | Enable process accounting. |
| `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex` | Change the clock; time is shared even when namespaces isolate other state. |
| `sethostname`, `setdomainname` | Change the UTS namespace. sbx sets the hostname before exec; the target must not alter it further. |
| `syslog` | Read or clear the kernel log, which can contain host secrets. |
| `iopl`, `ioperm` | Obtain raw I/O port access. |
| `fanotify_init` | Create a host-wide filesystem notification group. |
| `quotactl` | Change disk quotas on host filesystems. |

## Deliberately allowed

These calls are not denied, and the reason matters:

- `clone` without namespace flags, `fork`, `vfork`, `execve`, `execveat`:
  ordinary process creation and execution inside the sandbox.
- `clone3` is answered with `ENOSYS`, not `EPERM`, so libc falls back to
  `clone`; `clone3` cannot create a namespace because the fallback is filtered.
- `ioctl` except `TIOCSTI`: terminals and devices need other requests.
- `openat2`: path resolution is restricted by Landlock and the mount layout,
  and `openat2` cannot create a mount.
- `memfd_create`, `process_madvise`, `prctl`, `seccomp`: ordinary runtime and
  self-management calls. A target that installs a *stricter* filter only hurts
  itself; `prctl` cannot remove the filter.
- File and network calls: the mount, net and Landlock layers decide what is
  reachable.

## Kernel syscall-table review

The list was checked against the running kernel's table, not against a memory
of syscall numbers. Commands used:

```
uname -r
ausyscall --dump
```

On the development host (`7.3.0-4-cachyos`) `ausyscall --dump` reports 383
named entries with a maximum number of 471. Every one of the 51 denylisted
names is present in that table, and no number in the list is attributed to a
different syscall. The list is built from `libc::SYS_*` constants, so a
toolchain that lacks a name fails to compile rather than silently using a
stale number.

Known discrepancies and non-goals:

- The table contains syscalls sbx deliberately allows (`openat2`,
  `memfd_create`, `process_madvise`, ordinary file and network calls). They are
  constrained by namespaces and Landlock, not by the filter.
- The table will grow. This is a denylist: an unlisted future syscall is
  allowed. That is why the filter is not the only layer and why the list is
  reviewed at each milestone.
- 32-bit and x32 programs are refused with `EPERM` rather than filtered through
  a second table. sbx does not claim compatibility with them.
- `ioctl` and `clone` are conditional rules, not unconditional denials; see the
  layout above.

## Tests

- `crates/sbx-sys`: a test-only BPF interpreter evaluates the real compiled
  program. It checks allow/deny for ordinary calls, every denylisted number,
  `clone3` → `ENOSYS`, foreign and x32 ABIs, `TIOCSTI` versus another ioctl, and
  `clone` with and without namespace flags.
- `crates/sbx-cli/tests/escape_battery.rs` plus `crates/sbx-escape`: each probe
  runs outside first as a positive control and then inside. The expected result
  is a non-`EPERM` result outside and `EPERM` inside. A timeout or an `error`
  is never counted as `blocked`.
- `crates/sbx-cli/tests/compatibility.rs`: common programs must still work. If
  one fails, the test attempts an `strace` diagnosis and names the syscall
  returning `EPERM`; it never relaxes the filter on its own.

## Installing the filter

`PR_SET_NO_NEW_PRIVS` is set first. `seccomp(SECCOMP_SET_MODE_FILTER, 0, …)` is
then called with the pre-built program. A non-zero return is fatal: the target
reports the stage and errno to the supervisor and `sbx` exits `124`. Landlock
is applied before seccomp so that the filter cannot block the Landlock
installation itself.
