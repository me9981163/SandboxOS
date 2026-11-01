# 001 — Monitoring: seccomp user-notify and the event report (Milestone 3)

Status: **proposed — awaiting human approval before implementation.**

This record is intentionally written before code. It compares the available
observation mechanisms, chooses one, and fixes the process model, event schema
and failure behaviour so that the implementation has no room to invent a
policy on the fly.

## Context

Milestone 2 enforces filesystem and syscall restrictions. It can block an
attempt, but it cannot tell the user what the target tried to do. Milestone 3
adds observation:

- a small set of syscalls is reported to a supervisor;
- the supervisor writes a JSON Lines event stream to a file chosen by the
  user;
- `sbx report FILE` summarises that stream;
- observation never changes whether a syscall is allowed.

The target is untrusted. It controls syscall arguments, pointer targets,
lengths, timing and the number of attempts. The supervisor is trusted but must
treat every byte read from the target as data, not as a decision input.

## Alternatives considered

| Mechanism | Observability | Cost | Security risk | Compatibility with the denylist | Difficulty |
|---|---|---|---|---|---|
| **seccomp user-notify + supervisor** | Exact syscall number, PID and register arguments for selected calls. Pointer contents (paths, sockaddrs) can be read from target memory. | Low when only selected syscalls notify. One notification round trip per selected call; a small amount of supervisor memory. | Supervisor must treat target memory as untrusted and must never decide allow/deny from it. Listener fd is a privileged handle that must not leak into the target after exec. | Does not require relaxing the denylist. The target still cannot use `ptrace`; the supervisor observes through the seccomp listener instead. Notify and deny rules must not overlap, because a `CONTINUE` response can override a lower-priority filter. | Medium: raw BPF return value, listener fd passing, ioctl protocol, poll loop, bounded memory reads. |
| **ptrace tracer** | Every syscall, registers and memory, plus signals. | High: two stops per syscall, context switches, complex fork/exec/thread handling. | Tracer can modify target registers and memory; large kernel interface; target can detect tracing. Requires a parent relationship under Yama (or `PR_SET_PTRACER`, which widens the boundary). | The **target's** `ptrace` remains denied; the tracer uses ptrace from outside. But monitoring all syscalls is far broader than needed, and a tracing bug can change the target, not merely observe it. | High. |
| **eBPF tracepoints / kprobes** | Good, including syscall entry events; can aggregate in kernel. | Medium to high; program load and map memory. | Requires `CAP_BPF`/`CAP_PERFMON` or root on most hosts; unprivileged BPF is disabled. Enormous kernel attack surface for a rootless tool. | Independent of seccomp, but unavailable in the supported rootless mode. | High and host-dependent. |
| **`SECCOMP_RET_LOG` / audit-only** | Kernel audit record of the syscall number and basic data. | Very low for the target, but auditd may be absent or configured elsewhere. | Logs go to the host audit stream, not a per-run file; no reliable attribution, bounding or redaction. Paths are not captured. | Works with the denylist, but gives almost no useful evidence for a report. | Low, but insufficient. |
| **fanotify / inotify** | Filesystem events only, and only for paths that exist and are mounted. | Low to medium. | Requires notification groups and permissions; no nonexistent-path attempts, no connect/bind/exec, no target PID for a blocked open. | Orthogonal, but cannot answer “what did the target try to open outside the sandbox?” | Medium, and the result is incomplete. |

**Chosen: seccomp user-notify with a supervisor process.** It is the only
mechanism that is rootless, bounded to the syscalls we care about, compatible
with the existing denylist, and able to report the attempt without granting
the target any new authority.

## Mechanism: raw BPF, no new tracing crate

No new BPF or tracing crate is added. The existing `sbx-sys` `FilterBuilder`
already emits the raw `struct sock_filter` program. Milestone 3 extends it with
a `SECCOMP_RET_USER_NOTIF` branch for the selected syscalls. The listener is
created with `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER,
&prog)`; the successful return value is the listener file descriptor.

The supervisor uses the raw ioctl protocol from `<linux/seccomp.h>`:

- `SECCOMP_IOCTL_NOTIF_RECV` with `struct seccomp_notif`;
- `SECCOMP_IOCTL_NOTIF_ID_VALID` with the notification id;
- `SECCOMP_IOCTL_NOTIF_SEND` with `struct seccomp_notif_resp` and
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.

Verification performed for this record (not yet used by code):

- The host header `/usr/include/linux/seccomp.h` defines
  `SECCOMP_FILTER_FLAG_NEW_LISTENER` (`1 << 3`), `SECCOMP_RET_USER_NOTIF`
  (`0x7fc00000`), `struct seccomp_notif`, `struct seccomp_notif_resp`, the
  three ioctl numbers, and `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (`1`).
- The locked `libc` version is `0.2.191` (`Cargo.lock`). Its source at
  `~/.cargo/registry/src/index.crates.io-*/libc-0.2.191/src/unix/linux_like/linux/mod.rs`
  already defines `seccomp_notif`, `seccomp_notif_resp`,
  `seccomp_notif_addfd`, `SECCOMP_IOCTL_NOTIF_RECV`, `SECCOMP_IOCTL_NOTIF_SEND`,
  `SECCOMP_IOCTL_NOTIF_ID_VALID`, `SECCOMP_FILTER_FLAG_NEW_LISTENER` and
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. No extra dependency and no hand-computed
  ioctl numbers are needed; `sbx-sys` still wraps the calls and validates
  return values.
- `SECCOMP_GET_NOTIF_SIZES` is used at startup to compare the kernel's struct
  sizes with `size_of::<libc::seccomp_notif>()` and
  `size_of::<libc::seccomp_notif_resp>()`. A mismatch refuses to run with
  `--events` (exit `124`) rather than using a mis-sized struct.

## Process model

The CLI process `P` is the supervisor and event writer. It is outside every
sandbox namespace and uses ordinary Rust (it is not a post-`fork` restricted
child).

```
P  CLI, trusted, outside all namespaces; owns the event file and listener
└── A  sandbox supervisor; builds root, waits for B
    └── B  target, PID 1 in its own PID namespace
```

Changes to the Milestone 2 flow:

1. When `--events FILE` is present, `P` creates a Unix
   `SOCK_SEQPACKET` socketpair before forking `A`. `A` inherits both ends and
   closes the read end immediately; it keeps the write end across its fork of
   `B` and closes its copy afterwards.
2. `B` installs the filter after `no_new_privs` and Landlock, exactly as
   today, but with a program that returns `USER_NOTIF` for the selected
   syscalls. The `seccomp()` call returns the listener fd.
3. `B` sends the listener fd to `P` with `SCM_RIGHTS` over the socketpair,
   closes the socketpair, then closes inherited descriptors, changes directory
   and `execve`s the target. The listener copy in `B` is closed before exec;
   `P` holds the only remaining handle.
4. `P` receives the listener, verifies the notification struct sizes, sets the
   listener non-blocking, and enters a loop that polls the listener and the
   existing status pipe. It reads the listener, captures what it can from
   target memory, responds `CONTINUE`, and writes a JSON line.
5. `A` is otherwise unchanged: it waits for `B`, reports the raw wait status,
   and exits. `P` drains the listener and event queue before returning.

The socketpair is created only when monitoring is requested. Without
`--events`, the process model and the filter are exactly Milestone 2's.

### Why `P`, not `A`, is the supervisor

`P` is fully outside the sandbox and can allocate, format JSON, use
`std::fs`, and bound its own queue. `A` is a post-`fork` process restricted to
async-signal-safe syscalls by `AGENTS.md`; making it parse paths and serialise
JSON would violate that rule.

Reading target memory from `P` was verified on the development host: with
`/proc/sys/kernel/yama/ptrace_scope` = `1`, a grandparent can
`process_vm_readv` its grandchild (tested directly; the call returned the
requested byte count). `P` is an ancestor of `B`, so this is within Yama's
restriction. If a host has a stricter policy, `process_vm_readv` fails with
`EPERM`/`EFAULT`; that is recorded per event as “path unreadable”, never
treated as a reason to deny the syscall. The limitation is documented in the
report.

## Which syscalls are observed

Only these return `USER_NOTIF`:

| Syscall | Why |
|---|---|
| `open`, `openat`, `openat2` | The path is the primary evidence for filesystem attempts outside the baseline. Flags show read versus write/create intent. |
| `connect`, `bind` | The endpoint is the primary evidence for network attempts. The network namespace already blocks them. |
| `execve`, `execveat` | Records programs the target tried to execute, including the initial target. |

Everything else is handled exactly as in Milestone 2. In particular, a syscall
on the denylist still returns `EPERM`; it is **not** notified. This is
deliberate: a `CONTINUE` response would run the syscall and could override a
lower-priority filter, and notification of a denied call would either bypass
the denial or require a policy decision from the supervisor. The consequence
is stated honestly: `mount`, `ptrace`, `bpf`, and the rest of the denylist do
not appear in the event stream; the target only sees `EPERM`.

`open` is included even though it is rare on modern x86-64 because it is cheap
and completes the file-open family. `write`, `unlink`, `rename` and similar
calls are not notified: a write or destructive operation on an existing file
is normally preceded by an open, whose path and flags are captured. This is a
documented observation gap, not a claim of complete audit.

### Invariants

- The notify set and the denylist are disjoint. A unit test asserts this.
- The notify branch is placed after the deny branches in the BPF program, so
  even an accidental overlap cannot turn a denial into an allowed syscall.
- Every notification is answered with `CONTINUE` (or left unanswered only when
  the notification id is no longer valid and the target has already gone).
  The supervisor never returns `EPERM` for a notified syscall.
- Landlock and the mount/namespace layers still run for the syscall after
  `CONTINUE`. Notification does not bypass them.

## Notification handling and TOCTOU

For each `SECCOMP_IOCTL_NOTIF_RECV`:

1. Validate the notification id with `SECCOMP_IOCTL_NOTIF_ID_VALID`.
2. Capture bounded data from target memory with `process_vm_readv` using the
   PID from the notification:
   - paths: at most 4096 bytes, stop at NUL, note truncation if no NUL;
   - sockaddrs: at most `sizeof(sockaddr_storage)`, reject a length larger than
     that, accept short lengths, parse `AF_UNIX` (including abstract names),
     `AF_INET` and `AF_INET6`;
   - `openat2`: read at most `sizeof(open_how)` and only trust fields inside
     the caller-supplied size.
3. Validate the notification id again.
4. Send `seccomp_notif_resp { id, val: 0, error: 0, flags: CONTINUE }`.

If id validation fails before or after the read, the target has exited or the
notification was cancelled; no response is sent and the event is recorded with
a note if a partial observation exists. If `process_vm_readv` fails, the event
still records the syscall number and PID with `path_unreadable: true` and the
errno in the note. An event is never dropped merely because memory was
unreadable.

**TOCTOU:** the path read in step 2 is only a snapshot. The target can change
the memory before the kernel executes the syscall after step 4. Therefore the
event says “attempt observed”, and the path is never used to allow, deny, or
resume the syscall. This is the kernel documentation's warning about
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`, and it is why the event schema's `note`
says the path is not resolved by sbx. `ID_VALID` before and after the read
prevents acting on a stale notification id; it does not make the memory
immutable.

The supervisor always responds with `CONTINUE` even for a path that looks
dangerous. Enforcement remains the job of Landlock, mounts, namespaces and the
denylist.

## Event schema (stable, version 1)

One JSON object per line. Every line has exactly these top-level fields:

```json
{"ts":"2026-10-31T12:34:56.789Z","pid":1234,"kind":"openat","args":{},"note":"..."}
```

- `ts`: RFC 3339 UTC with millisecond precision. Captured with
  `CLOCK_REALTIME` at notification receipt.
- `pid`: PID from the notification, as seen by `P` (host PID namespace). `0`
  for `session` and `summary`.
- `kind`: `session`, `open`, `openat`, `openat2`, `connect`, `bind`, `execve`,
  `execveat`, or `summary`.
- `args`: object whose shape depends on `kind` (below).
- `note`: human-readable string. For target attempts it says the syscall was
  continued and the arguments are not resolved by sbx. For unreadable or
  truncated data it says so.

The first line is a `session` record, written by `P` before the target starts:

```json
{"ts":"...","pid":0,"kind":"session","args":{"schema":1,"target":"/bin/ls","cwd":"/home/sbx","ro":[],"rw":[],"events":"/tmp/sbx-events.jsonl"},"note":"session metadata; not a target attempt"}
```

The last line written by a completed run is a `summary` record:

```json
{"ts":"...","pid":0,"kind":"summary","args":{"events":42,"dropped":0,"monitor_complete":true,"monitor_errors":[]},"note":"end of run"}
```

Argument shapes:

| Kind | `args` fields |
|---|---|
| `open` | `path`, `flags`, `path_truncated`, `path_unreadable`, `path_lossy` |
| `openat` | `dirfd`, `path`, `flags`, `path_truncated`, `path_unreadable`, `path_lossy` |
| `openat2` | `dirfd`, `path`, `flags` (from `open_how` if readable, otherwise null), `resolve` (if readable), `path_truncated`, `path_unreadable`, `path_lossy` |
| `connect`, `bind` | `family`, `address`, `port` (where applicable), `abstract` (Unix abstract socket), `addr_truncated`, `addr_unreadable` |
| `execve` | `path`, `path_truncated`, `path_unreadable`, `path_lossy` |
| `execveat` | `dirfd`, `path`, `flags`, `path_truncated`, `path_unreadable`, `path_lossy` |

`path` is a JSON string decoded as lossy UTF-8; `path_lossy: true` marks that
the original bytes were not valid UTF-8. The event is evidence, not a
round-trippable filename. A path with no NUL within the 4096-byte window is
truncated and flagged. A relative path is recorded as given, with `dirfd`; sbx
does not resolve it.

The event file is opened by `P` with `O_CLOEXEC | O_NOFOLLOW`, mode `0600`,
create and truncate. A relative `--events` path is resolved against the host
working directory. If the resolved file would be inside a `--ro` or `--rw`
grant, `sbx` refuses with exit `125`: otherwise the target could read, truncate
or forge its own audit trail. Parent directories must already exist.

## Bounded supervisor

`P` has a bounded in-memory queue (1024 fixed-size event records, each holding
at most 4096 bytes of payload). It responds `CONTINUE` before enqueuing, so a
slow disk cannot deadlock the target. If the queue is full, the event is
dropped and `dropped` is incremented. `P` drains the queue to the file between
poll iterations and once more at exit. The summary reports the exact counts.

A dropped event is not a hole in enforcement; enforcement never depended on
the event. The report says how many observations were lost. A write failure
(I/O error, disk full) is treated the same way as a full queue: stop writing,
record a monitor error, keep the target running, and print a warning to stderr
after it exits. The report file may then be incomplete; it must not silently
pretend otherwise.

Startup failures are different and are fatal before the target runs:

- `--events` requested but `SECCOMP_RET_USER_NOTIF` is unavailable;
- the notification struct sizes do not match the kernel's;
- listener creation, the `SCM_RIGHTS` send, or the receive fails;
- the event file cannot be created or written with the required flags.

These return exit `124` (unavailable required observation) or `125` (invalid
event path), and no target runs. Without `--events`, monitoring is off and the
summary says `[off] seccomp user-notify monitoring: disabled (no --events file)`.

## `sbx report FILE`

`sbx report FILE [--json]` reads the JSONL file and prints a human-readable
summary, or a stable JSON object with `--json`.

It reports:

- **Session:** target, cwd, grants, schema version, event file.
- **Files outside the baseline:** absolute `open`/`openat`/`openat2` paths that
  are not under `/usr`, the synthesized `/etc`, `/proc`, `/dev`, `/tmp`,
  `/run`, `/var`, `/home/sbx`, or a declared `--ro`/`--rw` grant. Relative
  paths are listed separately because sbx cannot resolve them.
- **Connections:** every `connect`/`bind`, with family and address; abstract
  Unix sockets and non-loopback addresses are called out.
- **Programs executed:** every `execve`/`execveat` path, with the initial
  target marked and paths outside `/usr` called unusual.
- **Sensitive names:** paths containing the same credential/name list used by
  the path policy (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.bashrc`, `id_rsa`,
  ...). This is a hint for the human, not a verdict.
- **Events:** total, dropped, malformed lines, monitor errors and whether the
  summary record was present.
- **Unusual:** a short list of concrete observations (write flags outside the
  baseline, non-loopback connection, execution outside `/usr`, unreadable
  paths, truncated paths).

The report opens with a prominent statement: **these are attempts observed,
not verdicts; the sandbox blocked what the kernel refused, and the report does
not re-evaluate policy.** If the `session` line is missing or the file ends in
a partial line, the report says the baseline is unknown or the tail is
incomplete instead of guessing.

`--json` shape (stable):

```json
{
  "schema": 1,
  "session": null,
  "events": {"total": 0, "dropped": 0, "malformed": 0, "complete": false, "errors": []},
  "files_outside_baseline": [],
  "relative_paths": [],
  "sensitive_paths": [],
  "connections": [],
  "programs": [],
  "unusual": [],
  "notes": ["Attempts observed, not verdicts."]
}
```

Report exit codes: `0` after a readable file, even if it contains suspicious
attempts; `125` if the file cannot be read or contains no valid event. Malformed
individual lines are counted and do not abort the report. `--json` does not
change stdout with target data; the report command runs no target.

## Tests planned

1. **Schema unit tests:** serialise/deserialise every event kind; required keys;
   unknown kinds; lossy/truncated paths; report JSON shape.
2. **Fake malicious fixture:** a temp fake home with a canary in `.ssh` and a
   fake `.bashrc`; a host TCP listener; run a target that tries to read the
   canary, connect to the listener, and write the fake `.bashrc`. Assert the
   canary is not returned, the events include the three attempts, and
   `sbx report` flags the paths/connection. The fake home is outside the
   sandbox unless explicitly granted; write attempts to a `--ro` fixture prove
   read-only enforcement as well.
3. **Unreadable/malformed memory:** extend `sbx-escape` (or a small test helper)
   with attempts that pass a NULL path pointer, a pointer to unmapped memory, a
   path with no NUL in the window, and a bogus sockaddr length. Assert the
   target gets the ordinary `EFAULT`/`EINVAL`, sbx does not crash, and the
   events carry `path_unreadable`/`path_truncated`/`addr_unreadable`.
4. **Flood and drops:** unit-test the bounded queue with a tiny capacity; run a
   multi-threaded opener inside the sandbox and assert the run completes, the
   summary accounting is consistent (`events + dropped` matches attempts the
   supervisor saw), and no malformed lines are produced. A fast host may drop
   zero events; the test must not pretend otherwise.
5. **Overhead:** time `find /usr -type f` with and without `--events` (median of
   several runs) and report the measured numbers. No arbitrary pass/fail ratio
   is asserted; the measurement is the result.
6. **No Milestone 1/2 regressions:** the full workspace gate, escape battery,
   compatibility matrix, Landlock proof and cleanup tests still run.

## Consequences and known gaps

- Events are observations, not a security boundary. A target can lie about
  paths, change memory, or stop generating events. The report says so.
- Denied syscalls are not events. An `EPERM` from the denylist is visible to
  the target but not to the report.
- Path capture is best-effort. A target that makes its memory unreadable or
  uses a host with a stricter Yama policy produces events without paths; the
  report must show that rather than infer a path.
- The event stream can be large. Only the supervisor queue is bounded; the file
  grows until the run ends. A future milestone can add rotation/limits.
- `--events` is per run and truncates the file. It is not a long-term audit
  log; the report is a snapshot.
- The listener fd is a privileged handle. It is sent directly to `P`, closed in
  `B` before `execve`, and never inherited by the target. A failure to send it
  is fatal rather than silently dropping observation.
- Adding `sbx-monitor` and user-notify changes the process model only when
  `--events` is present; the default run path and its overhead stay at
  Milestone 2 behaviour.

## Approval requested

Approve this record to implement:

- the combined deny/notify BPF program and listener handshake;
- `--events FILE`, the supervisor loop, the event schema and bounded queue;
- `sbx report FILE [--json]`;
- the tests above, including the fake malicious fixture, malformed memory,
  flooding and overhead measurement.

No Milestone 3 code is written until this record is approved.
