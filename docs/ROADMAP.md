# sbx roadmap

Working name: **sbx**. Rootless Linux sandbox that runs untrusted programs and
reports what they attempted to do. Security correctness and honesty take
priority over features.

This session covers Milestones 0-3. One milestone at a time: implement, run the
verification gate, report in the `AGENTS.md` format, then stop for approval.

## Step 0 — Repository setup

- Initialise git (no remote, no commits).
- Cargo workspace: `sbx-core`, `sbx-sys`, `sbx-probe`, `sbx-runner`, `sbx-cli`,
  `sbx-escape`; `sbx-monitor` is added in Milestone 3.
- `publish = false` everywhere; `#![forbid(unsafe_code)]` everywhere except
  `sbx-sys`.
- `.gitignore` first: `/target`, editor files, generated files.
- CI running fmt, clippy, tests on Linux. Hosted runners may not allow every
  sandbox feature; escape tests that cannot run report `SKIPPED` visibly and
  never pass silently.
- Ask the human for copyright holder and license before adding LICENSE files.
- Save this milestone list as `docs/ROADMAP.md`.

## Milestone 0 — Threat model and `sbx doctor`

### 0.1 `docs/THREAT_MODEL.md`

Written before sandbox code. Contains assets, adversary, numbered testable
security goals (G1..), non-goals, trust boundaries and the sequence of trust,
honest known weak spots (shared kernel, user namespaces enlarging kernel attack
surface, TOCTOU in seccomp user-notify, confused-deputy bind mounts), and a
protections-vs-goals matrix kept updated each milestone.

### 0.2 `sbx doctor`

Probe, do not merely read config:

- kernel version;
- unprivileged user namespaces by actually calling `unshare(CLONE_NEWUSER)` in
  a forked child, including uid/gid mapping; explain likely causes of failure
  and what the human could change (never change it automatically);
- mount, pid, net, ipc and uts namespaces inside a user namespace;
- Landlock ABI through the syscall;
- seccomp filter mode and `SECCOMP_RET_USER_NOTIF`;
- `no_new_privs`;
- informational only: cgroup v2, `/dev/kvm`.

Output: readable table with `ok` / `degraded` / `unavailable` per feature and a
one-line fix hint; `--json` for machines. Exit 0 only when every required host
capability is available.

Tests: fakeable probe/classification logic, plus a smoke test running
`sbx doctor --json` and checking valid JSON with expected keys. Probes run for
real and need no root.

## Milestone 1 — `sbx run`: namespaces, new root, no network, no capabilities

```
sbx run [--ro PATH]... [--rw PATH]... [--env KEY]... [--cwd PATH] \
        [--hostname NAME] -- CMD [ARGS...]
```

- User, mount, pid, net, ipc and uts namespaces created together, rootless;
  host uid/gid mapped to the same ids; `setgroups=deny` before `gid_map`.
- New root on tmpfs, entered with `pivot_root` (not `chroot`): read-only
  `nosuid,nodev` bind mounts of the minimal system directories (`/usr`, `/lib*`,
  `/bin`, `/sbin` as present, merged-`/usr` handled), synthesized minimal
  `/etc`, fresh `/proc`, minimal `/dev`, private `/tmp`, and user `--ro`/`--rw`
  paths at their host absolute paths.
- Canonicalise and validate requested paths. Reject non-existent paths and
  obviously sensitive locations unless `--i-know-this-is-dangerous`; document
  the list (for example `~/.ssh`, `~/.gnupg`, `~/.aws`, all of `$HOME`, `/`,
  `/etc`, `/proc`, `/sys`, `/dev`).
- Network off by default: new net namespace with loopback only; document that
  this loopback is not the host loopback.
- Empty environment plus `--env KEY` allowlist and a small safe default
  (`PATH`, sandbox-private `HOME`, `TERM`, `LANG`).
- Drop all capabilities (bounding, permitted, effective, inheritable, ambient)
  and set `PR_SET_NO_NEW_PRIVS` before `exec`.
- New session (`setsid`), close inherited fds above stderr, `PR_SET_PDEATHSIG`,
  and a minimal init that reaps zombies and forwards signals.
- Whole tree dies when `sbx` is killed/exits. Exit codes: child status;
  `128+N` for signal `N`; `125` internal error; `124` refusal because a
  requested protection is unavailable. Documented.
- Protection summary on stderr before target start, suppressible with
  `--quiet`, never silently wrong. Lists enforced and not-applied protections.
- Fail closed if any required mechanism is unavailable, pointing to
  `sbx doctor`.

Tests: `sbx-escape` battery, run twice (positive control outside, sandboxed
inside), with canaries, per-goal outcomes, timeouts and visible `SKIPPED`.
Attempts cover file reads, `..`, symlink escape, environment secrets, inherited
fds, TCP/abstract-unix connections, host process inspection/signalling, writes
outside `--rw` and into `--ro`, capabilities/NNP, setuid, mount/unshare/setns/
chroot, `TIOCSTI`, host hostname isolation. Also argument/exit-code/stdin/
stdout/stderr passthrough, `--cwd`, missing command/path, dangerous path
refusal, orphan cleanup, and real read-only enforcement.

If the environment cannot create user namespaces, print `SKIPPED: <reason>` and
give exact commands to run elsewhere.

## Milestone 2 — Landlock and seccomp (defense in depth)

### Landlock

- Ruleset mirrors the mount layout (same ro/rw sets), applied after
  `no_new_privs` and before `exec`; a mount mistake must not be a single point
  of failure.
- Negotiate ABI explicitly. Fail closed if unavailable unless
  `--allow-degraded=landlock`; summary shows it off. No silent "best effort".
- Use only rights the available ABI offers (read, write, execute, refer,
  truncate, ...).

Tests: with mount-layer rules deliberately loosened in a test-only build, prove
Landlock alone still blocks outside access.

### Seccomp

- Default denylist profile returning `EPERM` (not kill) so ordinary programs
  degrade gracefully. Justify every syscall in `docs/SECCOMP.md`:
  tracing/cross-process memory; namespace/mount manipulation; module/kexec;
  bpf/perf/userfaultfd/io_uring/keyring/file-handles; system state. Review the
  list against the running kernel's syscall table and report discrepancies.
- Handle non-native syscall ABIs safely (x32 / 32-bit compat); test it.
- `clone3` returns `ENOSYS` so libc falls back to `clone`; filter `clone` flags
  and block `CLONE_NEW*`.
- Compatibility matrix for common programs; skip missing tools visibly. For
  failures, identify the exact blocked syscall and decide with the human
  whether to relax.
- Tests: blocked syscalls return the expected errno inside, positive controls
  outside, filter-construction unit tests, no Milestone 1 regressions.
- Fail closed if the filter cannot be installed.

## Milestone 3 — Observation: events and report

**Decision record first:** `docs/decisions/001-monitoring.md`, then wait for
approval before implementing. Compare seccomp user-notify + supervisor,
ptrace tracing, eBPF, and log-only approaches: observability, cost, security
risk, compatibility with the seccomp denylist (including blocking `ptrace`),
implementation difficulty. State exactly which crate/raw-BPF mechanism is
needed for user-notify, verified against crate source and docs.

After approval:

- Observation never decides allow/deny on pointer arguments. Always resume
  syscalls; events are "attempts observed", not verdicts. Document TOCTOU.
- Re-validate notification ids before and after reading target memory, as the
  seccomp documentation requires; handle unreadable/racing memory without
  crashing.
- Observe a small useful set: `open`, `openat`, `openat2`, `connect`, `bind`,
  `execve`/`execveat`, plus anything the decision record justifies. Measure
  overhead; notify filter only on selected syscalls.
- Supervisor outside the sandbox, distrusts target data, survives huge paths,
  malformed data and floods with a bounded buffer and counted drops.
- Event stream: JSON Lines, stable schema `ts`, `pid`, `kind`, `args`, `note`,
  written to `--events FILE`, never mixed with target stdout.
- `sbx report FILE`: summarize files outside baseline, connection attempts,
  programs executed, dropped events, anything unusual; human-readable and
  `--json`; clearly state these are *attempts observed*.
- Tests: schema; benign "fake malicious" fixture (canary in fake `~/.ssh`,
  local listener connection, write to fake `~/.bashrc`) proving blocking,
  event capture and report summary; event flooding and malformed memory;
  overhead on `find /usr -type f` with and without monitoring.

## Quality bar

Small readable functions; comments explain *why* (especially kernel interface
choices); no clever code where simple works. Every security claim is backed by
a test or command actually run; everything else is labelled "Uncertain". If the
sandbox can be escaped: stop, describe exactly, and wait for the human.
