# AGENTS.md — sbx

This file is the authoritative working agreement for everyone (human or agent)
changing this repository. Read it before touching code.

## What sbx is

`sbx` is rootless Linux sandbox software. It runs untrusted programs inside a
restrictive sandbox and reports what those programs attempted to do. It is
security software: an unfounded claim is a defect, and a silent failure is
worse than a loud refusal.

## Principles

1. **Honest.** Every security claim must be backed by a test that was actually
   run or by a command whose output is quoted. Anything else is labelled
   "Uncertain". Never claim a protection that is not active.
2. **Fail closed.** If a required kernel mechanism is unavailable, or setup
   fails, refuse to run. Never silently degrade. The only exception is an
   explicit opt-in such as `--allow-degraded=landlock`, and the protection
   summary must show the degraded feature as off.
3. **Enforcement is separate from observation.** Mount namespaces, Landlock
   and seccomp enforce. `SECCOMP_RET_USER_NOTIF` events are observation only.
   Observation must never decide whether a pointer argument is allowed:
   target memory can change between check and use.
4. **Correctness over features.** Small, readable functions. Comments explain
   *why* a kernel interface or trade-off was chosen, not what the code does.
5. **No guessing.** If behaviour is unknown, probe it, test it, or state that it
   is unknown. Do not invent license terms, copyright holders, or security
   guarantees.
6. **No commits or tags** unless the human explicitly asks. Propose a
   Conventional Commit message and tag in the milestone report.
7. **Local-only development.** No runtime network calls. External test
   repositories go in `/tmp`, never in this repo. No files over 10 MB in the
   repo.

## Path boundary (hard rule)

Never read, list, copy, archive, or search anything outside the project
directory and `/tmp/sbx-*`. Never touch `$HOME`, `~/.ssh`, `~/.config`, or
another project. Create clean copies only with `git clone` or `git worktree`;
never with `cp`, `rsync`, `tar`, `find`, or shell globs. If a task appears to
require access outside those roots, stop and ask the human first. Cargo's
implicit use of its own cache is not permission to inspect `$HOME`.

## Crate layout

| Crate | Responsibility |
|---|---|
| `sbx-core` | Shared types: feature states, path policy, protection summary, event schema. No Linux syscalls. |
| `sbx-sys` | All `unsafe`, raw Linux syscall wrappers, fork/clone, namespace, mount, seccomp, Landlock bindings. Only crate allowed to use `unsafe`. |
| `sbx-probe` | Host capability probes used by `sbx doctor`; fakeable parsing/classification logic lives here. |
| `sbx-runner` | Sandbox construction and target execution (namespaces, new root, capabilities, Landlock, seccomp). |
| `sbx-cli` | `sbx` binary: argument parsing, output, exit codes. Thin. |
| `sbx-escape` | Escape-test helper. Emits one JSON line per named attempt. |
| `sbx-monitor` | Milestone 3 observation supervisor and event/report code. |

Every crate except `sbx-sys` starts with `#![forbid(unsafe_code)]`.
`publish = false` in every crate.

## Unsafe rules

- `unsafe` is permitted **only** in `sbx-sys`.
- Every `unsafe` block has a `// SAFETY:` comment naming the invariant that
  makes it sound.
- Validate all lengths, pointers and file descriptors at the `sbx-sys`
  boundary. Never let a raw kernel return value escape unvalidated.
- Do not add a dependency merely to avoid writing a small, auditable wrapper.
  Vendored or third-party code must be reviewed for what it actually does.

## Fork-safety rules

The sandbox child is forked from a Rust process. Between `fork()` and `execve()`
it must be treated as a restricted environment:

- Only async-signal-safe syscalls (`read`, `write`, `close`, `dup2`, `unshare`,
  `mount`, `pivot_root`, `prctl`, `seccomp`, `execve`, `_exit`, ...) are
  allowed. No `malloc`, no locks, no Rust formatting, no `std::fs`, no DNS.
- All paths (`CString`s), argument vectors and buffers are allocated **before**
  `fork()`.
- Errors are reported to the parent as a small fixed struct or errno over a
  pre-created pipe, then the child calls `_exit`.
- The parent is the only side allowed to use ordinary Rust after `fork()`.
- Never call `fork()` from a process with other threads alive. The CLI is
  single-threaded by design.

## Sandbox and enforcement rules

- Rootless only. No setuid helpers, no privileged daemon.
- Create user, mount, pid, net, ipc and uts namespaces together. Map the host
  uid/gid to the same ids inside (`setgroups` = `deny` before `gid_map`).
- Build a new root on a tmpfs and `pivot_root` into it; do not use `chroot`.
- The new root contains only the documented minimal system mounts, a
  synthesized `/etc`, a fresh `/proc`, a minimal `/dev`, a private `/tmp`, and
  the user's `--ro`/`--rw` paths at their host absolute paths.
- All bind mounts use `MS_NOSUID | MS_NODEV`. `--ro` paths use `MS_RDONLY`.
- Network is off by default: new net namespace with loopback only.
- Start from an empty environment. Pass only requested `--env` names plus the
  documented safe defaults.
- Drop all capabilities (bounding, permitted, effective, inheritable, ambient)
  and set `PR_SET_NO_NEW_PRIVS` before `exec`.
- New session; close inherited descriptors above stderr; set
  `PR_SET_PDEATHSIG`; reap the process tree.
- Exit codes: target status pass-through; `128+N` for signal `N`; `125` for
  internal `sbx` error; `124` for refusal caused by an unavailable required
  protection. Document any addition.
- Print a protection summary to stderr before the target starts. `--quiet`
  suppresses it, but never makes it wrong. List protections not applied.

## Escape-test rules

- `sbx-escape` runs named attempts and prints exactly one JSON object per
  attempt: `{"name","goal","outcome","detail"}` where outcome is `blocked`,
  `escaped`, or `error`.
- Every attempt names the security goal it tests (`G1`..`G5`).
- Integration tests run the battery **twice**: unsandboxed first as a
  **positive control**, then inside `sbx run`. Any attempt that is supposed to
  be possible for a normal process but does not show `escaped` outside makes
  the test inconclusive.
- Canaries: sensitive fixtures contain a unique random token generated by the
  harness. Reading the token is proof of escape; the token must never be
  reachable from the sandbox except through the attempted hole.
- Positive controls for blocked syscalls: run the same syscall outside and
  verify it succeeds or returns the expected non-blocked errno.
- Each attempt has a timeout. A timeout is `error`, never `blocked`.
- If a feature cannot be tested on the current host (for example no pty), the
  test prints `SKIPPED: <reason>` visibly. It must never pass silently.
- An `error` outcome does not count as a pass. Investigate it.

## Decision records and human checkpoints

- Non-obvious design trade-offs go in `docs/decisions/NNN-short-title.md`.
- Milestone 3 starts with decision record `docs/decisions/001-monitoring.md`.
  Do not implement Milestone 3 before the human approves that record.
- One milestone at a time: implement, run the verification gate, report, then
  STOP and wait for approval. Do not work ahead.

## Verification gate

Before every milestone report:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --nocapture
```

`--nocapture` keeps `SKIPPED` lines visible instead of hiding them in a
successful test's captured output.

Plus any targeted commands (for example escape tests, overhead measurements).
Quote the real result. A red gate is reported as red.

## Report format

Use exactly this format after every milestone:

```
### Milestone X — <title> (target tag: vX.Y.Z)
**Status:** Done / In Progress / Blocked

**What changed:**
- ...

**Decisions made:**
- ... (or link to docs/decisions/NNN-*.md)

**Tests added/updated:**
- ...

**Verification gate:**
- cargo fmt --all --check: ...
- cargo clippy --workspace --all-targets -- -D warnings: ...
- cargo test --workspace -- --nocapture: ...
- (other commands run): ...

**Measured results (if applicable):**
- ...

**Uncertain / could not verify:**
- ...

**Next:** STOP — awaiting approval before Milestone X+1
**Proposed commit:** <conventional commit message>
**Proposed tag:** vX.Y.Z
```
