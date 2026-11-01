# 003 — Landlock and seccomp defence in depth (Milestone 2)

Status: accepted for Milestone 2.

## Context

Milestone 1 built the sandbox from namespaces, a `pivot_root` new root,
capability dropping and `no_new_privs`. That is one enforcement stack with one
failure mode: a mount mistake, an unexpected bind mount or a leaked descriptor
could expose a host path. Milestone 2 adds two independent kernel layers and a
syscall filter, and must never claim a layer that is not actually active.

The filters run in the target after `PR_SET_NO_NEW_PRIVS`; installation failure
is fatal. Nothing is decided by observing the target.

## Decision: Landlock mirrors the mount layout

The Landlock ruleset is built from the same `Grant` list as the mount table, so
`--ro` and `--rw` mean the same thing to both layers. The rule set is:

| Path | Rights |
|---|---|
| `/` | `READ_DIR` only |
| `/usr` | `EXECUTE`, `READ_FILE`, `READ_DIR` |
| `/etc`, `/run`, `/var`, `/home`, `/proc` | `READ_FILE`, `READ_DIR` |
| `/dev` | `READ_FILE`, `WRITE_FILE`, `READ_DIR` |
| `/tmp`, `/var/tmp`, `/home/sbx` | every handled right |
| each `--ro` directory grant | `EXECUTE`, `READ_FILE`, `READ_DIR` |
| each `--ro` file grant | `EXECUTE`, `READ_FILE` |
| each `--rw` directory grant | every handled right |
| each `--rw` file grant | `EXECUTE`, `WRITE_FILE`, `READ_FILE`, `TRUNCATE` |

File rules never carry directory-only rights (`READ_DIR`, `MAKE_*`,
`REMOVE_*`), because `landlock_add_rule` rejects them with `EINVAL`.

Only rights advertised by the running ABI are handled. ABI 1 contributes the
base 13 filesystem rights; ABI 2 adds `REFER`; ABI 3 adds `TRUNCATE`. Newer
ABIs add rights that are intentionally not handled yet. Passing an unknown bit
to `landlock_create_ruleset` fails, so the mask is derived from the negotiated
ABI rather than hard-coded to the newest kernel.

### Why `IOCTL_DEV` is not handled

Landlock ABI 5 added `IOCTL_DEV`, but handling it would deny ioctls on the
inherited stdin/stdout/stderr descriptors, which point at the host terminal
outside the sandbox hierarchy. That would break ordinary interactive programs
for no gain: `TIOCSTI` is the dangerous terminal ioctl, and seccomp denies it
explicitly. Other device ioctls are already limited by the minimal `/dev` and
by the absence of host device nodes.

## Decision: seccomp is a denylist returning `EPERM`

A kill-on-deny profile would make ordinary programs die with no diagnostics.
`EPERM` lets a program report the failure or fall back, and matches what the
kernel returns when a rootless process attempts a privileged operation. The
full syscall-by-syscall justification is in `docs/SECCOMP.md`.

The profile also handles the syscall ABI explicitly:

- A non-`AUDIT_ARCH_X86_64` call returns `EPERM`. sbx does not maintain a
  second table for 32-bit compat and will not guess at one.
- x32 numbers (bit 30 set) return `EPERM`.
- `clone3` returns `ENOSYS`, so glibc falls back to `clone`, whose
  `CLONE_NEW*` flags are then filtered. Returning `EPERM` here would break
  process creation instead of producing a safe fallback.
- `ioctl` is allowed except `TIOCSTI`.
- `clone` is allowed unless a namespace flag is present.

The denylist is reviewed against the running kernel's syscall table and the
result is recorded in `docs/SECCOMP.md`. It remains a denylist; mount
namespaces and Landlock, not the list, are the primary boundaries.

## Decision: fail closed, with one explicit opt-in

If Landlock cannot be negotiated or its ruleset cannot be installed, `sbx`
exits `124` unless the user passed `--allow-degraded=landlock`. That flag only
*permits* running without the layer; it never disables an available layer, and
the protection summary prints `[off] Landlock filesystem rules` with the
reason. No other protection has a degradation flag. Seccomp installation
failure is always fatal.

`--allow-degraded` accepts only the value `landlock`; anything else exits `125`.
This keeps typos from looking like a successful opt-in.

## Decision: a test-only loosened-mount build proves Landlock

`--features landlock-proof` makes the runner bind `SBX_PROOF_HOST` at `/host`
without adding a Landlock rule. The test then runs the same binary twice:

1. with Landlock enabled, reading `/host/canary` must fail;
2. with `--allow-degraded=landlock` (which in this test build forces Landlock
   off), the same read must succeed.

The second run is the positive control: it proves the mount layer really was
loosened, so the first failure is attributable to Landlock rather than to the
mount namespace. In a normal build the flag never forces an available layer
off. The test suite's summary assertions also require the deliberately exposed
mount to be disclosed in the protection summary.

## Consequences

- Two independent filesystem layers now agree on the allowlist. A future
  change to `--ro`/`--rw` handling must update both, and the unit tests check
  that they mirror each other.
- Landlock ABI differences are visible in the summary and in the unit tests.
  An older kernel may handle fewer rights; it never receives an unsupported
  bit.
- Programs using 32-bit or x32 syscall ABIs do not run. That is a deliberate
  fail-closed limitation, documented rather than emulated.
- `io_uring`, `bpf`, `perf_event_open`, `userfaultfd` and the keyring are
  unavailable to the target. The compatibility matrix records this so a new
  program failure can be triaged instead of silently excused.
