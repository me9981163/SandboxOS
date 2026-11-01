# Host path policy

`sbx run` exposes host paths only through `--ro PATH` and `--rw PATH`. Every
path is resolved with `fs::canonicalize` **before** the sandbox is built, so
`..` and symlinks are resolved by the host kernel and the policy sees the real
target. A path that cannot be canonicalised (missing, permission denied, a
dangling symlink) is rejected with exit `125`.

This policy is a guardrail against accidents. It is not a substitute for
reading the path you grant: once `--i-know-this-is-dangerous` is used, the
target can read or write whatever that path contains.

## Hard denials

These are refused even with `--i-know-this-is-dangerous`:

- A path that is not absolute after canonicalisation.
- `/` itself: granting the host root would expose everything.
- Any path containing a NUL byte (rejected when the `CString` is built).

## Dangerous paths

These require `--i-know-this-is-dangerous`:

| Path | Why |
|---|---|
| `/proc` and anything under it | host processes, kernel state, writable sysctls |
| `/sys` and anything under it | host devices and kernel knobs |
| `/dev` and anything under it | host device nodes and terminals |
| `/run` and anything under it | host daemons, sockets, pid files, credentials |
| `/boot` and anything under it | kernel and bootloader state |
| `/root` and anything under it | the host root account's home |
| `/etc` and anything under it | host accounts, keys, service configuration |
| `/var` and anything under it | host logs, spools, databases, lib state |
| exactly `/home` | every user's home directory |
| exactly `/tmp` | other processes' temporary files and sockets |
| any component named `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.password-store`, `.netrc`, `.git-credentials`, `.npmrc`, `.pypirc`, `.mozilla`, `.thunderbird`, `keyrings`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `authorized_keys`, `shadow`, `gshadow`, `sudoers`, `private_key` | credentials or account databases |
| a write grant (`--rw`) on `/usr` or anything under it | modifying host system software |
| a write grant on exactly `/bin`, `/sbin`, `/lib`, `/lib64` | modifying host system software |

A host path under `/tmp` is allowed (for example
`/tmp/project-1234`); only the directory `/tmp` itself is dangerous. The
sandbox still gets its own private `/tmp`; the grant appears at the host
absolute path.

## Always available

The target can always see the sandbox's own layout:

- `/usr` read-only (with `/bin`, `/sbin`, `/lib`, `/lib64` symlinked to it on
  merged-`/usr` hosts);
- the synthesized `/etc/passwd`, `/etc/group`, `/etc/hostname`, `/etc/hosts`,
  `/etc/resolv.conf`, `/etc/nsswitch.conf`;
- a fresh `/proc` for the sandbox's own PID namespace;
- the minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom`, `tty`, plus
  `fd`, `stdin`, `stdout`, `stderr` symlinks);
- a private `/tmp`;
- `/home/sbx`, the sandbox home;
- exactly the `--ro`/`--rw` paths, at their host absolute paths.

`--cwd PATH` is accepted only if the path is one of those sandbox locations or
is covered by a grant. A host path that happens to exist outside the sandbox is
not enough; `sbx` refuses with exit `125` rather than silently starting the
target elsewhere.

## Mode and mount flags

- `--ro` paths are recursive bind mounts with `MS_RDONLY | MS_NOSUID |
  MS_NODEV`.
- `--rw` paths are recursive bind mounts with `MS_NOSUID | MS_NODEV`.
- The mount namespace is private, so these mounts never appear on the host.

## Landlock mirror

The same grant list builds a Landlock ruleset, so a mount mistake is not the
only thing standing between the target and a host path. Every `--ro` path gets
read/execute rights and every `--rw` path gets the full handled set; the
sandbox's own `/usr`, synthesized `/etc`, `/proc`, `/dev`, `/tmp` and
`/home/sbx` get the same rights as their mounts. File grants receive only
file-compatible rights, because `landlock_add_rule` rejects directory-only
rights on a file.

Only rights advertised by the running Landlock ABI are handled. If Landlock
is unavailable, `sbx` exits `124` unless `--allow-degraded=landlock` was
passed; the summary then reports the layer as off. See
`docs/decisions/003-landlock-and-seccomp.md`.

## Known race

Canonicalisation and mounting happen in two steps. A process running as the
same host uid could swap a path component between them. Same-uid host processes
are explicitly outside the threat model; hardening this would require
`openat2(RESOLVE_*)` and mounting by file descriptor.
