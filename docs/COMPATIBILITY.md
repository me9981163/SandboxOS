# Compatibility matrix

Status: **Milestone 2**. `crates/sbx-cli/tests/compatibility.rs` runs each case
inside the real sandbox and asserts its exit status and expected output. A
program that is not installed on the host prints a visible
`SKIPPED: compatibility <name>: <path> is not installed` line and is not
counted as a pass. The test fails if no case ran.

Cases (24):

| Name | Program | Check |
|---|---|---|
| `sh-builtin` | `/bin/sh -c 'echo compatibility-ok'` | shell and builtins |
| `true` | `/bin/true` | exit 0 |
| `false` | `/bin/false` | exit 1 |
| `echo` | `/bin/echo compatibility ok` | stdout |
| `cat-passwd` | `/bin/cat /etc/passwd` | synthesized `/etc`, not host |
| `ls-root` | `/bin/ls /` | directory listing |
| `id` | `/usr/bin/id` | uid/gid mapping |
| `env` | `/usr/bin/env` | environment allowlist |
| `find` | `/usr/bin/find /usr -maxdepth 1 -name bin` | read-only `/usr` traversal |
| `grep` | `/usr/bin/grep root /etc/passwd` | file read |
| `sed` | `/usr/bin/sed -n 1p /etc/passwd` | file read |
| `sort` | `/usr/bin/sort /etc/passwd` | file read |
| `wc` | `/usr/bin/wc -l /etc/passwd` | file read |
| `tar` | `/usr/bin/tar --version` | archive tool startup |
| `gzip` | `/usr/bin/gzip --version` | compression tool startup |
| `python3` | `/usr/bin/python3 -c 'print(6 * 7)'` | interpreter startup |
| `git` | `/usr/bin/git --version` | VCS startup |
| `curl` | `/usr/bin/curl --version` | network tool startup (network not used) |
| `ssh` | `/usr/bin/ssh -V` | client startup (connection not attempted) |
| `make` | `/usr/bin/make --version` | build tool startup |
| `awk` | `/usr/bin/awk 'BEGIN { print 6 * 7 }'` | text processing |
| `base64` | `/usr/bin/base64 /etc/hostname` | file read and encoding |
| `write-tmp` | write and read in `/tmp` | private tmpfs |
| `write-home` | write and read in `/home/sbx` | sandbox home |

Milestone 2 result on the development host: 24/24 passed, 0 skipped.

## When a case fails

The test prints the command, exit status, stdout, stderr and a diagnosis. If
`strace` is installed it re-runs the case under `strace -f -e trace=all` and
lists the syscalls that returned `EPERM`. If `strace` is absent, the message
says the blocked syscall could not be identified.

The test never relaxes a filter rule. A failure is a request for a human
decision: either the program needs a capability the sandbox deliberately
removes, or a filter rule is too broad. The decision and its justification
belong in `docs/SECCOMP.md` and the milestone report before any change is
made.
