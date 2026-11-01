# Exit codes

`sbx run` exits with the target's status whenever the target actually ran.

| Code | Meaning |
|---|---|
| `0`–`255` | The target's own exit status. |
| `124` | Refusal: a protection `sbx` requires is unavailable on this host, or a required enforcement layer (namespace, mount, Landlock, seccomp) could not be installed. Run `sbx doctor` for the exact feature. |
| `125` | Internal `sbx` error: invalid arguments or paths, an unknown `--allow-degraded` value, a refused dangerous path, an unavailable `--cwd`, or sandbox setup failure before the target could run. |
| `126` | The target was found but is not executable, is not a regular file, or resolves to a path that is not mounted inside the sandbox. |
| `127` | The target command was not found on the sandbox `PATH` and is not an existing absolute path. |
| `128+N` | The target was terminated by signal `N` (`128+9` = `137` for `SIGKILL`, `128+15` = `143` for `SIGTERM`). |
| `2` | Usage error from the argument parser (for example a missing `--` before the command). |

## Command not found

Before forking, `sbx` resolves the command against the **sandbox** `PATH`
(`/usr/local/bin:/usr/bin:/bin` by default) and against the mounts the sandbox
will actually have. This means:

- `sbx run -- nosuchcommand` exits `127` with
  `sbx: command not found: nosuchcommand`;
- `sbx run -- /opt/tool` exits `127` if the path does not exist, and `126` if it
  exists on the host but is not covered by `--ro`/`--rw` or an always-available
  system mount;
- an existing file without any execute bit exits `126`.

Resolution is not delegated to the target, so a command that would only be
findable through the target's own `PATH` manipulations cannot be launched by
surprise.

## Signals inside the sandbox

The target is PID 1 in its own PID namespace. The kernel ignores unhandled
signals sent to PID 1 by processes **inside** that namespace; a target doing
`kill -9 $$` may therefore survive. A signal delivered from the host (for
example the user pressing Ctrl-C, or the host killing the `sbx` process) still
terminates it and is reported as `128+N`. When `sbx` itself dies, the parent
death signal and PID-namespace init rules remove the whole target tree.

## Protection refusal

`sbx` fails closed. A missing required namespace, an unmappable uid/gid, a
failed mount/`pivot_root`, an unavailable Landlock ABI, a failed Landlock
ruleset, or a rejected seccomp filter is an error, never a silent downgrade.
Exit `124` is reserved for "the host cannot provide a protection that `sbx`
requires"; exit `125` is used for a failure while building the sandbox after
the argument and path checks have passed. The protection summary printed
before the target starts lists any protection that is not active.

### `--allow-degraded=landlock`

This is the only supported degradation opt-in. It permits `sbx` to run when
Landlock cannot be negotiated or applied. It never disables an available
Landlock layer: if the kernel provides it, the layer is on and the summary
says so. When the layer is off, the summary prints
`[off] Landlock filesystem rules` with the reason. Any other value for
`--allow-degraded` is rejected with exit `125`, so a typo cannot look like a
successful opt-in. There is no degraded mode for seccomp; failure to install
the filter is always fatal.
