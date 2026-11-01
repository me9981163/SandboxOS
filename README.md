# sbx

> **Experimental, not audited. Do not rely on sbx to contain real malware.**
>
> sbx is a rootless Linux sandbox, not a virtual machine. It shares the host
> kernel. A kernel vulnerability, a configuration mistake, or a path you grant
> can let a target escape or damage data. Use a disposable virtual machine for
> real malware and for any target you would not run directly on the host.

sbx runs untrusted programs with a restrictive set of Linux namespaces, mounts,
filesystem rules, and syscalls. The public repository is named **SandboxOS**,
but the tool and crates are named **sbx**. This is not an operating system; the
final public project name is still undecided.

- Repository: <https://github.com/me9981163/SandboxOS>
- Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Exit codes: [`docs/EXIT_CODES.md`](docs/EXIT_CODES.md)

## Status

**Milestone 2 is implemented.** The current tool provides namespaces, a new
root, host-path grants, environment filtering, capability removal, Landlock and
a seccomp denylist.

**Milestone 3 is not implemented.** There is no `--events` option, no JSON Lines
event stream, and no `sbx report` command yet. The design is recorded in
[`docs/decisions/001-monitoring.md`](docs/decisions/001-monitoring.md) and is
awaiting approval. The protection summary therefore ends with:

```text
[off] seccomp user-notify monitoring: not enabled in Milestone 2 (planned for Milestone 3)
```

That line is accurate: observation is not active.

## Requirements

- Linux with unprivileged user namespaces enabled.
- A Rust toolchain (stable) for building from source.
- x86-64 is the tested architecture. Other architectures and 32-bit compatibility
  mode have not been verified.
- No root, setuid helper, or daemon is used.

## Build

```sh
cargo build --release
```

The binary is `target/release/sbx`.

## Quick start

Probe the host first. This does not change any settings:

```sh
./target/release/sbx doctor
```

Run a harmless command:

```sh
./target/release/sbx run -- /bin/echo hello
```

The protection summary is printed to stderr before the target starts. `--quiet`
suppresses the summary but does not disable any protection.

## Usage

```text
sbx doctor [--json]
sbx run [OPTIONS] -- CMD...
```

Useful `run` options:

- `--ro PATH`: expose a host path read-only at the same absolute path.
- `--rw PATH`: expose a host path read-write at the same absolute path.
- `--env KEY`: copy one host environment variable into the sandbox.
- `--cwd PATH`: set the working directory inside the sandbox.
- `--hostname NAME`: set the UTS-namespace hostname.
- `--quiet`: suppress the protection summary.
- `--allow-degraded=landlock`: explicitly permit running without Landlock.
- `--i-know-this-is-dangerous`: allow a grant that the default path policy
  would refuse.

Examples:

```sh
./target/release/sbx run --ro /data -- /bin/ls /data
./target/release/sbx run --rw /tmp/work --cwd /tmp/work -- /bin/sh
```

Exit status is the target's status. `124` means a required protection was
unavailable; `125` means an internal `sbx` error. See
[`docs/EXIT_CODES.md`](docs/EXIT_CODES.md) for the full table.

## Protections

The layers are independent where the kernel allows it:

- User, mount, PID, network, IPC and UTS namespaces.
- A tmpfs root with `pivot_root`, a read-only `/usr`, a synthesized `/etc`, a
  private `/tmp`, a minimal `/dev`, and only the requested host grants.
- An empty environment plus an allowlist (`PATH`, `HOME=/home/sbx`, `TERM`,
  `LANG`, and explicitly requested variables).
- Dropped capabilities, `PR_SET_NO_NEW_PRIVS`, Landlock filesystem rules and a
  seccomp denylist.
- Network namespaces with loopback only; no host interfaces or routes.
- Cleanup of inherited descriptors above stderr, a new session, and a target
  tree reaped by the supervisor.

`sbx doctor` reports what the host actually supports. `sbx run` refuses to start
when a required layer cannot be installed, unless `--allow-degraded=landlock`
is explicitly used. The summary always reports a degraded layer as off.

## Limitations

These are deliberate, current limitations, not a complete security proof:

- **Not a VM.** The host kernel is shared. A kernel bug can be a full escape.
  This project is not audited and must not be used to contain real malware.
- **Rootless user namespaces are required.** Hosts that disable them cannot run
  the sandbox.
- **Landlock depends on the kernel ABI.** Older kernels provide fewer rights.
  The summary reports the negotiated ABI and handled rights.
- **The seccomp profile is a denylist, not a complete syscall policy.** A denied
  call returns `EPERM`, but denied calls are not recorded in Milestone 2.
- **Observation is absent.** There is no event stream and no report yet, so
  there is no audit trail of attempted paths, connections, or executions.
- **Terminal injection coverage is partial.** `TIOCSTI` is denied, but the
  escape test cannot exercise it without a pty; that attempt is visibly skipped.
- **32-bit compatibility is not verified.** The seccomp filter rejects foreign
  and x32 ABIs, and the test suite does not include a 32-bit target.
- **Grants expose real data.** A `--ro` or `--rw` path is the real host path.
  Do not grant secrets or directories you do not intend the target to read.
  Dangerous paths require an explicit override.
- **Output is not sanitised.** The target's stdout and stderr are forwarded;
  terminal escape sequences are not filtered.
- **There are no disk or CPU quotas beyond the tmpfs sizes and the host's normal
  scheduling.** A target can fill its private `/tmp` or produce large output.
- **No event rotation, persistence, or long-term audit log exists.**
- **The project is pre-1.0, not fuzzed, and not independently audited.**

## Security

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting for this repository; details are in
[`SECURITY.md`](SECURITY.md).

For the adversary model, protected goals, and known gaps, read
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Documentation

- [`docs/ROADMAP.md`](docs/ROADMAP.md)
- [`docs/SECCOMP.md`](docs/SECCOMP.md)
- [`docs/PATH_POLICY.md`](docs/PATH_POLICY.md)
- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md)
- [`docs/decisions/`](docs/decisions/)

## License

Licensed under either of

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
