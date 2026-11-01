# Security policy

## Project status

sbx is experimental and has not been independently audited. It is a rootless
Linux sandbox, not a virtual machine. Do not use it to contain real malware.
See the warning and limitations in [`README.md`](README.md) and the adversary
model in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Supported versions

sbx is pre-1.0. There are no published releases and no long-term support
branches. Security fixes are made on the current `main` branch on a best-effort
basis. No response-time or fix-time guarantee is offered.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.**

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/me9981163/SandboxOS/security/advisories/new>

You can also open the repository's **Security** tab and choose **Report a
vulnerability**. GitHub keeps the report private until a disclosure is agreed.
No security email address is published for this project; the GitHub advisory is
the private reporting channel.

Please include, where possible:

- the `sbx` version or commit;
- the host kernel release and architecture;
- the command line, target, and grants used;
- a minimal reproduction, including whether the same action succeeds outside
  the sandbox as a positive control;
- the expected and observed behaviour;
- whether the issue affects enforcement, observation, or only documentation;
- relevant logs with secrets and personal data removed.

## In scope

Examples of issues that are in scope:

- sandbox escape or bypass of namespaces, mounts, Landlock, seccomp, capability
  removal, or `no_new_privs`;
- failure to fail closed when a required protection is unavailable;
- memory-safety or soundness bugs at the `sbx-sys` boundary;
- path-policy mistakes that expose data outside an explicit grant;
- a protection summary that claims a layer is active when it is not;
- target-controlled input that crashes the supervisor or changes enforcement;
- documentation that materially overstates a protection.

The limitations listed in the README are known and are not vulnerabilities by
themselves. A new way to turn a documented limitation into an escape, data
disclosure, or false protection claim is in scope.

## Disclosure

Please allow time to investigate and prepare a fix before public disclosure.
Credit can be included in the advisory if you want it. If a report is not
accepted as a vulnerability, the reasons will be explained rather than ignored.
