# Contributing to sbx

Read [`AGENTS.md`](AGENTS.md) first. It is the authoritative working agreement,
including the path boundary, unsafe-code rules, and the report format.

## Requirements

- Linux with unprivileged user namespaces enabled for the full test suite.
- A stable Rust toolchain with `rustfmt` and `clippy`.
- No root, setuid helper, or daemon.

## Required local verification gate

Run these commands from the repository root on a host that can create the
sandbox:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --bins
SBX_REQUIRE_SANDBOX=1 cargo test --workspace -- --nocapture
cargo test -p sbx-cli --features landlock-proof --test landlock_only -- --nocapture
cargo build --release
```

`--nocapture` keeps every `SKIPPED` line visible. `SBX_REQUIRE_SANDBOX=1`
turns an unavailable sandbox into a test failure instead of a skip, so the gate
cannot pass without exercising the sandbox. It does not turn feature-specific
skips, such as a missing pty, into failures. Unset it (or set it to `0`) only
when you deliberately want the visible-skip behaviour. Any value other than
`0`, `1`, or unset is an error.

The `landlock-proof` test is a test-only build. It deliberately exposes a host
directory at `/host` without a matching Landlock rule, then proves that
Landlock blocks the read while the loosened mount layer alone allows it. The
feature is not enabled by default and must not be used for a release build.

## Hosted CI

GitHub-hosted runners often cannot create unprivileged user namespaces. CI
therefore does not set `SBX_REQUIRE_SANDBOX=1`; sandbox-dependent tests print a
visible `SKIPPED` line, and a follow-up step reports the number of skip lines
with an Actions `::warning::`. A green hosted run is not evidence that the
sandbox protections passed. Run the strict gate above on a suitable local host
before claiming that a change was verified against the sandbox.

## Reproducible clean copies

Use `git clone` or `git worktree` for a clean copy. Do not create one with
`cp`, `rsync`, `tar`, `find`, or shell globs.

## Commits and tags

Do not commit or tag unless a maintainer explicitly asks. Propose a
Conventional Commit message and wait for approval.
