#![cfg(feature = "landlock-proof")]
#![forbid(unsafe_code)]
//! Test-only proof that Landlock is a real second layer.
//!
//! The `landlock-proof` build binds `SBX_PROOF_HOST` at `/host` without adding
//! a Landlock rule. With Landlock enabled, reading the canary must fail. With
//! Landlock deliberately disabled by `--allow-degraded=landlock`, the same read
//! must succeed, proving that the mount layer really was loosened and that it
//! was Landlock, not the mount namespace, that blocked the first read.

mod support;

use std::fs;
use std::process::Command;
use support::{random_token, sbx, skip_without_sandbox, TempDir};

fn run(args: &[&str], proof_host: &str) -> std::process::Output {
    Command::new(sbx())
        .env("SBX_PROOF_HOST", proof_host)
        .args(args)
        .output()
        .expect("run sbx")
}

#[test]
fn landlock_alone_blocks_a_deliberately_exposed_mount() {
    if skip_without_sandbox() {
        return;
    }

    let temp = TempDir::new("landlock-proof");
    let token = random_token();
    fs::write(temp.join("canary"), format!("{token}\n")).expect("write canary");
    let proof_host = temp.path().to_string_lossy().into_owned();

    // With Landlock on, the mount is visible but its contents are not readable.
    let blocked = run(
        &["run", "--quiet", "--", "/bin/cat", "/host/canary"],
        &proof_host,
    );
    assert_ne!(
        blocked.status.code(),
        Some(0),
        "Landlock did not block the exposed mount: stdout {} stderr {}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&blocked.stdout).contains(&token),
        "the canary leaked even though Landlock was enabled"
    );
    let stderr = String::from_utf8_lossy(&blocked.stderr);
    assert!(
        stderr.contains("Permission denied") || stderr.contains("Operation not permitted"),
        "expected a Landlock denial, got: {stderr}"
    );

    let summary = run(&["run", "--", "/bin/true"], &proof_host);
    let stderr = String::from_utf8_lossy(&summary.stderr);
    assert!(
        stderr.contains("[on ] Landlock filesystem rules"),
        "summary did not report Landlock as on: {stderr}"
    );
    assert!(
        stderr.contains("test-only exposed mount"),
        "summary did not disclose the deliberately exposed mount: {stderr}"
    );

    // In this build the flag forces Landlock off. The same read must now
    // succeed, which proves the mount layer alone is deliberately loose.
    let allowed = run(
        &[
            "run",
            "--quiet",
            "--allow-degraded=landlock",
            "--",
            "/bin/cat",
            "/host/canary",
        ],
        &proof_host,
    );
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "the loosened mount layer did not expose the canary: stderr {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains(&token),
        "the positive control did not read the canary"
    );

    let summary = run(
        &["run", "--allow-degraded=landlock", "--", "/bin/true"],
        &proof_host,
    );
    let stderr = String::from_utf8_lossy(&summary.stderr);
    assert!(
        stderr.contains("[off] Landlock filesystem rules"),
        "summary did not report the forced-off Landlock layer: {stderr}"
    );
}
