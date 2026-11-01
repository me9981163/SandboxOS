#![forbid(unsafe_code)]
//! Behavioural tests for `sbx run`: passthrough, filesystem grants, argument
//! and path validation, environment, exit codes, protection-summary display,
//! and whole-tree cleanup when `sbx` is killed.

mod support;

use sbx_sys as sys;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use support::{
    escape, random_token, require_sandbox_from, sandbox_skip_reason, sbx, skip_without_sandbox,
    TempDir,
};

fn run_sbx(args: &[&str]) -> std::process::Output {
    Command::new(sbx()).args(args).output().expect("run sbx")
}

#[test]
fn require_sandbox_environment_is_strict() {
    assert!(!require_sandbox_from(None).expect("unset is optional"));
    assert!(!require_sandbox_from(Some("0")).expect("zero disables the requirement"));
    assert!(require_sandbox_from(Some("1")).expect("one requires the sandbox"));
    assert!(require_sandbox_from(Some("")).is_err());
    assert!(require_sandbox_from(Some("true")).is_err());
    assert!(require_sandbox_from(Some(" 1")).is_err());
}

#[test]
fn optional_skip_returns_a_reason_without_panicking() {
    assert_eq!(
        sandbox_skip_reason(Err("no userns".to_string()), false).as_deref(),
        Some("no userns")
    );
    assert_eq!(sandbox_skip_reason(Ok(()), false), None);
    assert_eq!(sandbox_skip_reason(Ok(()), true), None);
}

#[test]
#[should_panic(expected = "SBX_REQUIRE_SANDBOX=1 but the sandbox is unavailable")]
fn required_sandbox_turns_a_skip_into_a_failure() {
    sandbox_skip_reason(Err("no userns".to_string()), true);
}

#[test]
fn stdio_and_exit_code_pass_through() {
    if skip_without_sandbox() {
        return;
    }
    let mut child = Command::new(sbx())
        .args([
            "run",
            "--quiet",
            "--",
            "/bin/sh",
            "-c",
            "read line; echo \"out:$line\"; echo err >&2; exit 42",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sbx");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(b"hello-stdin\n")
        .expect("write stdin");
    let output = child.wait_with_output().expect("wait for sbx");
    assert_eq!(output.status.code(), Some(42));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "out:hello-stdin"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("err"),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn arguments_are_passed_verbatim() {
    if skip_without_sandbox() {
        return;
    }
    let arguments = ["a b", "--not-an-sbx-flag", "'quoted'", "unicode-ü"];
    let mut args = vec!["run", "--quiet", "--", "/bin/echo"];
    args.extend(arguments.iter().copied());
    let output = run_sbx(&args);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), arguments.join(" "));
}

#[test]
fn cwd_is_honoured_and_validated() {
    if skip_without_sandbox() {
        return;
    }
    let temp = TempDir::new("cwd");
    let dir = temp.join("dir");
    fs::create_dir_all(&dir).unwrap();
    let dir = dir.to_string_lossy().into_owned();

    let output = run_sbx(&[
        "run", "--quiet", "--rw", &dir, "--cwd", &dir, "--", "/bin/pwd",
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), dir);

    let output = run_sbx(&["run", "--quiet", "--cwd", &dir, "--", "/bin/pwd"]);
    assert_eq!(output.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not available inside the sandbox"),
        "stderr was: {stderr}"
    );
}

#[test]
fn command_not_found_exits_127() {
    if skip_without_sandbox() {
        return;
    }
    for command in ["definitely-not-a-command", "/no/such/binary"] {
        let output = run_sbx(&["run", "--quiet", "--", command]);
        assert_eq!(
            output.status.code(),
            Some(127),
            "command {command} returned {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("command not found"));
    }
}

#[test]
fn existing_but_unavailable_or_non_executable_exits_126() {
    if skip_without_sandbox() {
        return;
    }
    let temp = TempDir::new("not-executable");

    // Existing executable on the host but not covered by any grant: the
    // target could not reach it inside the sandbox, so sbx must refuse.
    let outside = temp.join("unreachable");
    fs::write(&outside, b"#!/bin/sh\n").unwrap();
    let mut mode = fs::metadata(&outside).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(&outside, mode).unwrap();
    let output = run_sbx(&["run", "--quiet", "--", outside.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(126));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not mounted"),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // A file inside a grant that has no execute bit is still not executable.
    let inside = temp.join("no-exec");
    fs::write(&inside, b"#!/bin/sh\n").unwrap();
    let directory = temp.path().to_string_lossy().into_owned();
    let output = run_sbx(&[
        "run",
        "--quiet",
        "--ro",
        &directory,
        "--",
        inside.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(126));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not executable"),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn missing_and_dangerous_paths_are_refused() {
    if skip_without_sandbox() {
        return;
    }
    let missing = format!("/tmp/sbx-missing-{}", random_token());
    let output = run_sbx(&["run", "--quiet", "--ro", &missing, "--", "/bin/true"]);
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("No such file or directory"));

    let output = run_sbx(&["run", "--quiet", "--ro", "/etc", "--", "/bin/true"]);
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to expose /etc"));

    let output = run_sbx(&["run", "--quiet", "--rw", "/usr", "--", "/bin/true"]);
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("system software"));
}

#[test]
fn read_only_grant_really_is_read_only() {
    if skip_without_sandbox() {
        return;
    }
    let temp = TempDir::new("ro");
    let file = temp.join("keep.txt");
    fs::write(&file, b"original\n").unwrap();
    let dir = temp.path().to_string_lossy().into_owned();
    let script = format!("echo changed > {dir}/keep.txt; echo new > {dir}/new.txt");

    let output = run_sbx(&[
        "run", "--quiet", "--ro", &dir, "--", "/bin/sh", "-c", &script,
    ]);
    assert_ne!(output.status.code(), Some(0));
    assert_eq!(fs::read(&file).unwrap(), b"original\n");
    assert!(!temp.join("new.txt").exists());

    let output = run_sbx(&[
        "run",
        "--quiet",
        "--rw",
        &dir,
        "--",
        "/bin/sh",
        "-c",
        &format!("echo changed > {dir}/keep.txt"),
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(fs::read(&file).unwrap(), b"changed\n");
}

#[test]
fn environment_is_an_allowlist() {
    if skip_without_sandbox() {
        return;
    }
    let token = random_token();
    let output = Command::new(sbx())
        .args([
            "run",
            "--quiet",
            "--env",
            "SBX_TEST_SECRET",
            "--",
            "/usr/bin/env",
        ])
        .env("SBX_TEST_SECRET", &token)
        .output()
        .expect("run sbx");
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains(&format!("SBX_TEST_SECRET={token}")));

    let output = Command::new(sbx())
        .args(["run", "--quiet", "--", "/usr/bin/env"])
        .env("SBX_TEST_SECRET", &token)
        .output()
        .expect("run sbx");
    assert_eq!(output.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&token));

    let output = run_sbx(&["run", "--quiet", "--env", "HOME", "--", "/bin/true"]);
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("reserved"));
}

#[test]
fn protection_summary_is_shown_and_quiet_suppresses_only_display() {
    if skip_without_sandbox() {
        return;
    }
    let output = run_sbx(&["run", "--", "/bin/true"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("sbx: protection summary\n"));
    assert!(stderr.contains("[on ] user namespace"));
    assert!(stderr.contains("[on ] Landlock filesystem rules"));
    assert!(stderr.contains("[on ] seccomp syscall filter"));

    let output = run_sbx(&["run", "--quiet", "--", "/bin/true"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
}

#[test]
fn allow_degraded_accepts_only_known_features_and_never_hides_an_active_layer() {
    if skip_without_sandbox() {
        return;
    }
    let output = run_sbx(&[
        "run",
        "--quiet",
        "--allow-degraded=landlock",
        "--",
        "/bin/true",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // On this host Landlock is available, so the opt-in must not turn it off.
    let output = run_sbx(&["run", "--allow-degraded=landlock", "--", "/bin/true"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[on ] Landlock filesystem rules"),
        "an available Landlock layer was silently disabled: {stderr}"
    );

    let output = run_sbx(&["run", "--allow-degraded=selinux", "--", "/bin/true"]);
    assert_eq!(output.status.code(), Some(125));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown --allow-degraded feature"),
        "stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn hostname_is_isolated_and_configurable() {
    if skip_without_sandbox() {
        return;
    }
    let output = run_sbx(&["run", "--quiet", "--", "/bin/cat", "/etc/hostname"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "sbx");

    let output = run_sbx(&[
        "run",
        "--quiet",
        "--hostname",
        "sbx-test-host",
        "--",
        "/bin/cat",
        "/etc/hostname",
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "sbx-test-host"
    );
}

#[test]
fn killing_sbx_removes_the_whole_target_tree() {
    if skip_without_sandbox() {
        return;
    }
    let marker = format!(
        "{}.{}",
        3_000_000 + (std::process::id() as u64 % 1_000_000),
        random_token().len() as u64
    );
    let mut child = Command::new(sbx())
        .args(["run", "--quiet", "--", "/bin/sleep", &marker])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sbx");

    let deadline = Instant::now() + Duration::from_secs(5);
    while pids_with_argument(&marker).is_empty() {
        assert!(Instant::now() < deadline, "target process never appeared");
        thread::sleep(Duration::from_millis(20));
    }

    sys::kill(child.id() as i32, sys::SIGKILL).expect("kill sbx");
    let _ = child.wait();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !pids_with_argument(&marker).is_empty() {
        assert!(
            Instant::now() < deadline,
            "target process survived sbx: {:?}",
            pids_with_argument(&marker)
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn pids_with_argument(argument: &str) -> Vec<i32> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        if cmdline
            .split(|byte| *byte == 0)
            .any(|value| value == argument.as_bytes())
        {
            found.push(pid);
        }
    }
    found
}

/// Build the helper used by the escape battery and prove it is executable.
/// `escape()` builds it if the test runner did not.
#[test]
fn escape_helper_is_built_next_to_sbx() {
    let path = escape();
    assert!(
        path.is_file(),
        "{} is missing after building sbx-escape",
        path.display()
    );
    assert!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o111 != 0,
        "{} is not executable",
        path.display()
    );
}
