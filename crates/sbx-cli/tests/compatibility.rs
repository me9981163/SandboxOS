#![forbid(unsafe_code)]
//! Compatibility matrix for common programs.
//!
//! Every case runs inside the real sandbox. A missing host program is printed
//! as `SKIPPED` and never counted as a pass. When a case fails, the test tries
//! to name the blocked syscall with `strace` and tells the human not to relax
//! the filter without a decision; it never relaxes anything itself.

mod support;

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use support::{sbx, skip_without_sandbox, TempDir};

struct Case {
    name: &'static str,
    program: &'static str,
    args: &'static [&'static str],
    expected_code: i32,
    stdout_contains: Option<&'static str>,
    stderr_contains: Option<&'static str>,
}

const CASES: &[Case] = &[
    Case {
        name: "sh-builtin",
        program: "/bin/sh",
        args: &["-c", "echo compatibility-ok"],
        expected_code: 0,
        stdout_contains: Some("compatibility-ok"),
        stderr_contains: None,
    },
    Case {
        name: "true",
        program: "/bin/true",
        args: &[],
        expected_code: 0,
        stdout_contains: None,
        stderr_contains: None,
    },
    Case {
        name: "false",
        program: "/bin/false",
        args: &[],
        expected_code: 1,
        stdout_contains: None,
        stderr_contains: None,
    },
    Case {
        name: "echo",
        program: "/bin/echo",
        args: &["compatibility", "ok"],
        expected_code: 0,
        stdout_contains: Some("compatibility ok"),
        stderr_contains: None,
    },
    Case {
        name: "cat-passwd",
        program: "/bin/cat",
        args: &["/etc/passwd"],
        expected_code: 0,
        stdout_contains: Some("sbx sandbox"),
        stderr_contains: None,
    },
    Case {
        name: "ls-root",
        program: "/bin/ls",
        args: &["/"],
        expected_code: 0,
        stdout_contains: Some("usr"),
        stderr_contains: None,
    },
    Case {
        name: "id",
        program: "/usr/bin/id",
        args: &[],
        expected_code: 0,
        stdout_contains: Some("uid=1000"),
        stderr_contains: None,
    },
    Case {
        name: "env",
        program: "/usr/bin/env",
        args: &[],
        expected_code: 0,
        stdout_contains: Some("HOME=/home/sbx"),
        stderr_contains: None,
    },
    Case {
        name: "find",
        program: "/usr/bin/find",
        args: &["/usr", "-maxdepth", "1", "-name", "bin"],
        expected_code: 0,
        stdout_contains: Some("/usr/bin"),
        stderr_contains: None,
    },
    Case {
        name: "grep",
        program: "/usr/bin/grep",
        args: &["root", "/etc/passwd"],
        expected_code: 0,
        stdout_contains: Some("root:x:0:0"),
        stderr_contains: None,
    },
    Case {
        name: "sed",
        program: "/usr/bin/sed",
        args: &["-n", "1p", "/etc/passwd"],
        expected_code: 0,
        stdout_contains: Some("root:x:0:0"),
        stderr_contains: None,
    },
    Case {
        name: "sort",
        program: "/usr/bin/sort",
        args: &["/etc/passwd"],
        expected_code: 0,
        stdout_contains: Some("root:x:0:0"),
        stderr_contains: None,
    },
    Case {
        name: "wc",
        program: "/usr/bin/wc",
        args: &["-l", "/etc/passwd"],
        expected_code: 0,
        stdout_contains: Some("/etc/passwd"),
        stderr_contains: None,
    },
    Case {
        name: "tar",
        program: "/usr/bin/tar",
        args: &["--version"],
        expected_code: 0,
        stdout_contains: Some("tar"),
        stderr_contains: None,
    },
    Case {
        name: "gzip",
        program: "/usr/bin/gzip",
        args: &["--version"],
        expected_code: 0,
        stdout_contains: Some("gzip"),
        stderr_contains: None,
    },
    Case {
        name: "python3",
        program: "/usr/bin/python3",
        args: &["-c", "print(6 * 7)"],
        expected_code: 0,
        stdout_contains: Some("42"),
        stderr_contains: None,
    },
    Case {
        name: "git",
        program: "/usr/bin/git",
        args: &["--version"],
        expected_code: 0,
        stdout_contains: Some("git version"),
        stderr_contains: None,
    },
    Case {
        name: "curl",
        program: "/usr/bin/curl",
        args: &["--version"],
        expected_code: 0,
        stdout_contains: Some("curl"),
        stderr_contains: None,
    },
    Case {
        name: "ssh",
        program: "/usr/bin/ssh",
        args: &["-V"],
        expected_code: 0,
        stdout_contains: None,
        stderr_contains: Some("OpenSSH"),
    },
    Case {
        name: "make",
        program: "/usr/bin/make",
        args: &["--version"],
        expected_code: 0,
        stdout_contains: Some("GNU Make"),
        stderr_contains: None,
    },
    Case {
        name: "awk",
        program: "/usr/bin/awk",
        args: &["BEGIN { print 6 * 7 }"],
        expected_code: 0,
        stdout_contains: Some("42"),
        stderr_contains: None,
    },
    Case {
        name: "base64",
        program: "/usr/bin/base64",
        args: &["/etc/hostname"],
        expected_code: 0,
        stdout_contains: Some("c2J4"),
        stderr_contains: None,
    },
    Case {
        name: "write-tmp",
        program: "/bin/sh",
        args: &["-c", "cd /tmp && echo tmp-ok > probe && cat probe"],
        expected_code: 0,
        stdout_contains: Some("tmp-ok"),
        stderr_contains: None,
    },
    Case {
        name: "write-home",
        program: "/bin/sh",
        args: &["-c", "cd /home/sbx && echo home-ok > probe && cat probe"],
        expected_code: 0,
        stdout_contains: Some("home-ok"),
        stderr_contains: None,
    },
];

#[test]
fn common_programs_run_inside_the_sandbox() {
    if skip_without_sandbox() {
        return;
    }

    let mut ran = 0usize;
    let mut skipped = 0usize;
    for case in CASES {
        if !Path::new(case.program).is_file() {
            eprintln!(
                "SKIPPED: compatibility {}: {} is not installed",
                case.name, case.program
            );
            skipped += 1;
            continue;
        }

        let output = run_inside(case);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut problems = Vec::new();
        if output.status.code() != Some(case.expected_code) {
            problems.push(format!(
                "exit {:?}, expected {}",
                output.status.code(),
                case.expected_code
            ));
        }
        if let Some(needle) = case.stdout_contains {
            if !stdout.contains(needle) {
                problems.push(format!("stdout does not contain `{needle}`"));
            }
        }
        if let Some(needle) = case.stderr_contains {
            if !stderr.contains(needle) {
                problems.push(format!("stderr does not contain `{needle}`"));
            }
        }

        if problems.is_empty() {
            eprintln!("compatibility: {} ok", case.name);
            ran += 1;
            continue;
        }

        let diagnosis = trace_blocked_syscalls(case);
        panic!(
            "compatibility case `{}` failed: {}\ncommand: {} {}\nexit: {:?}\nstdout:\n{}\nstderr:\n{}\nblocked-syscall diagnosis:\n{}",
            case.name,
            problems.join("; "),
            case.program,
            case.args.join(" "),
            output.status.code(),
            stdout,
            stderr,
            diagnosis
        );
    }

    assert!(ran > 0, "no compatibility case ran; skipped {skipped}");
    eprintln!("compatibility: {ran} case(s) passed, {skipped} skipped");
}

fn run_inside(case: &Case) -> Output {
    let mut command = Command::new(sbx());
    command.args(["run", "--quiet", "--", case.program]);
    command.args(case.args);
    command.output().expect("run sbx")
}

/// Name the syscalls that returned EPERM under `strace`, if it is installed.
/// Strace is a diagnostic only: the test never uses its output to change the
/// filter. If it is missing, the message says so and asks for a human decision.
fn trace_blocked_syscalls(case: &Case) -> String {
    let Some(strace) = ["/usr/bin/strace", "/bin/strace"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
    else {
        return "strace is not installed, so the blocked syscall could not be identified; \
                do not relax any filter rule without a human decision"
            .to_string();
    };

    let temp = TempDir::new("compatibility-trace");
    let log = temp.join("trace.log");
    let mut command = Command::new(strace);
    command.args(["-f", "-qq", "-e", "trace=all", "-o"]);
    command.arg(&log);
    command.arg(sbx());
    command.args(["run", "--quiet", "--", case.program]);
    command.args(case.args);
    let output = match command.output().map_err(|error| {
        format!(
            "strace could not run ({error}); do not relax any filter rule without a human decision"
        )
    }) {
        Ok(output) => output,
        Err(message) => return message,
    };
    let text = fs::read_to_string(&log).unwrap_or_default();
    let denied: Vec<&str> = text.lines().filter(|line| line.contains("EPERM")).collect();
    if denied.is_empty() {
        format!(
            "strace recorded no EPERM (exit {:?}); this looks like an ordinary program error, \
             not a seccomp denial. Do not relax the filter without a human decision.\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    } else {
        format!(
            "syscalls returning EPERM (last {} shown):\n{}\nDo not relax the filter without a human decision.",
            denied.len().min(10),
            denied[denied.len().saturating_sub(10)..].join("\n")
        )
    }
}
