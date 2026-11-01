#![forbid(unsafe_code)]
//! Runs `sbx-escape` twice: once unsandboxed as a positive control, then inside
//! `sbx run`. An attempt only counts as blocked inside when it actually escaped
//! outside; anything else is reported as inconclusive or `SKIPPED`.
//!
//! The battery is run one attempt per process. That gives every attempt the
//! same fresh process state (a namespace-changing attempt cannot affect the
//! next one) and lets the harness enforce a timeout. A timeout is a failure,
//! never a pass.

mod support;

use sbx_sys as sys;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use support::{escape, random_token, sbx, skip_without_sandbox, TempDir};

const CANARY_NAME: &str = ".sbx-canary";
const INHERITED_FD: i32 = 42;

/// Keep this list in sync with `sbx-escape`'s printed attempt names.
const ATTEMPTS: &[&str] = &[
    "ssh-canary",
    "etc-passwd",
    "dotdot",
    "symlink-escape",
    "env-secret",
    "inherited-fd",
    "tcp-host",
    "unix-abstract",
    "proc-inspect",
    "proc-signal",
    "tiocsti",
    "write-outside",
    "write-readonly",
    "hostname",
    "capabilities",
    "no-new-privs",
    "setuid",
    "unshare-user",
    "mount",
    "setns",
    "chroot",
    "clone3",
    "x32-syscall",
    "ptrace",
    "process-vm",
    "pidfd-open",
    "bpf",
    "perf-event-open",
    "userfaultfd",
    "io-uring",
    "keyctl",
    "open-by-handle",
];

struct Fixture {
    temp: TempDir,
    host_home: PathBuf,
    grant: PathBuf,
    secret: PathBuf,
    outside: PathBuf,
    read_only: PathBuf,
    bin: PathBuf,
    sandbox_hostname: String,
    token: String,
    tcp: TcpListener,
    abstract_name: String,
    _abstract: OwnedFd,
    _canary: OwnedFd,
    helper: Child,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new("escape");
        let token = random_token();

        let host_home = temp.join("home");
        fs::create_dir_all(host_home.join(".ssh")).unwrap();
        fs::write(host_home.join(".ssh/id_rsa"), format!("{token}\n")).unwrap();

        let grant = temp.join("grant");
        fs::create_dir_all(&grant).unwrap();
        fs::write(grant.join("allowed.txt"), b"allowed\n").unwrap();

        let secret = temp.join("secret");
        fs::create_dir_all(&secret).unwrap();
        fs::write(secret.join(CANARY_NAME), format!("{token}\n")).unwrap();

        let outside = temp.join("outside");
        fs::create_dir_all(&outside).unwrap();

        let read_only = temp.join("ro");
        fs::create_dir_all(&read_only).unwrap();
        fs::write(read_only.join("keep.txt"), b"keep\n").unwrap();

        let bin = temp.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let escape_copy = bin.join("sbx-escape");
        fs::copy(escape(), &escape_copy).expect("copy sbx-escape");
        let mut mode = fs::metadata(&escape_copy).unwrap().permissions();
        mode.set_mode(0o755);
        fs::set_permissions(&escape_copy, mode).unwrap();

        symlink(secret.join(CANARY_NAME), grant.join("escape-abs"))
            .expect("absolute symlink fixture");
        symlink("../secret/.sbx-canary", grant.join("escape-rel"))
            .expect("relative symlink fixture");

        let helper = Command::new("/bin/sleep")
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start host helper process");

        let tcp = TcpListener::bind(("127.0.0.1", 0)).expect("bind host TCP listener");
        let abstract_name = format!("sbx-escape-{}", &token[..24]);
        let abstract_fd =
            sys::bind_abstract_listener(&abstract_name).expect("bind host abstract socket");

        let canary_path = secret.join(CANARY_NAME);
        let canary = sys::open_inheritable_read(&canary_path).expect("open canary");
        sys::dup2_fd(&canary, INHERITED_FD).expect("dup canary to inherited fd");

        let sandbox_hostname = format!("sbx-escape-{}-{}", std::process::id(), &token[..8]);

        Self {
            temp,
            host_home,
            grant,
            secret,
            outside,
            read_only,
            bin,
            sandbox_hostname,
            token,
            tcp,
            abstract_name,
            _abstract: abstract_fd,
            _canary: canary,
            helper,
        }
    }

    fn tcp_port(&self) -> u16 {
        self.tcp.local_addr().expect("listener address").port()
    }

    fn battery_args(&self, attempt: &str) -> Vec<String> {
        vec![
            "--only".to_string(),
            attempt.to_string(),
            "--host-home".to_string(),
            self.host_home.to_string_lossy().into_owned(),
            "--grant".to_string(),
            self.grant.to_string_lossy().into_owned(),
            "--secret".to_string(),
            self.secret.to_string_lossy().into_owned(),
            "--outside".to_string(),
            self.outside.to_string_lossy().into_owned(),
            "--ro".to_string(),
            self.read_only.to_string_lossy().into_owned(),
            "--host-pid".to_string(),
            self.helper.id().to_string(),
            "--tcp-port".to_string(),
            self.tcp_port().to_string(),
            "--abstract".to_string(),
            self.abstract_name.clone(),
            "--sandbox-hostname".to_string(),
            self.sandbox_hostname.clone(),
        ]
    }

    fn outside_command(&self, attempt: &str) -> Command {
        let mut command = Command::new(self.bin.join("sbx-escape"));
        command
            .args(self.battery_args(attempt))
            .env("SBX_HOST_SECRET", &self.token)
            .stdin(Stdio::null());
        command
    }

    fn inside_command(&self, attempt: &str) -> Command {
        let mut command = Command::new(sbx());
        command
            .arg("run")
            .arg("--quiet")
            .arg("--ro")
            .arg(&self.grant)
            .arg("--ro")
            .arg(&self.read_only)
            .arg("--ro")
            .arg(&self.bin)
            .arg("--hostname")
            .arg(&self.sandbox_hostname)
            .arg("--")
            .arg(self.bin.join("sbx-escape"))
            .args(self.battery_args(attempt))
            .stdin(Stdio::null());
        command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.helper.kill();
        let _ = self.helper.wait();
        let _ = fs::remove_file(self.outside.join("sbx-escape-pwned"));
        let _ = fs::remove_file(self.read_only.join("sbx-escape-pwned"));
        let _ = fs::remove_dir_all(self.temp.path());
    }
}

#[derive(Debug, Clone)]
struct Verdict {
    outcome: String,
    detail: String,
}

fn run_with_timeout(mut command: Command) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn command");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait().expect("poll child") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let output = child.wait_with_output().expect("collect timed-out child");
                panic!(
                    "attempt timed out; stdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    child.wait_with_output().expect("collect output")
}

fn parse_verdict(output: &Output, attempt: &str) -> Verdict {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one JSON line for {attempt}, got:\n{stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|error| panic!("invalid JSON for {attempt}: {error}: {}", lines[0]));
    assert_eq!(value["name"], attempt);
    for key in ["name", "goal", "outcome", "detail"] {
        assert!(
            value.get(key).is_some(),
            "attempt {attempt} is missing `{key}`: {value}"
        );
    }
    let outcome = value["outcome"].as_str().expect("outcome is a string");
    assert!(
        matches!(outcome, "blocked" | "escaped" | "error"),
        "attempt {attempt} has invalid outcome `{outcome}`"
    );
    assert!(
        value["goal"]
            .as_str()
            .is_some_and(|goal| goal.starts_with('G')),
        "attempt {attempt} has no G goal"
    );
    Verdict {
        outcome: outcome.to_string(),
        detail: value["detail"].as_str().unwrap_or_default().to_string(),
    }
}

fn is_skipped(attempt: &str, verdict: &Verdict) -> bool {
    verdict.detail.starts_with("SKIPPED:")
        || (attempt == "clone3" && verdict.detail.contains("ENOSYS"))
}

#[test]
fn escape_battery_positive_control_then_sandbox() {
    if skip_without_sandbox() {
        return;
    }
    assert!(
        escape().is_file(),
        "sbx-escape is missing at {}",
        escape().display()
    );
    let fixture = Fixture::new();

    let mut outside = BTreeMap::new();
    let mut skipped = Vec::new();
    for attempt in ATTEMPTS {
        let output = run_with_timeout(fixture.outside_command(attempt));
        assert!(
            output.status.success(),
            "outside control for {attempt} exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        let verdict = parse_verdict(&output, attempt);
        if verdict.outcome == "escaped" {
            outside.insert(*attempt, verdict);
        } else if is_skipped(attempt, &verdict) {
            eprintln!("SKIPPED: {attempt}: {}", verdict.detail);
            skipped.push(*attempt);
        } else {
            panic!(
                "positive control for {attempt} did not escape, so the inside result cannot prove anything: {}",
                verdict.detail
            );
        }
    }

    // The canary must be reachable outside, otherwise the file attempts prove
    // only that the fixture paths are wrong.
    let outside_details: String = outside
        .values()
        .map(|verdict| verdict.detail.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        outside_details.contains(&fixture.token),
        "the canary token never appeared in any positive control; fixture is broken"
    );

    // The positive control is allowed to leave these behind; the sandbox is not.
    let _ = fs::remove_file(fixture.outside.join("sbx-escape-pwned"));
    let _ = fs::remove_file(fixture.read_only.join("sbx-escape-pwned"));

    let mut checked = 0;
    for attempt in ATTEMPTS {
        let output = run_with_timeout(fixture.inside_command(attempt));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(0),
            "sandboxed attempt {attempt} exited {:?}: {stderr}",
            output.status.code()
        );
        let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), stderr);
        assert!(
            !combined.contains(&fixture.token),
            "CANARY LEAKED during {attempt}: {combined}"
        );
        let verdict = parse_verdict(&output, attempt);
        if skipped.contains(attempt) {
            assert_ne!(
                verdict.outcome, "escaped",
                "attempt {attempt} escaped inside even though the outside control was skipped: {}",
                verdict.detail
            );
            continue;
        }
        assert_eq!(
            verdict.outcome, "blocked",
            "attempt {attempt} was not blocked inside: {}",
            verdict.detail
        );
        checked += 1;
    }

    assert!(
        checked + skipped.len() == ATTEMPTS.len(),
        "only {checked} attempts were verified and {} were skipped",
        skipped.len()
    );
    assert!(!fixture.outside.join("sbx-escape-pwned").exists());
    assert!(!fixture.read_only.join("sbx-escape-pwned").exists());
    assert_eq!(
        fs::read(fixture.read_only.join("keep.txt")).unwrap(),
        b"keep\n"
    );
}
