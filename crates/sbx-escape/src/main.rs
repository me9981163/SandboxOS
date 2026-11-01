#![forbid(unsafe_code)]
//! Escape-attempt battery helper.
//!
//! Every invocation prints exactly one JSON object per attempted escape:
//! `{"name","goal","outcome","detail"}`, where `outcome` is `blocked`,
//! `escaped`, or `error`. The same binary is run outside the sandbox as a
//! positive control and again inside `sbx run`; the integration test decides
//! whether the pair of results proves anything.
//!
//! `--only NAME` runs one attempt. The test harness uses that so a namespace
//! attempt cannot change the process state seen by the next attempt, and so a
//! hung attempt can be killed by the harness timeout. A timeout is never
//! reported as `blocked`.

use sbx_sys as sys;
use serde::Serialize;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Descriptor the harness deliberately leaves inheritable. sbx must close it
/// before `execve`.
const INHERITED_FD: c_int = 42;
const CANARY_NAME: &str = ".sbx-canary";
const SNIPPET_LIMIT: usize = 240;

fn main() {
    let config = match Config::parse(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("sbx-escape: {message}");
            std::process::exit(2);
        }
    };

    let selected: Vec<(&str, &str)> = ATTEMPTS
        .iter()
        .copied()
        .filter(|(name, _)| config.only.as_deref().is_none_or(|only| only == *name))
        .collect();

    if selected.is_empty() {
        eprintln!(
            "sbx-escape: unknown attempt `{}`",
            config.only.as_deref().unwrap_or("")
        );
        std::process::exit(2);
    }

    for (name, goal) in selected {
        match attempt(name, &config) {
            Ok(observation) => {
                let outcome = if observation.escaped {
                    "escaped"
                } else {
                    "blocked"
                };
                emit(name, goal, outcome, &observation.detail);
            }
            Err(message) if message.starts_with("SKIPPED:") => {
                // A skipped attempt must be visible and must never be counted
                // as a pass. `error` is the only allowed non-verdict outcome.
                eprintln!(
                    "SKIPPED: {name}: {}",
                    message.trim_start_matches("SKIPPED:")
                );
                emit(name, goal, "error", &message);
            }
            Err(message) => emit(name, goal, "error", &message),
        }
    }
}

/// Every attempt names the goal from `docs/THREAT_MODEL.md` that it tests.
const ATTEMPTS: &[(&str, &str)] = &[
    ("ssh-canary", "G1"),
    ("etc-passwd", "G1"),
    ("dotdot", "G1"),
    ("symlink-escape", "G1"),
    ("env-secret", "G1"),
    ("inherited-fd", "G1"),
    ("tcp-host", "G2"),
    ("unix-abstract", "G2"),
    ("proc-inspect", "G3"),
    ("proc-signal", "G3"),
    ("tiocsti", "G3"),
    ("write-outside", "G4"),
    ("write-readonly", "G4"),
    ("hostname", "G4"),
    ("capabilities", "G5"),
    ("no-new-privs", "G5"),
    ("setuid", "G5"),
    ("unshare-user", "G5"),
    ("mount", "G5"),
    ("setns", "G5"),
    ("chroot", "G5"),
    ("clone3", "G5"),
    ("x32-syscall", "G5"),
    ("ptrace", "G3"),
    ("process-vm", "G3"),
    ("pidfd-open", "G3"),
    ("bpf", "G5"),
    ("perf-event-open", "G5"),
    ("userfaultfd", "G5"),
    ("io-uring", "G5"),
    ("keyctl", "G5"),
    ("open-by-handle", "G5"),
];

#[derive(Serialize)]
struct JsonLine<'a> {
    name: &'a str,
    goal: &'a str,
    outcome: &'a str,
    detail: &'a str,
}

fn emit(name: &str, goal: &str, outcome: &str, detail: &str) {
    let line = JsonLine {
        name,
        goal,
        outcome,
        detail,
    };
    match serde_json::to_string(&line) {
        Ok(text) => println!("{text}"),
        Err(error) => eprintln!("sbx-escape: cannot encode result: {error}"),
    }
}

struct Observation {
    escaped: bool,
    detail: String,
}

fn escaped(detail: impl Into<String>) -> Observation {
    Observation {
        escaped: true,
        detail: detail.into(),
    }
}

fn blocked(detail: impl Into<String>) -> Observation {
    Observation {
        escaped: false,
        detail: detail.into(),
    }
}

#[derive(Default)]
struct Config {
    only: Option<String>,
    host_home: Option<PathBuf>,
    grant: Option<PathBuf>,
    secret: Option<PathBuf>,
    outside: Option<PathBuf>,
    read_only: Option<PathBuf>,
    host_pid: Option<i32>,
    tcp_port: Option<u16>,
    abstract_name: Option<String>,
    sandbox_hostname: Option<String>,
}

impl Config {
    fn parse(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut config = Config::default();
        let mut args = args;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--only" => config.only = Some(next_value(&mut args, "--only")?),
                "--host-home" => {
                    config.host_home = Some(PathBuf::from(next_value(&mut args, "--host-home")?))
                }
                "--grant" => config.grant = Some(PathBuf::from(next_value(&mut args, "--grant")?)),
                "--secret" => {
                    config.secret = Some(PathBuf::from(next_value(&mut args, "--secret")?))
                }
                "--outside" => {
                    config.outside = Some(PathBuf::from(next_value(&mut args, "--outside")?))
                }
                "--ro" => config.read_only = Some(PathBuf::from(next_value(&mut args, "--ro")?)),
                "--host-pid" => {
                    let text = next_value(&mut args, "--host-pid")?;
                    config.host_pid = Some(
                        text.parse()
                            .map_err(|_| format!("--host-pid `{text}` is not a pid"))?,
                    );
                }
                "--tcp-port" => {
                    let text = next_value(&mut args, "--tcp-port")?;
                    config.tcp_port = Some(
                        text.parse()
                            .map_err(|_| format!("--tcp-port `{text}` is not a port"))?,
                    );
                }
                "--abstract" => config.abstract_name = Some(next_value(&mut args, "--abstract")?),
                "--sandbox-hostname" => {
                    config.sandbox_hostname = Some(next_value(&mut args, "--sandbox-hostname")?)
                }
                "--list" => {
                    for (name, goal) in ATTEMPTS {
                        println!("{name} {goal}");
                    }
                    std::process::exit(0);
                }
                "--help" | "-h" => {
                    println!(
                        "usage: sbx-escape [--only NAME] [--host-home PATH] [--grant PATH] \
                         [--secret PATH] [--outside PATH] [--ro PATH] [--host-pid PID] \
                         [--tcp-port PORT] [--abstract NAME] [--sandbox-hostname NAME]"
                    );
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument `{other}` (try --help)")),
            }
        }
        Ok(config)
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn attempt(name: &str, config: &Config) -> Result<Observation, String> {
    match name {
        "ssh-canary" => attempt_ssh_canary(config),
        "etc-passwd" => attempt_etc_passwd(),
        "dotdot" => attempt_dotdot(config),
        "symlink-escape" => attempt_symlink(config),
        "env-secret" => attempt_env_secret(),
        "inherited-fd" => attempt_inherited_fd(),
        "tcp-host" => attempt_tcp_host(config),
        "unix-abstract" => attempt_unix_abstract(config),
        "proc-inspect" => attempt_proc_inspect(config),
        "proc-signal" => attempt_proc_signal(config),
        "tiocsti" => attempt_tiocsti(),
        "write-outside" => attempt_write_outside(config),
        "write-readonly" => attempt_write_readonly(config),
        "hostname" => attempt_hostname(config),
        "capabilities" => attempt_capabilities(),
        "no-new-privs" => attempt_no_new_privs(),
        "setuid" => attempt_setuid(),
        "unshare-user" => attempt_unshare_user(),
        "mount" => attempt_mount(),
        "setns" => attempt_setns(),
        "chroot" => attempt_chroot(),
        "clone3" => attempt_clone3(),
        "x32-syscall" => attempt_x32_syscall(),
        "ptrace" => attempt_ptrace(),
        "process-vm" => attempt_process_vm(),
        "pidfd-open" => attempt_pidfd_open(),
        "bpf" => attempt_bpf(),
        "perf-event-open" => attempt_perf_event_open(),
        "userfaultfd" => attempt_userfaultfd(),
        "io-uring" => attempt_io_uring(),
        "keyctl" => attempt_keyctl(),
        "open-by-handle" => attempt_open_by_handle(),
        other => Err(format!("unknown attempt `{other}`")),
    }
}

fn attempt_ssh_canary(config: &Config) -> Result<Observation, String> {
    let host_home = config
        .host_home
        .as_ref()
        .ok_or("ssh-canary requires --host-home")?;
    let sandbox_home = std::env::var_os("HOME").map(PathBuf::from);
    let mut paths = vec![host_home.join(".ssh/id_rsa")];
    if let Some(home) = sandbox_home {
        paths.push(home.join(".ssh/id_rsa"));
    }

    let mut notes = Vec::new();
    for path in paths {
        match fs::read(&path) {
            Ok(data) if !data.is_empty() => {
                return Ok(escaped(format!(
                    "read {} bytes from {}: {}",
                    data.len(),
                    path.display(),
                    snippet(&data)
                )));
            }
            Ok(_) => notes.push(format!("{}: empty", path.display())),
            Err(error) => notes.push(format!("{}: {error}", path.display())),
        }
    }
    Ok(blocked(notes.join("; ")))
}

fn attempt_etc_passwd() -> Result<Observation, String> {
    let data =
        fs::read("/etc/passwd").map_err(|error| format!("cannot read /etc/passwd: {error}"))?;
    let text = String::from_utf8_lossy(&data);
    // The runner writes this exact record into the synthesized file. Seeing it
    // proves the target is reading the sandbox's /etc, not the host's.
    if text.contains("sbx:x:1000:1000:sbx sandbox:") {
        Ok(blocked(format!(
            "read the synthesized sandbox /etc/passwd ({} bytes)",
            data.len()
        )))
    } else {
        Ok(escaped(format!(
            "read a host-looking /etc/passwd ({} bytes): {}",
            data.len(),
            snippet(&data)
        )))
    }
}

fn attempt_dotdot(config: &Config) -> Result<Observation, String> {
    let grant = config.grant.as_ref().ok_or("dotdot requires --grant")?;
    let secret = config.secret.as_ref().ok_or("dotdot requires --secret")?;
    let relative = Path::new("..").join(
        secret
            .file_name()
            .ok_or("dotdot: --secret has no final component")?,
    );
    let paths = [
        grant.join(&relative).join(CANARY_NAME),
        grant.join("..").join(&relative).join(CANARY_NAME),
    ];
    let mut notes = Vec::new();
    for path in paths {
        match fs::read(&path) {
            Ok(data) if !data.is_empty() => {
                return Ok(escaped(format!(
                    "traversal reached {} ({} bytes): {}",
                    path.display(),
                    data.len(),
                    snippet(&data)
                )));
            }
            Ok(_) => notes.push(format!("{}: empty", path.display())),
            Err(error) => notes.push(format!("{}: {error}", path.display())),
        }
    }
    Ok(blocked(notes.join("; ")))
}

fn attempt_symlink(config: &Config) -> Result<Observation, String> {
    let grant = config
        .grant
        .as_ref()
        .ok_or("symlink-escape requires --grant")?;
    let paths = [grant.join("escape-abs"), grant.join("escape-rel")];
    let mut notes = Vec::new();
    for path in paths {
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) => {
                return Err(format!(
                    "symlink fixture {} is missing: {error}",
                    path.display()
                ))
            }
        }
        match fs::read(&path) {
            Ok(data) if !data.is_empty() => {
                return Ok(escaped(format!(
                    "followed {} to {} bytes: {}",
                    path.display(),
                    data.len(),
                    snippet(&data)
                )));
            }
            Ok(_) => notes.push(format!("{}: empty target", path.display())),
            Err(error) => notes.push(format!("{}: {error}", path.display())),
        }
    }
    Ok(blocked(notes.join("; ")))
}

fn attempt_env_secret() -> Result<Observation, String> {
    match std::env::var("SBX_HOST_SECRET") {
        Ok(value) if !value.is_empty() => Ok(escaped(format!(
            "SBX_HOST_SECRET is present ({} bytes); value withheld from output",
            value.len()
        ))),
        Ok(_) => Ok(blocked("SBX_HOST_SECRET is present but empty")),
        Err(std::env::VarError::NotPresent) => Ok(blocked("SBX_HOST_SECRET is absent")),
        Err(error) => Err(format!("cannot inspect SBX_HOST_SECRET: {error}")),
    }
}

fn attempt_inherited_fd() -> Result<Observation, String> {
    match sys::read_fd_once(INHERITED_FD, 4096) {
        Ok(data) if !data.is_empty() => Ok(escaped(format!(
            "read {} bytes from inherited fd {INHERITED_FD}: {}",
            data.len(),
            snippet(&data)
        ))),
        Ok(_) => Ok(blocked(format!("inherited fd {INHERITED_FD} was empty"))),
        Err(error) if error.raw_os_error() == Some(libc::EBADF) => {
            Ok(blocked(format!("inherited fd {INHERITED_FD} is closed")))
        }
        Err(error) => Err(format!("reading inherited fd {INHERITED_FD}: {error}")),
    }
}

fn attempt_tcp_host(config: &Config) -> Result<Observation, String> {
    let port = config.tcp_port.ok_or("tcp-host requires --tcp-port")?;
    match sys::connect_tcp([127, 0, 0, 1], port) {
        Ok(()) => Ok(escaped(format!(
            "connected to host TCP listener 127.0.0.1:{port}"
        ))),
        Err(error) if is_network_denial(&error) => Ok(blocked(format!(
            "connection to 127.0.0.1:{port} failed: {error}"
        ))),
        Err(error) => Err(format!("connection to 127.0.0.1:{port}: {error}")),
    }
}

fn attempt_unix_abstract(config: &Config) -> Result<Observation, String> {
    let name = config
        .abstract_name
        .as_deref()
        .ok_or("unix-abstract requires --abstract")?;
    match sys::connect_abstract(name) {
        Ok(()) => Ok(escaped(format!(
            "connected to host abstract unix socket `{name}`"
        ))),
        Err(error) if is_network_denial(&error) => Ok(blocked(format!(
            "abstract socket `{name}` unavailable: {error}"
        ))),
        Err(error) => Err(format!("abstract socket `{name}`: {error}")),
    }
}

fn attempt_proc_inspect(config: &Config) -> Result<Observation, String> {
    let pid = config.host_pid.ok_or("proc-inspect requires --host-pid")?;
    let path = PathBuf::from(format!("/proc/{pid}/cmdline"));
    match fs::read(&path) {
        Ok(data) if !data.is_empty() => Ok(escaped(format!(
            "read host process cmdline {} ({} bytes): {}",
            path.display(),
            data.len(),
            snippet(&data)
        ))),
        Ok(_) => Ok(blocked(format!("{} is empty", path.display()))),
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.kind() == io::ErrorKind::PermissionDenied =>
        {
            Ok(blocked(format!(
                "cannot inspect {}: {error}",
                path.display()
            )))
        }
        Err(error) => Err(format!("inspecting {}: {error}", path.display())),
    }
}

fn attempt_proc_signal(config: &Config) -> Result<Observation, String> {
    let pid = config.host_pid.ok_or("proc-signal requires --host-pid")?;
    // Signal 0 performs existence and permission checks without delivering a
    // signal, so the positive control does not disturb the helper process.
    match sys::kill(pid, 0) {
        Ok(()) => Ok(escaped(format!("kill({pid}, 0) reached a host process"))),
        Err(error)
            if error.raw_os_error() == Some(libc::ESRCH)
                || error.raw_os_error() == Some(libc::EPERM) =>
        {
            Ok(blocked(format!("kill({pid}, 0) failed: {error}")))
        }
        Err(error) => Err(format!("kill({pid}, 0): {error}")),
    }
}

fn attempt_tiocsti() -> Result<Observation, String> {
    if !sys::stdin_is_tty() {
        return Err("SKIPPED: stdin is not a pty, so TIOCSTI cannot be tested".to_string());
    }
    match sys::tiocsti(b'X') {
        Ok(()) => Ok(escaped("TIOCSTI injected a byte into the terminal")),
        Err(error)
            if error.raw_os_error() == Some(libc::EPERM)
                || error.raw_os_error() == Some(libc::EIO)
                || error.raw_os_error() == Some(libc::ENOTTY) =>
        {
            Ok(blocked(format!("TIOCSTI failed: {error}")))
        }
        Err(error) => Err(format!("TIOCSTI: {error}")),
    }
}

fn attempt_write_outside(config: &Config) -> Result<Observation, String> {
    let outside = config
        .outside
        .as_ref()
        .ok_or("write-outside requires --outside")?;
    let target = outside.join("sbx-escape-pwned");
    match fs::write(&target, b"sbx-escape wrote outside the granted paths\n") {
        Ok(()) => Ok(escaped(format!(
            "wrote {} outside every grant",
            target.display()
        ))),
        Err(error) => Ok(blocked(format!(
            "write to {} failed: {error}",
            target.display()
        ))),
    }
}

fn attempt_write_readonly(config: &Config) -> Result<Observation, String> {
    let read_only = config
        .read_only
        .as_ref()
        .ok_or("write-readonly requires --ro")?;
    let target = read_only.join("sbx-escape-pwned");
    match fs::write(&target, b"sbx-escape wrote into a read-only grant\n") {
        Ok(()) => Ok(escaped(format!(
            "wrote {} through a read-only grant",
            target.display()
        ))),
        Err(error) => Ok(blocked(format!(
            "write to {} failed: {error}",
            target.display()
        ))),
    }
}

fn attempt_hostname(config: &Config) -> Result<Observation, String> {
    let expected = config
        .sandbox_hostname
        .as_deref()
        .ok_or("hostname requires --sandbox-hostname")?;
    let actual = sys::gethostname().map_err(|error| format!("gethostname: {error}"))?;
    if actual == expected {
        Ok(blocked(format!("hostname is the sandbox value `{actual}`")))
    } else {
        Ok(escaped(format!(
            "hostname is `{actual}`, not the sandbox value `{expected}`"
        )))
    }
}

fn attempt_capabilities() -> Result<Observation, String> {
    let status = read_status()?;
    let fields = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];
    let mut values = Vec::new();
    let mut any = false;
    for field in fields {
        let value = status_hex(&status, field)
            .ok_or_else(|| format!("{field} missing from /proc/self/status"))?;
        any |= value != 0;
        values.push(format!("{field}={value:#x}"));
    }
    let detail = values.join(" ");
    if any {
        Ok(escaped(format!("non-zero capability set: {detail}")))
    } else {
        Ok(blocked(detail))
    }
}

fn attempt_no_new_privs() -> Result<Observation, String> {
    let status = read_status()?;
    let value =
        status_decimal(&status, "NoNewPrivs").ok_or("NoNewPrivs missing from /proc/self/status")?;
    if value == 0 {
        Ok(escaped("NoNewPrivs=0"))
    } else {
        Ok(blocked(format!("NoNewPrivs={value}")))
    }
}

fn attempt_setuid() -> Result<Observation, String> {
    let mountinfo =
        fs::read_to_string("/proc/self/mountinfo").map_err(|e| format!("mountinfo: {e}"))?;
    let (mountpoint, options) = usr_mount(&mountinfo)
        .ok_or("cannot find the mount covering /usr in /proc/self/mountinfo")?;
    let nosuid = options.split(',').any(|option| option == "nosuid");
    let status = read_status()?;
    let nnp =
        status_decimal(&status, "NoNewPrivs").ok_or("NoNewPrivs missing from /proc/self/status")?;
    let detail =
        format!("mount `{mountpoint}` options `{options}` nosuid={nosuid} NoNewPrivs={nnp}");
    if !nosuid {
        Ok(escaped(format!("setuid bits are honoured: {detail}")))
    } else if nnp == 1 {
        Ok(blocked(detail))
    } else {
        Err(format!(
            "nosuid is set but NoNewPrivs is not active: {detail}"
        ))
    }
}

fn attempt_unshare_user() -> Result<Observation, String> {
    match sys::unshare(sys::CLONE_NEWUSER | sys::CLONE_NEWNS) {
        Ok(()) => Ok(escaped("unshare(CLONE_NEWUSER|CLONE_NEWNS) succeeded")),
        Err(error) if is_namespace_denial(&error) => Ok(blocked(format!(
            "unshare(CLONE_NEWUSER|CLONE_NEWNS) failed: {error}"
        ))),
        Err(error) => Err(format!("unshare(CLONE_NEWUSER|CLONE_NEWNS): {error}")),
    }
}

fn attempt_mount() -> Result<Observation, String> {
    let directory = std::env::temp_dir().join(format!("sbx-escape-mnt-{}", std::process::id()));
    fs::create_dir_all(&directory).map_err(|e| format!("mkdir {}: {e}", directory.display()))?;
    if let Err(error) = sys::unshare(sys::CLONE_NEWUSER | sys::CLONE_NEWNS) {
        return Ok(blocked(format!(
            "could not create a mount namespace: {error}"
        )));
    }
    let target = CString::new(directory.as_os_str().as_bytes())
        .map_err(|_| "mount target contains a NUL byte")?;
    let options = CString::from(c"size=1m");
    match sys::mount_tmpfs(&target, &options, 0) {
        Ok(()) => Ok(escaped(format!(
            "mounted a tmpfs at {} after creating a user/mount namespace",
            directory.display()
        ))),
        Err(error) => Err(format!("mount tmpfs at {}: {error}", directory.display())),
    }
}

fn attempt_setns() -> Result<Observation, String> {
    // A deliberately invalid descriptor distinguishes the filter from the
    // kernel: an unfiltered call returns EBADF, the filter returns EPERM.
    match sys::setns(-1, sys::CLONE_NEWNS) {
        Ok(()) => Ok(escaped("setns(-1) unexpectedly succeeded")),
        Err(error) if is_namespace_denial(&error) => {
            Ok(blocked(format!("setns(-1, CLONE_NEWNS) failed: {error}")))
        }
        Err(error) => Ok(escaped(format!(
            "setns(-1, CLONE_NEWNS) reached the kernel: {error}"
        ))),
    }
}

fn attempt_chroot() -> Result<Observation, String> {
    if let Err(error) = sys::unshare(sys::CLONE_NEWUSER | sys::CLONE_NEWNS) {
        return Ok(blocked(format!(
            "could not create a user/mount namespace: {error}"
        )));
    }
    match sys::chroot(c"/") {
        Ok(()) => Ok(escaped("chroot(\"/\") succeeded after unshare")),
        Err(error) => Err(format!("chroot(\"/\"): {error}")),
    }
}

fn attempt_clone3() -> Result<Observation, String> {
    match sys::clone3_probe() {
        Ok(()) => Ok(escaped("clone3 returned success with invalid arguments")),
        Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => {
            Ok(blocked("clone3 returned ENOSYS"))
        }
        Err(error) => Ok(escaped(format!(
            "clone3 reached the kernel and returned: {error}"
        ))),
    }
}

/// The probes below use an invalid argument that an unfiltered kernel handles
/// with a non-`EPERM` result. Seeing that result outside and `EPERM` inside is
/// what makes the filter, rather than ordinary kernel policy, observable.
fn probe_outcome(label: &str, result: io::Result<()>) -> Observation {
    match result {
        Ok(()) => escaped(format!("{label} reached the kernel and succeeded")),
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
            blocked(format!("{label} denied with EPERM: {error}"))
        }
        Err(error) => escaped(format!("{label} reached the kernel: {error}")),
    }
}

fn attempt_x32_syscall() -> Result<Observation, String> {
    Ok(probe_outcome("x32 getpid", sys::x32_getpid_probe()))
}

fn attempt_ptrace() -> Result<Observation, String> {
    Ok(probe_outcome(
        "ptrace(PTRACE_PEEKDATA, -1)",
        sys::ptrace_probe(),
    ))
}

fn attempt_process_vm() -> Result<Observation, String> {
    let mut payload = *b"SBX-PROCESS-VM-POSITIVE-CONTROL";
    match sys::process_vm_readv_self(&mut payload) {
        Ok(read) if read == payload.len() => Ok(escaped(format!(
            "process_vm_readv read {read} bytes from this process's own memory"
        ))),
        Ok(read) => Err(format!(
            "process_vm_readv returned {read} bytes, expected {}",
            payload.len()
        )),
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => Ok(blocked(format!(
            "process_vm_readv denied with EPERM: {error}"
        ))),
        Err(error) => Ok(escaped(format!(
            "process_vm_readv reached the kernel: {error}"
        ))),
    }
}

fn attempt_pidfd_open() -> Result<Observation, String> {
    Ok(probe_outcome("pidfd_open(self)", sys::pidfd_open_probe()))
}

fn attempt_bpf() -> Result<Observation, String> {
    Ok(probe_outcome("bpf(unknown command)", sys::bpf_probe()))
}

fn attempt_perf_event_open() -> Result<Observation, String> {
    Ok(probe_outcome(
        "perf_event_open(NULL)",
        sys::perf_event_open_probe(),
    ))
}

fn attempt_userfaultfd() -> Result<Observation, String> {
    Ok(probe_outcome(
        "userfaultfd(invalid flags)",
        sys::userfaultfd_probe(),
    ))
}

fn attempt_io_uring() -> Result<Observation, String> {
    Ok(probe_outcome(
        "io_uring_setup(NULL)",
        sys::io_uring_setup_probe(),
    ))
}

fn attempt_keyctl() -> Result<Observation, String> {
    Ok(probe_outcome("keyctl(unknown op)", sys::keyctl_probe()))
}

fn attempt_open_by_handle() -> Result<Observation, String> {
    Ok(probe_outcome(
        "open_by_handle_at(-1, NULL)",
        sys::open_by_handle_at_probe(),
    ))
}

fn read_status() -> Result<String, String> {
    fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status: {e}"))
}

fn status_field<'a>(status: &'a str, field: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name == field).then(|| value.trim())
    })
}

fn status_hex(status: &str, field: &str) -> Option<u64> {
    u64::from_str_radix(status_field(status, field)?, 16).ok()
}

fn status_decimal(status: &str, field: &str) -> Option<u64> {
    status_field(status, field)?.parse().ok()
}

/// Return the mount point and per-mount options for `/usr`, falling back to the
/// root mount on hosts where `/usr` is part of `/`.
fn usr_mount(mountinfo: &str) -> Option<(String, String)> {
    let mut root = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 6 {
            continue;
        }
        let mountpoint = fields[4].to_string();
        let options = fields[5].to_string();
        if mountpoint == "/usr" {
            return Some((mountpoint, options));
        }
        if mountpoint == "/" {
            root = Some((mountpoint, options));
        }
    }
    root
}

fn is_namespace_denial(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EPERM) | Some(libc::EACCES) | Some(libc::ENOSYS)
    )
}

fn is_network_denial(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NotFound
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::TimedOut
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::PermissionDenied
    )
}

fn snippet(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    let mut out: String = text.chars().take(SNIPPET_LIMIT).collect();
    if text.chars().count() > SNIPPET_LIMIT {
        out.push_str("...");
    }
    out.replace('\0', " ")
}
