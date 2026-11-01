#![forbid(unsafe_code)]
//! Sandbox construction and target execution.
//!
//! The process model is documented in
//! `docs/decisions/002-sandbox-process-model.md`:
//!
//! - The CLI process (`P`) validates arguments and builds a complete, immutable
//!   plan, including every `CString` and pointer array.
//! - `P` forks supervisor `A`. `A` enters the user namespace, waits for `P` to
//!   write the uid/gid maps, creates the remaining namespaces, builds the new
//!   root, pivots into it, then unshares the PID namespace.
//! - `A` forks target `B`, which is PID 1 in the new PID namespace and mounts
//!   the fresh `/proc` before dropping capabilities and executing the target.
//! - `A` waits for `B` and relays the raw wait status to `P` over a pipe. All
//!   three processes use `PR_SET_PDEATHSIG(SIGKILL)` so the tree cannot outlive
//!   the CLI.
//!
//! Everything `A` and `B` need is allocated before the first `fork`. The code
//! they run is restricted to the small safe wrappers in `sbx-sys`; no
//! formatting, allocation, `std::fs`, or locks are used in those paths.

use sbx_core::{GrantMode, PathPolicy, PolicyDecision, ProtectionSummary};
use sbx_sys as sys;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::raw::{c_char, c_int, c_ulong};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// The fixed sandbox home. `HOME` always points here; `--env HOME` is rejected
/// so a grant cannot silently turn the target's home directory into a host path.
pub const SANDBOX_HOME: &str = "/home/sbx";
/// PATH used inside the sandbox unless `--env PATH` supplies a host value.
pub const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
/// Default UTS-namespace hostname.
pub const DEFAULT_HOSTNAME: &str = "sbx";

const EXIT_INTERNAL: i32 = 125;
const EXIT_UNAVAILABLE: i32 = 124;
const EXIT_NOT_FOUND: i32 = 127;
const EXIT_NOT_EXECUTABLE: i32 = 126;

const EIO: i32 = 5;
const EEXIST: i32 = 17;

// Frames sent from A to P over the status pipe.
const FRAME_SETUP_ERROR: u8 = 1;
const FRAME_EXEC_ERROR: u8 = 2;
const FRAME_TARGET_EXIT: u8 = 3;
const FRAME_SUPERVISOR_ERROR: u8 = 4;

// Non-plan stages reported by A.
const SETUP_PDEATHSIG: u16 = 0x8001;
const SETUP_USERNS: u16 = 0x8002;
const SETUP_NAMESPACES: u16 = 0x8003;
const SETUP_PRIVATE_MOUNTS: u16 = 0x8004;
const SETUP_HOSTNAME: u16 = 0x8005;
const SETUP_LOOPBACK: u16 = 0x8006;
const SETUP_PIVOT: u16 = 0x8007;
const SETUP_OLDROOT: u16 = 0x8008;
const SETUP_UNSHARE_PID: u16 = 0x8009;
const SETUP_FORK_TARGET: u16 = 0x800A;
const SETUP_TARGET_PIPE: u16 = 0x800B;
const SETUP_TARGET_WAIT: u16 = 0x800C;

// Stages reported by B inside the new root.
const STAGE_PDEATHSIG: u8 = 1;
const STAGE_SETSID: u8 = 2;
const STAGE_PROC: u8 = 3;
const STAGE_CLOSE_FDS: u8 = 4;
const STAGE_CAPS: u8 = 5;
const STAGE_NNP: u8 = 6;
const STAGE_LANDLOCK: u8 = 7;
const STAGE_SECCOMP: u8 = 8;
const STAGE_CHDIR: u8 = 9;
const STAGE_EXEC: u8 = 10;

/// Options accepted by `sbx run`.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub ro: Vec<PathBuf>,
    pub rw: Vec<PathBuf>,
    pub env: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub hostname: String,
    pub command: Vec<OsString>,
    pub dangerous: bool,
    /// Explicit opt-in when the kernel cannot provide Landlock. The protection
    /// summary still reports the layer as off; this never silently degrades.
    pub allow_degraded_landlock: bool,
}

/// A failure before the target could run, or an internal failure while it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunError {
    pub code: i32,
    pub message: String,
}

impl RunError {
    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_INTERNAL,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_UNAVAILABLE,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_NOT_FOUND,
            message: message.into(),
        }
    }

    fn not_executable(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_NOT_EXECUTABLE,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RunError {}

/// A fully validated sandbox plan. Creating one does not change the host; the
/// caller decides whether to print the summary and call [`Prepared::execute`].
pub struct Prepared {
    spec: SandboxSpec,
    temp: TempRoot,
}

impl Prepared {
    pub fn summary(&self) -> &ProtectionSummary {
        &self.spec.summary
    }

    /// Build the sandbox, run the target, and return the exit code `sbx` should
    /// use. `Ok(code)` includes normal exits and `128+N` for signal `N`.
    pub fn execute(self) -> Result<i32, RunError> {
        let Prepared { spec, temp } = self;
        let result = execute_spec(&spec);
        drop(temp);
        result
    }
}

/// Validate arguments, probe required mechanics, and build the immutable plan.
pub fn prepare(options: RunOptions) -> Result<Prepared, RunError> {
    if options.command.is_empty() {
        return Err(RunError::internal("no command supplied"));
    }

    let hostname = validate_hostname(&options.hostname)?;
    let grants = resolve_grants(&options)?;
    let path_value = sandbox_path(&options)?;
    let env = build_environment(&options, &path_value)?;

    let cwd_host = match &options.cwd {
        Some(path) => {
            let canonical = fs::canonicalize(path)
                .map_err(|e| RunError::internal(format!("--cwd {}: {e}", path.display())))?;
            if !canonical.is_dir() {
                return Err(RunError::internal(format!(
                    "--cwd {} is not a directory",
                    canonical.display()
                )));
            }
            if !sandbox_has_path(&canonical, &grants) {
                return Err(RunError::internal(format!(
                    "--cwd {} is not available inside the sandbox; grant it with --ro or --rw",
                    canonical.display()
                )));
            }
            Some(canonical)
        }
        None => None,
    };

    let resolved = resolve_command(&options, &grants, &path_value, cwd_host.as_deref())?;
    let cwd_sandbox = cwd_host
        .clone()
        .unwrap_or_else(|| PathBuf::from(SANDBOX_HOME));

    let proof_host = proof_host()?;

    probe_required_mechanics()?;

    let (landlock, landlock_off_reason) = configure_landlock(&options, &grants)?;
    let seccomp = sys::default_seccomp_program()
        .map_err(|e| RunError::internal(format!("could not build the seccomp profile: {e}")))?;

    let temp = TempRoot::create()?;
    let devices = available_devices();
    let steps = build_steps(
        &temp.path,
        &grants,
        &hostname,
        &devices,
        proof_host.as_deref(),
    )?;
    let ro_count = grants
        .iter()
        .filter(|grant| grant.mode == GrantMode::ReadOnly)
        .count();
    let rw_count = grants
        .iter()
        .filter(|grant| grant.mode == GrantMode::ReadWrite)
        .count();
    let device_list = if devices.is_empty() {
        "none".to_string()
    } else {
        devices
            .iter()
            .map(|name| format!("/dev/{name}"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut summary = ProtectionSummary::new(resolved.exec_path.to_string_lossy());
    summary.add(
        "user namespace",
        true,
        format!(
            "uid/gid {} mapped to itself; setgroups=deny before gid_map",
            sys::getuid()
        ),
    );
    summary.add(
        "mount namespace",
        true,
        "private propagation; tmpfs root; pivot_root (not chroot)",
    );
    summary.add(
        "pid namespace",
        true,
        "target is PID 1; fresh /proc mounted with subset=pid",
    );
    summary.add(
        "network namespace",
        true,
        "loopback only; no host interfaces or routes",
    );
    summary.add("ipc namespace", true, "separate System V/POSIX IPC");
    summary.add(
        "uts namespace",
        true,
        format!("hostname `{}`", hostname.to_string_lossy()),
    );
    summary.add(
        "capabilities",
        true,
        "bounding, permitted, effective, inheritable and ambient sets cleared",
    );
    summary.add(
        "no_new_privs",
        true,
        "setuid/file capabilities cannot elevate",
    );
    summary.add(
        "seccomp syscall filter",
        true,
        "default denylist returns EPERM; clone3 returns ENOSYS; foreign/x32 ABIs and TIOCSTI denied; clone namespace flags denied",
    );
    summary.add(
        "inherited descriptors",
        true,
        "all descriptors above stderr closed before exec",
    );
    summary.add(
        "environment",
        true,
        format!(
            "empty base plus PATH, HOME={SANDBOX_HOME}, TERM, LANG and {} allowlisted name(s)",
            env.extra_names
        ),
    );
    summary.add(
        "host filesystem",
        true,
        format!(
            "/usr read-only; {ro_count} read-only grant(s); {rw_count} read-write grant(s); private /tmp"
        ),
    );
    summary.add(
        "device access",
        true,
        format!(
            "minimal /dev binds ({device_list}); device-node binds are the documented MS_NODEV exception"
        ),
    );
    match &landlock {
        Some(config) => summary.add(
            "Landlock filesystem rules",
            true,
            format!(
                "ABI {}; {} path-beneath rule(s); handled rights {:#x}; mirrors the mount layout",
                config.abi,
                config.rules.len(),
                config.handled_access_fs
            ),
        ),
        None => summary.add(
            "Landlock filesystem rules",
            false,
            format!(
                "OFF: {}; explicitly allowed by --allow-degraded=landlock",
                landlock_off_reason
                    .as_deref()
                    .unwrap_or("not available on this kernel")
            ),
        ),
    }
    summary.add(
        "seccomp user-notify monitoring",
        false,
        "not enabled in Milestone 2 (planned for Milestone 3)",
    );
    if let Some(proof) = &proof_host {
        summary.add(
            "test-only exposed mount",
            false,
            format!(
                "{} is bind-mounted at /host without a Landlock rule (landlock-proof build)",
                proof.display()
            ),
        );
    }

    let spec = SandboxSpec {
        root_c: cstring_path(&temp.path)?,
        put_old_c: cstring_path(&temp.path.join("oldroot"))?,
        hostname,
        cwd: cstring_path(&cwd_sandbox)?,
        exec_path: cstring_path(&resolved.exec_path)?,
        argv: env.argv,
        env: env.env,
        argv_ptrs: Vec::new(),
        env_ptrs: Vec::new(),
        steps,
        summary,
        landlock,
        seccomp,
    };

    let mut spec = spec;
    spec.argv_ptrs = spec
        .argv
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    spec.env_ptrs = spec
        .env
        .iter()
        .map(|value| value.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    Ok(Prepared { spec, temp })
}

/// A host path granted inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    host: PathBuf,
    mode: GrantMode,
    is_dir: bool,
}

/// The Landlock ruleset prepared in the parent and installed in the target.
struct LandlockConfig {
    abi: c_int,
    handled_access_fs: u64,
    rules: Vec<sys::LandlockRule>,
}

/// Negotiate Landlock and build rules that mirror the mount layout.
///
/// Returns `(None, Some(reason))` only when the caller explicitly opted into
/// degraded operation with `--allow-degraded=landlock`. Every other failure is
/// a hard refusal (`124`), because silently losing this layer would contradict
/// the protection summary.
fn configure_landlock(
    options: &RunOptions,
    grants: &[Grant],
) -> Result<(Option<LandlockConfig>, Option<String>), RunError> {
    // In the test-only proof build, --allow-degraded=landlock also forces the
    // layer off. That lets one binary compare "Landlock on" with "only the
    // deliberately loose mount layer". Normal builds never disable an
    // available Landlock: the flag only permits running without it.
    #[cfg(feature = "landlock-proof")]
    if options.allow_degraded_landlock {
        return Ok((
            None,
            Some(
                "disabled by --allow-degraded=landlock in the landlock-proof test build"
                    .to_string(),
            ),
        ));
    }

    let unavailable =
        |reason: String| -> Result<(Option<LandlockConfig>, Option<String>), RunError> {
            if options.allow_degraded_landlock {
                Ok((None, Some(reason)))
            } else {
                Err(RunError::unavailable(format!(
                "Landlock is unavailable ({reason}); rerun with --allow-degraded=landlock to run without this layer"
            )))
            }
        };

    let abi = match sys::landlock_abi() {
        Ok(abi) => abi,
        Err(reason) => return unavailable(format!("ABI query failed: {reason}")),
    };
    let handled_access_fs = sys::landlock_access_for_abi(abi);
    if let Err(error) = sys::landlock_probe(handled_access_fs) {
        return unavailable(format!(
            "kernel rejected the ABI {abi} access mask ({handled_access_fs:#x}): {error}"
        ));
    }
    let rules = build_landlock_rules(handled_access_fs, grants)?;
    Ok((
        Some(LandlockConfig {
            abi,
            handled_access_fs,
            rules,
        }),
        None,
    ))
}

fn build_landlock_rules(
    handled_access_fs: u64,
    grants: &[Grant],
) -> Result<Vec<sys::LandlockRule>, RunError> {
    // File rights are valid on a rule whose path is a regular file. The
    // directory-only rights below would make `landlock_add_rule` fail with
    // EINVAL on a file, so a file grant gets only the file subset.
    let file_rights = sys::LANDLOCK_ACCESS_FS_EXECUTE
        | sys::LANDLOCK_ACCESS_FS_WRITE_FILE
        | sys::LANDLOCK_ACCESS_FS_READ_FILE
        | sys::LANDLOCK_ACCESS_FS_TRUNCATE;
    let read_only_directory = sys::LANDLOCK_ACCESS_FS_EXECUTE
        | sys::LANDLOCK_ACCESS_FS_READ_FILE
        | sys::LANDLOCK_ACCESS_FS_READ_DIR;

    let mut rules = Vec::new();
    let mut add = |path: &Path, access: u64| -> Result<(), RunError> {
        let access = access & handled_access_fs;
        if access == 0 {
            return Ok(());
        }
        rules.push(sys::LandlockRule {
            path: cstring_path(path)?,
            access,
        });
        Ok(())
    };

    // Allow listing the sandbox root itself. This grants READ_DIR on the whole
    // hierarchy, but no file-content right; every file still needs a rule.
    add(Path::new("/"), sys::LANDLOCK_ACCESS_FS_READ_DIR)?;
    add(Path::new("/usr"), read_only_directory)?;
    for path in ["/etc", "/run", "/var", "/home"] {
        add(
            Path::new(path),
            sys::LANDLOCK_ACCESS_FS_READ_FILE | sys::LANDLOCK_ACCESS_FS_READ_DIR,
        )?;
    }
    add(
        Path::new("/proc"),
        sys::LANDLOCK_ACCESS_FS_READ_FILE | sys::LANDLOCK_ACCESS_FS_READ_DIR,
    )?;
    add(
        Path::new("/dev"),
        sys::LANDLOCK_ACCESS_FS_READ_FILE
            | sys::LANDLOCK_ACCESS_FS_WRITE_FILE
            | sys::LANDLOCK_ACCESS_FS_READ_DIR,
    )?;

    // These trees are private tmpfs mounts (or the sandbox home), so they get
    // the full handled set, including REFER and TRUNCATE when the ABI has them.
    for path in ["/tmp", "/var/tmp", SANDBOX_HOME] {
        add(Path::new(path), handled_access_fs)?;
    }

    // Every grant mirrors its mount: read-only grants cannot write, while
    // read-write grants get the same rights the mount layer allows.
    for grant in grants {
        let access = if grant.mode == GrantMode::ReadWrite {
            if grant.is_dir {
                handled_access_fs
            } else {
                file_rights
            }
        } else if grant.is_dir {
            read_only_directory
        } else {
            sys::LANDLOCK_ACCESS_FS_EXECUTE | sys::LANDLOCK_ACCESS_FS_READ_FILE
        };
        add(&grant.host, access)?;
    }

    Ok(rules)
}

fn resolve_grants(options: &RunOptions) -> Result<Vec<Grant>, RunError> {
    let mut grants: Vec<Grant> = Vec::new();
    for (paths, mode) in [
        (&options.ro, GrantMode::ReadOnly),
        (&options.rw, GrantMode::ReadWrite),
    ] {
        for path in paths {
            let canonical = fs::canonicalize(path)
                .map_err(|e| RunError::internal(format!("--ro/--rw {}: {e}", path.display())))?;
            match PathPolicy::check(&canonical, mode) {
                PolicyDecision::Allow => {}
                PolicyDecision::RequiresDangerous { reason } => {
                    if !options.dangerous {
                        return Err(RunError::internal(format!(
                            "refusing to expose {}: {reason}; add --i-know-this-is-dangerous to override",
                            canonical.display()
                        )));
                    }
                }
                PolicyDecision::Deny { reason } => {
                    return Err(RunError::internal(format!(
                        "refusing to expose {}: {reason}",
                        canonical.display()
                    )));
                }
            }
            if is_under(&canonical, Path::new("/proc")) {
                return Err(RunError::internal(
                    "grants under /proc are not supported; the sandbox mounts a fresh procfs there"
                        .to_string(),
                ));
            }
            let metadata = fs::metadata(&canonical)
                .map_err(|e| RunError::internal(format!("{}: {e}", canonical.display())))?;
            if grants.iter().any(|grant| grant.host == canonical) {
                return Err(RunError::internal(format!(
                    "{} was granted more than once",
                    canonical.display()
                )));
            }
            grants.push(Grant {
                host: canonical,
                mode,
                is_dir: metadata.is_dir(),
            });
        }
    }

    // Mount parents before children so a child mount point exists inside the
    // already-cloned subtree.
    grants.sort_by_key(|grant| grant.host.components().count());
    Ok(grants)
}

fn sandbox_path(options: &RunOptions) -> Result<String, RunError> {
    if options.env.iter().any(|name| name == "PATH") {
        if let Ok(host) = std::env::var("PATH") {
            return Ok(host);
        }
    }
    Ok(DEFAULT_PATH.to_string())
}

struct Environment {
    argv: Vec<CString>,
    env: Vec<CString>,
    extra_names: usize,
}

fn build_environment(options: &RunOptions, path_value: &str) -> Result<Environment, RunError> {
    let mut entries: Vec<(OsString, OsString)> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    let push = |entries: &mut Vec<(OsString, OsString)>,
                seen: &mut std::collections::BTreeSet<String>,
                name: &str,
                value: OsString| {
        if seen.insert(name.to_string()) {
            entries.push((OsString::from(name), value));
        }
    };

    // Defaults first, so `--env PATH` can still override PATH.
    push(&mut entries, &mut seen, "PATH", OsString::from(path_value));
    push(
        &mut entries,
        &mut seen,
        "HOME",
        OsString::from(SANDBOX_HOME),
    );
    if let Some(term) = std::env::var_os("TERM") {
        push(&mut entries, &mut seen, "TERM", term);
    }
    if let Some(lang) = std::env::var_os("LANG") {
        push(&mut entries, &mut seen, "LANG", lang);
    }

    let mut extra_names = 0usize;
    for name in &options.env {
        if name == "HOME" {
            return Err(RunError::internal(
                "--env HOME is reserved: the sandbox home is always /home/sbx",
            ));
        }
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(RunError::internal(format!("invalid --env name `{name}`")));
        }
        let Some(value) = std::env::var_os(name) else {
            continue;
        };
        if seen.contains(name) {
            // PATH/TERM/LANG: the allowlisted host value replaces the default.
            if let Some(slot) = entries.iter_mut().find(|(key, _)| key == OsStr::new(name)) {
                slot.1 = value;
            }
        } else {
            seen.insert(name.clone());
            extra_names += 1;
            entries.push((OsString::from(name), value));
        }
    }

    let mut env = Vec::with_capacity(entries.len());
    for (name, value) in entries {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_bytes());
        env.push(CString::new(bytes).map_err(|_| {
            RunError::internal(format!(
                "environment variable {} contains a NUL byte",
                name.to_string_lossy()
            ))
        })?);
    }

    let mut argv = Vec::with_capacity(options.command.len());
    for (index, value) in options.command.iter().enumerate() {
        let cstring = CString::new(value.as_bytes())
            .map_err(|_| RunError::internal(format!("argument {index} contains a NUL byte")))?;
        argv.push(cstring);
    }

    Ok(Environment {
        argv,
        env,
        extra_names,
    })
}

fn validate_hostname(name: &str) -> Result<CString, RunError> {
    if name.is_empty() || name.len() > 64 {
        return Err(RunError::internal(
            "--hostname must be between 1 and 64 bytes",
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    {
        return Err(RunError::internal(
            "--hostname may only contain ASCII letters, digits, '-', '.' and '_'",
        ));
    }
    CString::new(name).map_err(|_| RunError::internal("--hostname contains a NUL byte"))
}

fn resolve_command(
    options: &RunOptions,
    grants: &[Grant],
    path_value: &str,
    cwd_host: Option<&Path>,
) -> Result<ResolvedCommand, RunError> {
    let program = &options.command[0];
    if program.is_empty() {
        return Err(RunError::not_found("empty command name"));
    }

    if program.as_bytes().contains(&b'/') {
        let candidate = if Path::new(program).is_absolute() {
            PathBuf::from(program)
        } else {
            let Some(cwd) = cwd_host else {
                return Err(RunError::not_executable(
                    "relative command paths require --cwd so the host path can be resolved",
                ));
            };
            cwd.join(program)
        };
        let metadata = match fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(RunError::not_found(format!(
                    "command not found: {}",
                    candidate.display()
                )))
            }
            Err(e) => {
                return Err(RunError::internal(format!(
                    "cannot inspect {}: {e}",
                    candidate.display()
                )))
            }
        };
        if !metadata.is_file() {
            return Err(RunError::not_executable(format!(
                "{} is not a regular file",
                candidate.display()
            )));
        }
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(RunError::not_executable(format!(
                "{} is not executable",
                candidate.display()
            )));
        }
        let canonical = fs::canonicalize(&candidate).map_err(|e| {
            RunError::internal(format!("cannot resolve {}: {e}", candidate.display()))
        })?;
        if !binary_reachable(&canonical, grants) {
            return Err(RunError::not_executable(format!(
                "{} resolves to {}, which is not mounted in the sandbox; grant it with --ro or --rw",
                candidate.display(),
                canonical.display()
            )));
        }
        return Ok(ResolvedCommand {
            exec_path: PathBuf::from(program),
            _argv0: program.clone(),
        });
    }

    for directory in path_value.split(':') {
        if directory.is_empty() {
            // POSIX treats an empty component as the current directory. An
            // implicit cwd search is exactly the kind of surprise a sandbox
            // should not add, so it is skipped.
            continue;
        }
        let directory = Path::new(directory);
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(program);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            continue;
        }
        let canonical = fs::canonicalize(&candidate).map_err(|e| {
            RunError::internal(format!("cannot resolve {}: {e}", candidate.display()))
        })?;
        if !binary_reachable(&canonical, grants) {
            return Err(RunError::not_executable(format!(
                "{} resolves to {}, which is not mounted in the sandbox; grant it with --ro or --rw",
                candidate.display(),
                canonical.display()
            )));
        }
        return Ok(ResolvedCommand {
            exec_path: candidate,
            _argv0: program.clone(),
        });
    }

    Err(RunError::not_found(format!(
        "command not found: {}",
        program.to_string_lossy()
    )))
}

struct ResolvedCommand {
    exec_path: PathBuf,
    _argv0: OsString,
}

fn binary_reachable(canonical: &Path, grants: &[Grant]) -> bool {
    is_under(canonical, Path::new("/usr"))
        || grants.iter().any(|grant| is_under(canonical, &grant.host))
}

fn sandbox_has_path(path: &Path, grants: &[Grant]) -> bool {
    // Only claim paths that this sandbox actually creates. In particular a
    // host path under `/tmp` or `/etc` is not the sandbox's private tmpfs or
    // synthesized `/etc`, so it must be granted explicitly.
    if path == Path::new("/") || is_under(path, Path::new("/usr")) {
        return true;
    }
    if [
        "/etc",
        "/proc",
        "/dev",
        "/tmp",
        "/run",
        "/var",
        "/var/tmp",
        SANDBOX_HOME,
    ]
    .iter()
    .any(|candidate| path == Path::new(candidate))
    {
        return true;
    }
    if is_under(path, Path::new(SANDBOX_HOME)) {
        return true;
    }
    grants.iter().any(|grant| is_under(path, &grant.host))
}

fn is_under(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn proof_host() -> Result<Option<PathBuf>, RunError> {
    #[cfg(feature = "landlock-proof")]
    {
        let Some(raw) = std::env::var_os("SBX_PROOF_HOST") else {
            return Ok(None);
        };
        let path = fs::canonicalize(&raw).map_err(|error| {
            RunError::internal(format!(
                "SBX_PROOF_HOST {} cannot be resolved: {error}",
                PathBuf::from(&raw).display()
            ))
        })?;
        if !path.is_dir() {
            return Err(RunError::internal(format!(
                "SBX_PROOF_HOST {} is not a directory",
                path.display()
            )));
        }
        Ok(Some(path))
    }
    #[cfg(not(feature = "landlock-proof"))]
    {
        Ok(None)
    }
}

fn probe_required_mechanics() -> Result<(), RunError> {
    if let Err(e) = sys::probe_userns(
        sys::CLONE_NEWNS
            | sys::CLONE_NEWUTS
            | sys::CLONE_NEWIPC
            | sys::CLONE_NEWNET
            | sys::CLONE_NEWPID,
        true,
    ) {
        return Err(RunError::unavailable(format!(
            "user/mount/pid/net/ipc/uts namespaces are unavailable: {e}"
        )));
    }
    if let Err(e) = sys::probe_no_new_privs() {
        return Err(RunError::unavailable(format!(
            "PR_SET_NO_NEW_PRIVS is unavailable: {e}"
        )));
    }
    if let Err(e) = sys::probe_seccomp_filter() {
        return Err(RunError::unavailable(format!(
            "seccomp filters are unavailable, so the namespace guard cannot be installed: {e}"
        )));
    }
    Ok(())
}

struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    fn create() -> Result<Self, RunError> {
        let base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        for attempt in 0..100u32 {
            let path = base.join(format!("sbx-root-{}-{nanos}-{attempt}", std::process::id()));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(RunError::internal(format!(
                        "cannot create sandbox root {}: {e}",
                        path.display()
                    )))
                }
            }
        }
        Err(RunError::internal(
            "cannot create a unique sandbox root directory",
        ))
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        // The tmpfs was mounted only inside A's mount namespace. Once the
        // namespace is gone this is an empty host directory.
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Debug)]
enum Step {
    Mkdir {
        path: CString,
        mode: u32,
    },
    CreateFile {
        path: CString,
        mode: u32,
        contents: Vec<u8>,
    },
    Symlink {
        target: CString,
        link: CString,
    },
    MountTmpfs {
        target: CString,
        options: CString,
        flags: c_ulong,
    },
    Bind {
        source: CString,
        target: CString,
        recursive: bool,
        readonly: bool,
        allow_devices: bool,
    },
}

impl Step {
    fn label(&self) -> String {
        match self {
            Step::Mkdir { path, .. } => format!("mkdir {}", path.to_string_lossy()),
            Step::CreateFile { path, .. } => format!("create {}", path.to_string_lossy()),
            Step::Symlink { link, .. } => format!("symlink {}", link.to_string_lossy()),
            Step::MountTmpfs { target, .. } => format!("mount tmpfs {}", target.to_string_lossy()),
            Step::Bind { source, target, .. } => format!(
                "bind {} -> {}",
                source.to_string_lossy(),
                target.to_string_lossy()
            ),
        }
    }
}

fn available_devices() -> Vec<&'static str> {
    ["null", "zero", "full", "random", "urandom", "tty"]
        .into_iter()
        .filter(|name| Path::new("/dev").join(name).exists())
        .collect()
}

fn build_steps(
    root: &Path,
    grants: &[Grant],
    hostname: &CStr,
    devices: &[&'static str],
    proof_host: Option<&Path>,
) -> Result<Vec<Step>, RunError> {
    let mut steps = Vec::new();
    let mkdir = |steps: &mut Vec<Step>, inside: &str, mode: u32| -> Result<(), RunError> {
        steps.push(Step::Mkdir {
            path: cstring_path(&under_root(root, inside))?,
            mode,
        });
        Ok(())
    };
    let symlink = |steps: &mut Vec<Step>, inside: &str, target: &str| -> Result<(), RunError> {
        steps.push(Step::Symlink {
            target: CString::new(target).map_err(|_| RunError::internal("symlink target NUL"))?,
            link: cstring_path(&under_root(root, inside))?,
        });
        Ok(())
    };

    steps.push(Step::MountTmpfs {
        target: cstring_path(root)?,
        options: CString::from(c"mode=0755,size=512m"),
        flags: sys::MS_NOSUID | sys::MS_NODEV,
    });

    for directory in [
        "usr", "etc", "home", "tmp", "proc", "dev", "run", "var", "var/tmp", "oldroot",
    ] {
        mkdir(&mut steps, directory, 0o755)?;
    }
    mkdir(&mut steps, "home/sbx", 0o700)?;

    symlink(&mut steps, "bin", "usr/bin")?;
    symlink(&mut steps, "sbin", "usr/bin")?;
    symlink(&mut steps, "lib", "usr/lib")?;
    symlink(&mut steps, "lib64", "usr/lib")?;
    if Path::new("/usr/lib32").is_dir() {
        symlink(&mut steps, "lib32", "usr/lib32")?;
    }

    steps.push(Step::Bind {
        source: CString::from(c"/usr"),
        target: cstring_path(&under_root(root, "usr"))?,
        recursive: true,
        readonly: true,
        allow_devices: false,
    });

    // `/dev` is a separate tmpfs. The tmpfs itself is nosuid; it is not nodev,
    // because the target needs the host's null/zero/random device semantics.
    // The individual device bind mounts are the documented exception to the
    // otherwise universal MS_NODEV rule. See docs/decisions/002.
    steps.push(Step::MountTmpfs {
        target: cstring_path(&under_root(root, "dev"))?,
        options: CString::from(c"mode=0755,size=16m"),
        flags: sys::MS_NOSUID,
    });
    for name in devices {
        let host = Path::new("/dev").join(name);
        steps.push(Step::CreateFile {
            path: cstring_path(&under_root(root, &format!("dev/{name}")))?,
            mode: 0o666,
            contents: Vec::new(),
        });
        steps.push(Step::Bind {
            source: cstring_path(&host)?,
            target: cstring_path(&under_root(root, &format!("dev/{name}")))?,
            recursive: false,
            readonly: false,
            allow_devices: true,
        });
    }
    for (link, target) in [
        ("dev/fd", "/proc/self/fd"),
        ("dev/stdin", "/proc/self/fd/0"),
        ("dev/stdout", "/proc/self/fd/1"),
        ("dev/stderr", "/proc/self/fd/2"),
    ] {
        symlink(&mut steps, link, target)?;
    }

    steps.push(Step::MountTmpfs {
        target: cstring_path(&under_root(root, "tmp"))?,
        options: CString::from(c"mode=1777,size=256m"),
        flags: sys::MS_NOSUID | sys::MS_NODEV,
    });

    let uid = sys::getuid();
    let gid = sys::getgid();
    let passwd = format!(
        "root:x:0:0:root:/root:/bin/sh\nsbx:x:{uid}:{gid}:sbx sandbox:{SANDBOX_HOME}:/bin/sh\n"
    );
    let group = format!("root:x:0:\nsbx:x:{gid}:\n");
    let hosts = format!(
        "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 {}\n",
        hostname.to_string_lossy()
    );
    let files: [(&str, &[u8], u32); 6] = [
        ("passwd", passwd.as_bytes(), 0o644),
        ("group", group.as_bytes(), 0o644),
        ("hostname", hostname.to_bytes(), 0o644),
        ("hosts", hosts.as_bytes(), 0o644),
        (
            "resolv.conf",
            b"# network access is not available in this sandbox\n",
            0o644,
        ),
        (
            "nsswitch.conf",
            b"passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n",
            0o644,
        ),
    ];
    for (name, contents, mode) in files {
        steps.push(Step::CreateFile {
            path: cstring_path(&under_root(root, &format!("etc/{name}")))?,
            mode,
            contents: contents.to_vec(),
        });
    }

    for grant in grants {
        add_grant_steps(&mut steps, root, grant)?;
    }

    if let Some(host) = proof_host {
        let target = under_root(root, "host");
        steps.push(Step::Mkdir {
            path: cstring_path(&target)?,
            mode: 0o755,
        });
        steps.push(Step::Bind {
            source: cstring_path(host)?,
            target: cstring_path(&target)?,
            recursive: true,
            readonly: true,
            allow_devices: false,
        });
    }

    Ok(steps)
}

fn add_grant_steps(steps: &mut Vec<Step>, root: &Path, grant: &Grant) -> Result<(), RunError> {
    let mut target = root.to_path_buf();
    let components: Vec<&OsStr> = grant
        .host
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        return Err(RunError::internal("grant has no path components"));
    }

    for (index, component) in components.iter().enumerate() {
        target.push(component);
        let last = index + 1 == components.len();
        if last && !grant.is_dir {
            steps.push(Step::CreateFile {
                path: cstring_path(&target)?,
                mode: 0o000,
                contents: Vec::new(),
            });
        } else {
            steps.push(Step::Mkdir {
                path: cstring_path(&target)?,
                mode: 0o755,
            });
        }
    }

    steps.push(Step::Bind {
        source: cstring_path(&grant.host)?,
        target: cstring_path(&target)?,
        recursive: grant.is_dir,
        readonly: grant.mode == GrantMode::ReadOnly,
        allow_devices: false,
    });
    Ok(())
}

fn under_root(root: &Path, inside: &str) -> PathBuf {
    root.join(inside.trim_start_matches('/'))
}

fn cstring_path(path: &Path) -> Result<CString, RunError> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| RunError::internal(format!("path {} contains a NUL byte", path.display())))
}

struct SandboxSpec {
    root_c: CString,
    put_old_c: CString,
    hostname: CString,
    cwd: CString,
    exec_path: CString,
    argv: Vec<CString>,
    env: Vec<CString>,
    argv_ptrs: Vec<*const c_char>,
    env_ptrs: Vec<*const c_char>,
    steps: Vec<Step>,
    summary: ProtectionSummary,
    landlock: Option<LandlockConfig>,
    seccomp: sys::SeccompProgram,
}

fn execute_spec(spec: &SandboxSpec) -> Result<i32, RunError> {
    let (status_r, status_w) =
        sys::pipe_cloexec().map_err(|e| RunError::internal(format!("status pipe: {e}")))?;
    let (ready_r, ready_w) =
        sys::pipe_cloexec().map_err(|e| RunError::internal(format!("ready pipe: {e}")))?;
    let (ack_r, ack_w) =
        sys::pipe_cloexec().map_err(|e| RunError::internal(format!("ack pipe: {e}")))?;

    let status_r_fd = status_r.as_raw_fd();
    let status_w_fd = status_w.as_raw_fd();
    let ready_r_fd = ready_r.as_raw_fd();
    let ready_w_fd = ready_w.as_raw_fd();
    let ack_r_fd = ack_r.as_raw_fd();
    let ack_w_fd = ack_w.as_raw_fd();

    // P-side ends become Files so the parent can use ordinary I/O. The child
    // ends stay as OwnedFds and are closed in P after the fork.
    let mut status_reader = File::from(status_r);
    let mut ready_reader = File::from(ready_r);
    let mut ack_writer = File::from(ack_w);

    let pid = match sys::fork() {
        Ok(sys::ForkResult::Parent { pid }) => pid,
        Ok(sys::ForkResult::Child) => {
            // A: close the parent's ends; the three child ends are the raw fds
            // captured above. This process never returns.
            sys::close_fd(status_r_fd);
            sys::close_fd(ready_r_fd);
            sys::close_fd(ack_w_fd);
            setup_child(spec, ready_w_fd, ack_r_fd, status_w_fd)
        }
        Err(e) => return Err(RunError::internal(format!("fork: {e}"))),
    };
    drop(status_w);
    drop(ready_w);
    drop(ack_r);

    let uid = sys::getuid();
    let gid = sys::getgid();

    let mut ready = [0u8; 1];
    let ready_ok = read_exact_or_eof(&mut ready_reader, &mut ready).unwrap_or(false);
    if !ready_ok {
        // A reports the actual failure over the status pipe, then exits.
        let _ = sys::waitpid_status(pid);
        let frame = collect_frames(&mut status_reader)?;
        return Err(frame_error(spec, frame));
    }

    if let Err(e) = sys::write_user_maps(pid, uid, gid) {
        // Closing the ack pipe unblocks A's handshake read.
        drop(ack_writer);
        let _ = sys::waitpid_status(pid);
        return Err(RunError::unavailable(format!(
            "cannot write uid/gid maps: {e}"
        )));
    }
    if let Err(e) = ack_writer.write_all(&[1u8]) {
        drop(ack_writer);
        let _ = sys::waitpid_status(pid);
        return Err(RunError::internal(format!(
            "cannot acknowledge uid/gid maps: {e}"
        )));
    }
    drop(ack_writer);

    let frames = collect_frames(&mut status_reader)?;
    let a_status = sys::waitpid_status(pid);

    match frames {
        FrameResult::Target(raw) => match sys::decode_wait_status(raw) {
            Some(sys::WaitStatus::Exited(code)) => Ok(code),
            Some(sys::WaitStatus::Signaled(signal)) => Ok(128 + signal),
            None => Err(RunError::internal(
                "sandbox supervisor reported an undecodable target status",
            )),
        },
        FrameResult::ExecError { stage, errno } => Err(exec_failure(stage, errno)),
        FrameResult::SetupError { code, errno } => Err(setup_failure(spec, code, errno)),
        FrameResult::SupervisorError(errno) => Err(RunError::internal(format!(
            "sandbox supervisor failed while waiting for the target: {}",
            io::Error::from_raw_os_error(errno)
        ))),
        FrameResult::None => match a_status {
            Ok(sys::WaitStatus::Signaled(signal)) => Err(RunError::internal(format!(
                "sandbox supervisor was killed by signal {signal} before reporting the target"
            ))),
            Ok(sys::WaitStatus::Exited(code)) => Err(RunError::internal(format!(
                "sandbox supervisor exited with code {code} before reporting the target"
            ))),
            Err(e) => Err(RunError::internal(format!(
                "cannot wait for sandbox supervisor: {e}"
            ))),
        },
    }
}

fn frame_error(spec: &SandboxSpec, frame: FrameResult) -> RunError {
    match frame {
        FrameResult::SetupError { code, errno } => setup_failure(spec, code, errno),
        FrameResult::ExecError { stage, errno } => exec_failure(stage, errno),
        FrameResult::SupervisorError(errno) => RunError::internal(format!(
            "sandbox supervisor failed: {}",
            io::Error::from_raw_os_error(errno)
        )),
        FrameResult::Target(_) => RunError::internal(
            "sandbox supervisor reported a target exit before the handshake completed",
        ),
        FrameResult::None => {
            RunError::internal("sandbox supervisor exited before creating the user namespace")
        }
    }
}

fn read_exact_or_eof(file: &mut File, buffer: &mut [u8]) -> io::Result<bool> {
    let mut offset = 0;
    while offset < buffer.len() {
        match file.read(&mut buffer[offset..]) {
            Ok(0) => return Ok(false),
            Ok(read) => offset += read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

enum FrameResult {
    SetupError { code: u16, errno: i32 },
    ExecError { stage: u8, errno: i32 },
    Target(c_int),
    SupervisorError(i32),
    None,
}

fn collect_frames(reader: &mut File) -> Result<FrameResult, RunError> {
    let mut result = FrameResult::None;
    let mut kind = [0u8; 1];
    loop {
        let got = read_exact_or_eof(reader, &mut kind)
            .map_err(|e| RunError::internal(format!("reading supervisor status: {e}")))?;
        if !got {
            break;
        }
        match kind[0] {
            FRAME_SETUP_ERROR => {
                let mut payload = [0u8; 6];
                read_required(reader, &mut payload)?;
                let code = u16::from_le_bytes([payload[0], payload[1]]);
                let errno = i32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]);
                result = FrameResult::SetupError { code, errno };
            }
            FRAME_EXEC_ERROR => {
                let mut payload = [0u8; 5];
                read_required(reader, &mut payload)?;
                let errno = i32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                result = FrameResult::ExecError {
                    stage: payload[0],
                    errno,
                };
            }
            FRAME_TARGET_EXIT => {
                let mut payload = [0u8; 4];
                read_required(reader, &mut payload)?;
                result = FrameResult::Target(i32::from_le_bytes(payload));
            }
            FRAME_SUPERVISOR_ERROR => {
                let mut payload = [0u8; 4];
                read_required(reader, &mut payload)?;
                result = FrameResult::SupervisorError(i32::from_le_bytes(payload));
            }
            other => {
                return Err(RunError::internal(format!(
                    "sandbox supervisor sent unknown status frame {other}"
                )))
            }
        }
    }
    Ok(result)
}

fn read_required(reader: &mut File, buffer: &mut [u8]) -> Result<(), RunError> {
    match read_exact_or_eof(reader, buffer) {
        Ok(true) => Ok(()),
        Ok(false) => Err(RunError::internal(
            "sandbox supervisor sent a truncated status frame",
        )),
        Err(e) => Err(RunError::internal(format!(
            "reading supervisor status: {e}"
        ))),
    }
}

fn exec_failure(stage: u8, errno: i32) -> RunError {
    let error = io::Error::from_raw_os_error(errno);
    match stage {
        STAGE_EXEC => match errno {
            2 | 20 => RunError::not_found(format!("cannot execute target: {error}")),
            1 | 13 => RunError::not_executable(format!("cannot execute target: {error}")),
            _ => RunError::internal(format!("execve failed: {error}")),
        },
        STAGE_PROC | STAGE_CLOSE_FDS | STAGE_CAPS | STAGE_NNP | STAGE_LANDLOCK | STAGE_SECCOMP
        | STAGE_PDEATHSIG => RunError::unavailable(format!(
            "required protection failed in the target at stage {}: {error}",
            stage_name(stage)
        )),
        _ => RunError::internal(format!(
            "target setup failed at stage {}: {error}",
            stage_name(stage)
        )),
    }
}

fn stage_name(stage: u8) -> &'static str {
    match stage {
        STAGE_PDEATHSIG => "PR_SET_PDEATHSIG",
        STAGE_SETSID => "setsid",
        STAGE_PROC => "mount /proc",
        STAGE_CLOSE_FDS => "close inherited descriptors",
        STAGE_CAPS => "drop capabilities",
        STAGE_NNP => "PR_SET_NO_NEW_PRIVS",
        STAGE_LANDLOCK => "apply Landlock ruleset",
        STAGE_SECCOMP => "install seccomp filter",
        STAGE_CHDIR => "chdir",
        STAGE_EXEC => "execve",
        _ => "unknown stage",
    }
}

fn setup_failure(spec: &SandboxSpec, code: u16, errno: i32) -> RunError {
    let error = io::Error::from_raw_os_error(errno);
    let label = match code {
        SETUP_PDEATHSIG => "PR_SET_PDEATHSIG".to_string(),
        SETUP_USERNS => "unshare(CLONE_NEWUSER)".to_string(),
        SETUP_NAMESPACES => "unshare(mount/uts/ipc/net)".to_string(),
        SETUP_PRIVATE_MOUNTS => "make mounts private".to_string(),
        SETUP_HOSTNAME => "sethostname".to_string(),
        SETUP_LOOPBACK => "bring up loopback".to_string(),
        SETUP_PIVOT => "pivot_root".to_string(),
        SETUP_OLDROOT => "detach old root".to_string(),
        SETUP_UNSHARE_PID => "unshare(CLONE_NEWPID)".to_string(),
        SETUP_FORK_TARGET => "fork target".to_string(),
        SETUP_TARGET_PIPE => "create target error pipe".to_string(),
        SETUP_TARGET_WAIT => "wait for target".to_string(),
        step if step > 0 => spec
            .steps
            .get((step - 1) as usize)
            .map(Step::label)
            .unwrap_or_else(|| format!("unknown step {step}")),
        _ => "unknown setup stage".to_string(),
    };
    let protection_related = matches!(
        errno,
        1 | 13 | 38 | 22 // EPERM, EACCES, ENOSYS, EINVAL
    ) || matches!(
        code,
        SETUP_USERNS
            | SETUP_NAMESPACES
            | SETUP_PRIVATE_MOUNTS
            | SETUP_PIVOT
            | SETUP_UNSHARE_PID
            | SETUP_PDEATHSIG
    );
    if protection_related {
        RunError::unavailable(format!(
            "required protection unavailable while setting up `{label}`: {error}"
        ))
    } else {
        RunError::internal(format!("sandbox setup failed at `{label}`: {error}"))
    }
}

// ---------------------------------------------------------------------------
// A: supervisor in the new namespaces
// ---------------------------------------------------------------------------

fn setup_child(spec: &SandboxSpec, ready_w: c_int, ack_r: c_int, status_w: c_int) -> ! {
    // The supervisor is still a forked process. Everything below uses only the
    // fixed buffers declared here or data prepared before the fork.
    if let Err(e) = sys::set_pdeathsig(sys::SIGKILL) {
        setup_fail(status_w, SETUP_PDEATHSIG, errno_of(e));
    }
    if let Err(raw) = sys::enter_user_namespace(ready_w, ack_r) {
        setup_fail(status_w, SETUP_USERNS, raw);
    }
    sys::close_fd(ready_w);
    sys::close_fd(ack_r);

    if let Err(e) =
        sys::unshare(sys::CLONE_NEWNS | sys::CLONE_NEWUTS | sys::CLONE_NEWIPC | sys::CLONE_NEWNET)
    {
        setup_fail(status_w, SETUP_NAMESPACES, errno_of(e));
    }
    if let Err(e) = sys::make_mounts_private() {
        setup_fail(status_w, SETUP_PRIVATE_MOUNTS, errno_of(e));
    }
    if let Err(e) = sys::sethostname(&spec.hostname) {
        setup_fail(status_w, SETUP_HOSTNAME, errno_of(e));
    }
    if let Err(e) = sys::bring_up_loopback() {
        setup_fail(status_w, SETUP_LOOPBACK, errno_of(e));
    }

    for (index, step) in spec.steps.iter().enumerate() {
        if let Err(errno) = run_step(step) {
            setup_fail(status_w, (index as u16) + 1, errno);
        }
    }

    if let Err(e) = sys::pivot_root(&spec.root_c, &spec.put_old_c) {
        setup_fail(status_w, SETUP_PIVOT, errno_of(e));
    }
    if let Err(e) = sys::chdir(c"/") {
        setup_fail(status_w, SETUP_PIVOT, errno_of(e));
    }
    if let Err(e) = sys::umount2(c"/oldroot", sys::MNT_DETACH) {
        setup_fail(status_w, SETUP_OLDROOT, errno_of(e));
    }
    let _ = sys::rmdir(c"/oldroot");

    if let Err(e) = sys::unshare(sys::CLONE_NEWPID) {
        setup_fail(status_w, SETUP_UNSHARE_PID, errno_of(e));
    }

    let (err_r, err_w) = match sys::pipe_cloexec() {
        Ok(pair) => pair,
        Err(e) => setup_fail(status_w, SETUP_TARGET_PIPE, errno_of(e)),
    };
    let err_r_fd = sys::raw_fd(&err_r);
    let err_w_fd = sys::raw_fd(&err_w);

    let target = match sys::fork() {
        Ok(sys::ForkResult::Parent { pid }) => pid,
        Ok(sys::ForkResult::Child) => {
            sys::close_fd(err_r_fd);
            target_child(spec, err_w_fd)
        }
        Err(e) => setup_fail(status_w, SETUP_FORK_TARGET, errno_of(e)),
    };

    sys::close_fd(err_w_fd);
    let raw = match sys::waitpid_raw(target) {
        Ok(raw) => raw,
        Err(errno) => setup_fail(status_w, SETUP_TARGET_WAIT, errno),
    };

    let mut report = [0u8; 5];
    if sys::read_fd(err_r_fd, &mut report) {
        let errno = i32::from_le_bytes([report[1], report[2], report[3], report[4]]);
        report_exec_failure(status_w, report[0], errno);
    }

    report_target_exit(status_w, raw)
}

fn run_step(step: &Step) -> Result<(), i32> {
    match step {
        Step::Mkdir { path, mode } => match sys::mkdir(path, *mode) {
            Ok(()) => Ok(()),
            Err(e) if errno_of_ref(&e) == EEXIST => Ok(()),
            Err(e) => Err(errno_of_ref(&e)),
        },
        Step::CreateFile {
            path,
            mode,
            contents,
        } => match sys::create_file(path, *mode, contents) {
            Ok(()) => Ok(()),
            Err(e) if errno_of_ref(&e) == EEXIST => Ok(()),
            Err(e) => Err(errno_of_ref(&e)),
        },
        Step::Symlink { target, link } => match sys::symlink(target, link) {
            Ok(()) => Ok(()),
            Err(e) if errno_of_ref(&e) == EEXIST => Ok(()),
            Err(e) => Err(errno_of_ref(&e)),
        },
        Step::MountTmpfs {
            target,
            options,
            flags,
        } => sys::mount_tmpfs(target, options, *flags).map_err(|e| errno_of_ref(&e)),
        Step::Bind {
            source,
            target,
            recursive,
            readonly,
            allow_devices,
        } => sys::mount_bind(source, target, *recursive, *readonly, *allow_devices)
            .map_err(|e| errno_of_ref(&e)),
    }
}

fn errno_of(error: io::Error) -> i32 {
    errno_of_ref(&error)
}

fn errno_of_ref(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(EIO)
}

fn setup_fail(status_fd: c_int, code: u16, errno: i32) -> ! {
    let mut frame = [0u8; 7];
    frame[0] = FRAME_SETUP_ERROR;
    frame[1..3].copy_from_slice(&code.to_le_bytes());
    frame[3..7].copy_from_slice(&errno.to_le_bytes());
    let _ = sys::write_fd(status_fd, &frame);
    sys::exit_now(70)
}

fn report_exec_failure(status_fd: c_int, stage: u8, errno: i32) -> ! {
    let mut frame = [0u8; 6];
    frame[0] = FRAME_EXEC_ERROR;
    frame[1] = stage;
    frame[2..6].copy_from_slice(&errno.to_le_bytes());
    let _ = sys::write_fd(status_fd, &frame);
    sys::exit_now(0)
}

fn report_target_exit(status_fd: c_int, raw: c_int) -> ! {
    let mut frame = [0u8; 5];
    frame[0] = FRAME_TARGET_EXIT;
    frame[1..5].copy_from_slice(&raw.to_le_bytes());
    let _ = sys::write_fd(status_fd, &frame);
    sys::exit_now(0)
}

// ---------------------------------------------------------------------------
// B: PID 1 in the new PID namespace, then the target
// ---------------------------------------------------------------------------

fn target_child(spec: &SandboxSpec, err_w: c_int) -> ! {
    if let Err(e) = sys::set_pdeathsig(sys::SIGKILL) {
        target_fail(err_w, STAGE_PDEATHSIG, errno_of(e));
    }
    if let Err(e) = sys::setsid() {
        target_fail(err_w, STAGE_SETSID, errno_of(e));
    }
    // /proc must be mounted from inside the new PID namespace; mounting it in A
    // would expose A's (host) PID namespace.
    if let Err(e) = sys::mount_proc(sys::MS_NOSUID | sys::MS_NODEV | sys::MS_NOEXEC) {
        target_fail(err_w, STAGE_PROC, errno_of(e));
    }
    if let Err(e) = sys::close_fds_except(err_w) {
        target_fail(err_w, STAGE_CLOSE_FDS, errno_of(e));
    }
    if let Err(e) = sys::drop_all_capabilities() {
        target_fail(err_w, STAGE_CAPS, errno_of(e));
    }
    if let Err(e) = sys::set_no_new_privs() {
        target_fail(err_w, STAGE_NNP, errno_of(e));
    }
    if let Some(landlock) = &spec.landlock {
        if let Err(e) = sys::apply_landlock(landlock.handled_access_fs, &landlock.rules) {
            target_fail(err_w, STAGE_LANDLOCK, errno_of(e));
        }
    }
    if let Err(e) = spec.seccomp.install() {
        target_fail(err_w, STAGE_SECCOMP, errno_of(e));
    }
    if let Err(e) = sys::chdir(&spec.cwd) {
        target_fail(err_w, STAGE_CHDIR, errno_of(e));
    }

    let errno = sys::execve_raw(&spec.exec_path, &spec.argv_ptrs, &spec.env_ptrs);
    target_fail(err_w, STAGE_EXEC, errno)
}

fn target_fail(err_fd: c_int, stage: u8, errno: i32) -> ! {
    let mut report = [0u8; 5];
    report[0] = stage;
    report[1..5].copy_from_slice(&errno.to_le_bytes());
    let _ = sys::write_fd(err_fd, &report);
    sys::exit_now(71)
}

/// Milestone in which the runner becomes functional.
pub const IMPLEMENTED_IN_MILESTONE: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(host: &str, mode: GrantMode, is_dir: bool) -> Grant {
        Grant {
            host: PathBuf::from(host),
            mode,
            is_dir,
        }
    }

    fn rule<'a>(rules: &'a [sys::LandlockRule], path: &str) -> &'a sys::LandlockRule {
        rules
            .iter()
            .find(|rule| rule.path.to_string_lossy() == path)
            .unwrap_or_else(|| panic!("no Landlock rule for {path}"))
    }

    #[test]
    fn landlock_rules_mirror_the_mount_layout() {
        let handled = sys::landlock_access_for_abi(10);
        let grants = [
            grant("/grants/readonly", GrantMode::ReadOnly, true),
            grant("/grants/readwrite", GrantMode::ReadWrite, true),
            grant("/grants/file", GrantMode::ReadOnly, false),
            grant("/grants/writable-file", GrantMode::ReadWrite, false),
        ];
        let rules = build_landlock_rules(handled, &grants).expect("rules");

        let root = rule(&rules, "/");
        assert_eq!(root.access, sys::LANDLOCK_ACCESS_FS_READ_DIR);

        let usr = rule(&rules, "/usr");
        assert_ne!(usr.access & sys::LANDLOCK_ACCESS_FS_EXECUTE, 0);
        assert_ne!(usr.access & sys::LANDLOCK_ACCESS_FS_READ_FILE, 0);
        assert_eq!(usr.access & sys::LANDLOCK_ACCESS_FS_WRITE_FILE, 0);

        let tmp = rule(&rules, "/tmp");
        assert_ne!(tmp.access & sys::LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
        assert_ne!(tmp.access & sys::LANDLOCK_ACCESS_FS_MAKE_REG, 0);
        assert_ne!(tmp.access & sys::LANDLOCK_ACCESS_FS_REFER, 0);

        let readonly = rule(&rules, "/grants/readonly");
        assert_ne!(readonly.access & sys::LANDLOCK_ACCESS_FS_READ_FILE, 0);
        assert_ne!(readonly.access & sys::LANDLOCK_ACCESS_FS_READ_DIR, 0);
        assert_eq!(readonly.access & sys::LANDLOCK_ACCESS_FS_WRITE_FILE, 0);

        let readwrite = rule(&rules, "/grants/readwrite");
        assert_ne!(readwrite.access & sys::LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
        assert_ne!(readwrite.access & sys::LANDLOCK_ACCESS_FS_MAKE_REG, 0);

        // File rules must not carry directory-only rights, or the kernel
        // rejects them with EINVAL.
        let file = rule(&rules, "/grants/file");
        assert_ne!(file.access & sys::LANDLOCK_ACCESS_FS_READ_FILE, 0);
        assert_eq!(file.access & sys::LANDLOCK_ACCESS_FS_READ_DIR, 0);
        assert_eq!(file.access & sys::LANDLOCK_ACCESS_FS_MAKE_REG, 0);
        let writable_file = rule(&rules, "/grants/writable-file");
        assert_ne!(writable_file.access & sys::LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
        assert_eq!(writable_file.access & sys::LANDLOCK_ACCESS_FS_REFER, 0);
    }

    #[test]
    fn landlock_rules_never_use_rights_the_abi_lacks() {
        let handled = sys::landlock_access_for_abi(1);
        let rules = build_landlock_rules(handled, &[]).expect("rules");
        for rule in &rules {
            assert_eq!(rule.access & sys::LANDLOCK_ACCESS_FS_REFER, 0);
            assert_eq!(rule.access & sys::LANDLOCK_ACCESS_FS_TRUNCATE, 0);
            assert_eq!(rule.access & !handled, 0);
        }
    }
}
