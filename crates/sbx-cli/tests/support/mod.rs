#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Shared helpers for the `sbx` integration tests.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Path to the freshly built `sbx` binary.
pub fn sbx() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sbx"))
}

/// Path to the `sbx-escape` helper built next to `sbx`.
///
/// `cargo test` builds the binary targets of the package under test, but not a
/// binary from another workspace package. Build the helper once per test
/// process so a fresh clone works with the documented `cargo test --workspace`
/// gate, and so a stale helper cannot be used after its source changes.
pub fn escape() -> PathBuf {
    static ENSURED: OnceLock<()> = OnceLock::new();
    ENSURED.get_or_init(build_escape_helper);
    escape_path()
}

fn escape_path() -> PathBuf {
    sbx().parent().expect("sbx has a parent").join("sbx-escape")
}

fn build_escape_helper() {
    let sbx = sbx();
    let profile_dir = sbx.parent().expect("sbx has a parent");
    let target_dir = profile_dir
        .parent()
        .expect("profile directory has a parent");
    let profile = profile_dir
        .file_name()
        .and_then(|name| name.to_str())
        .expect("profile directory has a name");
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .arg("build")
        .arg("-p")
        .arg("sbx-escape")
        .arg("--target-dir")
        .arg(target_dir)
        .current_dir(workspace);
    match profile {
        "debug" => {}
        "release" => {
            command.arg("--release");
        }
        other => {
            command.arg("--profile").arg(other);
        }
    }

    let output = command.output().expect("run cargo build -p sbx-escape");
    assert!(
        output.status.success(),
        "could not build sbx-escape:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Return `Ok(())` when this host can actually create the sandbox.
///
/// A host without unprivileged user namespaces cannot run these tests. That is
/// not a pass: the caller prints a visible `SKIPPED` line and returns.
pub fn sandbox_available() -> Result<(), String> {
    static AVAILABLE: OnceLock<Result<(), String>> = OnceLock::new();
    AVAILABLE
        .get_or_init(|| {
            let output = Command::new(sbx())
                .args(["run", "--quiet", "--", "/bin/true"])
                .output()
                .map_err(|error| format!("cannot run sbx: {error}"))?;
            if output.status.success() {
                Ok(())
            } else {
                Err(format!(
                    "sbx run /bin/true exited {:?}: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            }
        })
        .clone()
}

/// Environment variable that turns an unavailable sandbox into a failure.
pub const REQUIRE_SANDBOX_ENV: &str = "SBX_REQUIRE_SANDBOX";

/// Parse the `SBX_REQUIRE_SANDBOX` value.
///
/// `1` requires the sandbox. Unset and `0` allow a visible skip. Any other
/// value is a configuration error rather than a silent skip.
pub fn require_sandbox_from(value: Option<&str>) -> Result<bool, String> {
    match value {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(other) => Err(format!(
            "{REQUIRE_SANDBOX_ENV} must be `1`, `0`, or unset, got `{other}`"
        )),
    }
}

/// Decide whether a sandbox-dependent test should return early.
///
/// Split from `skip_without_sandbox` so the decision can be tested without
/// changing the process environment while other tests run in parallel.
pub fn sandbox_skip_reason(available: Result<(), String>, required: bool) -> Option<String> {
    match available {
        Ok(()) => None,
        Err(reason) if required => {
            panic!("{REQUIRE_SANDBOX_ENV}=1 but the sandbox is unavailable: {reason}")
        }
        Err(reason) => Some(reason),
    }
}

/// Print a visible skip line and return true when the sandbox is unavailable.
///
/// With `SBX_REQUIRE_SANDBOX=1` an unavailable sandbox is a hard failure, not a
/// skip. This is for local gates on hosts that are expected to support the
/// sandbox. It does not turn feature-specific skips such as a missing pty into
/// failures.
pub fn skip_without_sandbox() -> bool {
    let required = require_sandbox_from(std::env::var(REQUIRE_SANDBOX_ENV).ok().as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    match sandbox_skip_reason(sandbox_available(), required) {
        None => false,
        Some(reason) => {
            eprintln!("SKIPPED: {reason}");
            true
        }
    }
}

/// A temporary directory removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("sbx-test-{label}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A unique token that cannot be guessed by the target and is easy to grep for.
pub fn random_token() -> String {
    let mut bytes = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .expect("read /dev/urandom");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
