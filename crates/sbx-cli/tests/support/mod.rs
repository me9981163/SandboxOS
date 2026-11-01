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
pub fn escape() -> PathBuf {
    sbx().parent().expect("sbx has a parent").join("sbx-escape")
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

/// Print a visible skip line and return true when the sandbox is unavailable.
pub fn skip_without_sandbox() -> bool {
    match sandbox_available() {
        Ok(()) => false,
        Err(reason) => {
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
