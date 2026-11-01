#![forbid(unsafe_code)]
//! Shared, platform-independent types for sbx.
//!
//! Nothing here talks to the kernel. Keeping the data model free of syscalls
//! makes it straightforward to unit-test classification and serialisation
//! without weakening the sandbox boundary.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

/// Whether a host path is granted read-only or read-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantMode {
    ReadOnly,
    ReadWrite,
}

/// The result of applying the host-path policy to one canonical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Safe to expose with the requested mode.
    Allow,
    /// Exposing this path needs `--i-know-this-is-dangerous`.
    RequiresDangerous { reason: String },
    /// Never expose this path, even with the override flag.
    Deny { reason: String },
}

/// Policy for paths bind-mounted into the sandbox.
///
/// The policy is deliberately path-based, not content-based: it can only make
/// claims about the name the user asked for. Callers must canonicalise first so
/// that `..` and symlinks cannot smuggle a sensitive directory past the checks.
pub struct PathPolicy;

impl PathPolicy {
    pub fn check(canonical: &Path, mode: GrantMode) -> PolicyDecision {
        if !canonical.is_absolute() {
            return PolicyDecision::Deny {
                reason: "path is not absolute".to_string(),
            };
        }

        let components: Vec<&str> = canonical
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => name.to_str(),
                _ => None,
            })
            .collect();

        if components.is_empty() {
            return PolicyDecision::Deny {
                reason: "refusing to grant the host root filesystem".to_string(),
            };
        }

        if let Some(component) = components.iter().find(|name| is_secret_component(name)) {
            return PolicyDecision::RequiresDangerous {
                reason: format!("path contains sensitive component `{component}`"),
            };
        }

        let text = canonical.to_string_lossy();
        let exact = |candidate: &str| text == candidate;
        let under = |candidate: &str| {
            text.strip_prefix(candidate)
                .is_some_and(|rest| rest.starts_with('/'))
        };

        // These expose host control interfaces or credentials directly.
        for sensitive in [
            "/proc", "/sys", "/dev", "/run", "/boot", "/root", "/etc", "/var",
        ] {
            if exact(sensitive) || under(sensitive) {
                return PolicyDecision::RequiresDangerous {
                    reason: format!("`{sensitive}` exposes host system state or credentials"),
                };
            }
        }

        if exact("/home") {
            return PolicyDecision::RequiresDangerous {
                reason: "`/home` exposes every user's home directory".to_string(),
            };
        }

        if exact("/tmp") {
            return PolicyDecision::RequiresDangerous {
                reason: "host `/tmp` may contain other processes' files".to_string(),
            };
        }

        // The sandbox already mounts /usr read-only. Granting subtrees of it is
        // redundant for read-only use, but writing to host system software is
        // not a normal sandbox operation.
        if exact("/usr") || under("/usr") {
            if mode == GrantMode::ReadWrite {
                return PolicyDecision::RequiresDangerous {
                    reason: "writing to host system software under `/usr`".to_string(),
                };
            }
            return PolicyDecision::Allow;
        }

        // Merged-/usr symlinks canonicalise to /usr, but keep the explicit
        // branches for hosts that have real directories.
        if (exact("/bin") || exact("/sbin") || exact("/lib") || exact("/lib64"))
            && mode == GrantMode::ReadWrite
        {
            return PolicyDecision::RequiresDangerous {
                reason: "writing to host system software".to_string(),
            };
        }

        PolicyDecision::Allow
    }
}

fn is_secret_component(name: &str) -> bool {
    matches!(
        name,
        ".ssh"
            | ".gnupg"
            | ".aws"
            | ".azure"
            | ".kube"
            | ".docker"
            | ".password-store"
            | ".netrc"
            | ".git-credentials"
            | ".npmrc"
            | ".pypirc"
            | ".mozilla"
            | ".thunderbird"
            | "keyrings"
            | "id_rsa"
            | "id_dsa"
            | "id_ecdsa"
            | "id_ed25519"
            | "authorized_keys"
            | "shadow"
            | "gshadow"
            | "sudoers"
            | "private_key"
    )
}

/// One line of the pre-execution protection report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    pub name: String,
    pub active: bool,
    pub detail: String,
}

/// The protections that `sbx run` claims to apply for one target.
///
/// `active == false` entries exist so that a protection which is not applied is
/// stated explicitly rather than omitted. The summary is display-only; the
/// sandbox does not read it back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectionSummary {
    pub target: String,
    pub entries: Vec<Protection>,
}

impl ProtectionSummary {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, name: impl Into<String>, active: bool, detail: impl Into<String>) {
        self.entries.push(Protection {
            name: name.into(),
            active,
            detail: detail.into(),
        });
    }

    /// Render a stable, human-readable block. It is written to stderr before
    /// the target is executed.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("sbx: protection summary\n");
        out.push_str(&format!("  target: {}\n", self.target));
        for entry in &self.entries {
            let state = if entry.active { "on " } else { "off" };
            out.push_str(&format!("  [{state}] {}: {}\n", entry.name, entry.detail));
        }
        out
    }
}

/// Exit code used when `sbx` itself fails (for example a bad argument after
/// parsing, or a failure in its own supervisor code).
pub const EXIT_INTERNAL_ERROR: i32 = 125;
/// Exit code used when `sbx` refuses to run because a required protection is
/// unavailable. This is deliberately distinct from an internal bug.
pub const EXIT_PROTECTION_UNAVAILABLE: i32 = 124;

/// The state of one probed feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeatureState {
    /// Present and usable for the milestones that need it.
    Ok,
    /// Present but limited. The report must say what is missing.
    Degraded,
    /// Not present. `sbx run` must fail closed if this feature is required.
    Unavailable,
}

impl FeatureState {
    pub fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One row in `sbx doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Feature {
    /// Stable machine-readable name (ASCII, snake_case).
    pub name: String,
    /// Human-readable name for the table.
    pub label: String,
    pub state: FeatureState,
    /// What was actually probed and what happened.
    pub detail: String,
    /// One-line actionable hint; `None` when the feature is healthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// Whether Milestones 1-3 require this feature.
    pub required: bool,
}

impl Feature {
    pub fn new(
        name: impl Into<String>,
        label: impl Into<String>,
        state: FeatureState,
        detail: impl Into<String>,
        fix: Option<impl Into<String>>,
        required: bool,
    ) -> Self {
        Self {
            name: name.into(),
            label: label.into(),
            state,
            detail: detail.into(),
            fix: fix.map(Into::into),
            required,
        }
    }
}

/// Parsed kernel release, used both for display and for fakeable tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
}

impl KernelVersion {
    /// Parse the leading `major.minor` from a release string such as
    /// `6.11.3-arch1-1`. Returns `None` rather than guessing when the shape is
    /// not what the kernel documents.
    pub fn parse(release: &str) -> Option<Self> {
        let mut parts = release.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor_part = parts.next()?;
        // A trailing suffix on the minor component (rare, but possible in
        // vendor kernels) is not a version number.
        let minor: u32 = minor_part
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()?;
        if minor_part.is_empty() {
            return None;
        }
        Some(Self { major, minor })
    }

    pub fn is_at_least(self, major: u32, minor: u32) -> bool {
        (self.major, self.minor) >= (major, minor)
    }
}

/// Full `sbx doctor` output. This is the stable `--json` schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub tool: String,
    pub version: String,
    pub kernel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<KernelVersion>,
    pub features: Vec<Feature>,
    /// True only when every host feature required by the milestones is `ok`.
    pub milestones_1_3_ready: bool,
}

impl DoctorReport {
    pub fn new(
        version: impl Into<String>,
        kernel: impl Into<String>,
        kernel_version: Option<KernelVersion>,
        features: Vec<Feature>,
    ) -> Self {
        let milestones_1_3_ready = features
            .iter()
            .filter(|f| f.required)
            .all(|f| f.state.is_ok());
        Self {
            tool: "sbx".to_string(),
            version: version.into(),
            kernel: kernel.into(),
            kernel_version,
            features,
            milestones_1_3_ready,
        }
    }

    /// Returns the required features that are not fully available.
    pub fn blocking(&self) -> Vec<&Feature> {
        self.features
            .iter()
            .filter(|f| f.required && !f.state.is_ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_normal_release() {
        assert_eq!(
            KernelVersion::parse("6.11.3-arch1-1"),
            Some(KernelVersion {
                major: 6,
                minor: 11
            })
        );
    }

    #[test]
    fn parses_two_component_release() {
        assert_eq!(
            KernelVersion::parse("5.15"),
            Some(KernelVersion {
                major: 5,
                minor: 15
            })
        );
    }

    #[test]
    fn rejects_garbage_instead_of_guessing() {
        assert_eq!(KernelVersion::parse(""), None);
        assert_eq!(KernelVersion::parse("linux"), None);
        assert_eq!(KernelVersion::parse("6"), None);
        assert_eq!(KernelVersion::parse("6.x"), None);
    }

    #[test]
    fn readiness_requires_every_required_feature_to_be_ok() {
        let ok = Feature::new("a", "A", FeatureState::Ok, "fine", None::<String>, true);
        let degraded = Feature::new(
            "b",
            "B",
            FeatureState::Degraded,
            "limited",
            Some("fix it"),
            true,
        );
        let optional = Feature::new(
            "c",
            "C",
            FeatureState::Unavailable,
            "absent",
            None::<String>,
            false,
        );

        assert!(DoctorReport::new("0", "k", None, vec![ok.clone()]).milestones_1_3_ready);
        let report = DoctorReport::new("0", "k", None, vec![ok, degraded, optional]);
        assert!(!report.milestones_1_3_ready);
        assert_eq!(report.blocking().len(), 1);
        assert_eq!(report.blocking()[0].name, "b");
    }

    #[test]
    fn policy_allows_an_ordinary_project_directory() {
        assert_eq!(
            PathPolicy::check(Path::new("/home/alice/project"), GrantMode::ReadWrite),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn policy_never_allows_the_host_root() {
        assert!(matches!(
            PathPolicy::check(Path::new("/"), GrantMode::ReadOnly),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn policy_requires_the_override_for_system_roots() {
        for path in [
            "/proc", "/sys", "/dev", "/etc", "/var", "/root", "/boot", "/run",
        ] {
            assert!(
                matches!(
                    PathPolicy::check(Path::new(path), GrantMode::ReadOnly),
                    PolicyDecision::RequiresDangerous { .. }
                ),
                "{path} should require the override"
            );
        }
    }

    #[test]
    fn policy_requires_the_override_for_host_tmp_and_home() {
        for path in ["/tmp", "/home"] {
            assert!(matches!(
                PathPolicy::check(Path::new(path), GrantMode::ReadOnly),
                PolicyDecision::RequiresDangerous { .. }
            ));
        }
    }

    #[test]
    fn policy_requires_the_override_for_secret_bearing_paths() {
        for path in [
            "/home/alice/.ssh",
            "/home/alice/project/id_rsa",
            "/home/alice/.config/keyrings",
            "/srv/.git-credentials",
        ] {
            assert!(
                matches!(
                    PathPolicy::check(Path::new(path), GrantMode::ReadOnly),
                    PolicyDecision::RequiresDangerous { .. }
                ),
                "{path} should require the override"
            );
        }
    }

    #[test]
    fn policy_allows_read_only_usr_but_marks_writes_dangerous() {
        assert_eq!(
            PathPolicy::check(Path::new("/usr/share/doc"), GrantMode::ReadOnly),
            PolicyDecision::Allow
        );
        assert!(matches!(
            PathPolicy::check(Path::new("/usr/local/bin"), GrantMode::ReadWrite),
            PolicyDecision::RequiresDangerous { .. }
        ));
    }

    #[test]
    fn policy_rejects_relative_paths() {
        assert!(matches!(
            PathPolicy::check(Path::new("relative/path"), GrantMode::ReadOnly),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn summary_renders_off_entries_instead_of_hiding_them() {
        let mut summary = ProtectionSummary::new("/usr/bin/echo");
        summary.add("user namespace", true, "mapped");
        summary.add("Landlock", false, "not enabled");
        let text = summary.render();
        assert!(text.contains("[on ] user namespace: mapped"));
        assert!(text.contains("[off] Landlock: not enabled"));
        assert!(text.contains("target: /usr/bin/echo"));
    }
}
