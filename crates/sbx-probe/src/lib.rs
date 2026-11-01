#![forbid(unsafe_code)]
//! Host capability probing for `sbx doctor`.
//!
//! Every kernel feature is probed for real through sbx-sys. The classification
//! step is a pure function over `ProbeFacts` so that it can be unit-tested with
//! fake inputs without weakening what the real binary does.

use sbx_core::{DoctorReport, Feature, FeatureState, KernelVersion};

/// Raw results of all probes. Keeping them separate from classification lets
/// tests exercise unavailable/degraded paths deterministically.
#[derive(Debug, Clone)]
pub struct ProbeFacts {
    pub kernel_release: Result<String, String>,
    pub machine: Result<String, String>,
    pub user_namespaces: Result<(), String>,
    pub mount_namespace: Result<(), String>,
    pub pid_namespace: Result<(), String>,
    pub net_namespace: Result<(), String>,
    pub ipc_namespace: Result<(), String>,
    pub uts_namespace: Result<(), String>,
    pub landlock_abi: Result<i32, String>,
    pub seccomp_mode: Result<i64, String>,
    pub seccomp_filter: Result<(), String>,
    pub seccomp_user_notif: Result<bool, String>,
    pub no_new_privs: Result<(), String>,
    pub cgroup_v2: bool,
    pub kvm: bool,
}

impl ProbeFacts {
    /// Run every probe for real. Forks are sequential and short-lived; the
    /// doctor process itself is never modified by a probe.
    pub fn collect() -> Self {
        let kernel_release = sbx_sys::kernel_release().map_err(|e| e.to_string());
        let machine = sbx_sys::machine().map_err(|e| e.to_string());

        // Each namespace is probed in a fresh user namespace with the caller's
        // own uid/gid mapped to themselves. This is the exact mode sbx run uses.
        let user_namespaces = sbx_sys::probe_userns(0, false);
        let mount_namespace = sbx_sys::probe_userns(sbx_sys::CLONE_NEWNS, false);
        let pid_namespace = sbx_sys::probe_userns(sbx_sys::CLONE_NEWPID, true);
        let net_namespace = sbx_sys::probe_userns(sbx_sys::CLONE_NEWNET, false);
        let ipc_namespace = sbx_sys::probe_userns(sbx_sys::CLONE_NEWIPC, false);
        let uts_namespace = sbx_sys::probe_userns(sbx_sys::CLONE_NEWUTS, false);

        let landlock_abi = sbx_sys::landlock_abi();
        let seccomp_mode = sbx_sys::seccomp_mode().map_err(|e| e.to_string());
        let seccomp_filter = sbx_sys::probe_seccomp_filter();
        let seccomp_user_notif = sbx_sys::seccomp_action_available(sbx_sys::SECCOMP_RET_USER_NOTIF);
        let no_new_privs = sbx_sys::probe_no_new_privs();

        Self {
            kernel_release,
            machine,
            user_namespaces,
            mount_namespace,
            pid_namespace,
            net_namespace,
            ipc_namespace,
            uts_namespace,
            landlock_abi,
            seccomp_mode,
            seccomp_filter,
            seccomp_user_notif,
            no_new_privs,
            cgroup_v2: sbx_sys::cgroup_v2_present(),
            kvm: sbx_sys::kvm_present(),
        }
    }
}

fn namespace_feature(
    name: &str,
    label: &str,
    result: &Result<(), String>,
    detail: &str,
) -> Feature {
    let fix = if name == "user_namespaces" {
        "Likely causes: kernel.unprivileged_userns_clone=0, user.max_user_namespaces=0, or an LSM/container policy denying unshare. Check those; sbx never changes sysctls itself."
    } else {
        "Namespace creation was denied after entering a user namespace; check kernel and LSM policy (see docs/THREAT_MODEL.md)."
    };
    match result {
        Ok(()) => Feature::new(name, label, FeatureState::Ok, detail, None::<String>, true),
        Err(e) => Feature::new(
            name,
            label,
            FeatureState::Unavailable,
            e.clone(),
            Some(fix),
            true,
        ),
    }
}

/// Pure classification of probe facts into the stable doctor report.
pub fn report_from_facts(version: &str, facts: &ProbeFacts) -> DoctorReport {
    let (kernel, kernel_version, kernel_feature) = match &facts.kernel_release {
        Ok(release) => {
            let parsed = KernelVersion::parse(release);
            let detail = match &facts.machine {
                Ok(machine) => format!("{release} ({machine})"),
                Err(_) => release.clone(),
            };
            let feature = match parsed {
                Some(_) => Feature::new(
                    "kernel",
                    "kernel",
                    FeatureState::Ok,
                    detail.clone(),
                    None::<String>,
                    false,
                ),
                None => Feature::new(
                    "kernel",
                    "kernel",
                    FeatureState::Degraded,
                    format!("{detail}; release string did not parse"),
                    None::<String>,
                    false,
                ),
            };
            (release.clone(), parsed, feature)
        }
        Err(e) => {
            let feature = Feature::new(
                "kernel",
                "kernel",
                FeatureState::Unavailable,
                e.clone(),
                Some("uname(2) failed; sbx cannot reason about this kernel."),
                false,
            );
            ("unknown".to_string(), None, feature)
        }
    };

    let mut features = vec![kernel_feature];

    features.push(namespace_feature(
        "user_namespaces",
        "user namespaces",
        &facts.user_namespaces,
        "unshare(CLONE_NEWUSER) plus uid/gid map preserving caller ids",
    ));
    features.push(namespace_feature(
        "mount_namespace",
        "mount namespace",
        &facts.mount_namespace,
        "unshare(CLONE_NEWNS) inside a mapped user namespace",
    ));
    features.push(namespace_feature(
        "pid_namespace",
        "pid namespace",
        &facts.pid_namespace,
        "unshare(CLONE_NEWPID); first child observed as pid 1",
    ));
    features.push(namespace_feature(
        "net_namespace",
        "net namespace",
        &facts.net_namespace,
        "unshare(CLONE_NEWNET) inside a mapped user namespace",
    ));
    features.push(namespace_feature(
        "ipc_namespace",
        "ipc namespace",
        &facts.ipc_namespace,
        "unshare(CLONE_NEWIPC) inside a mapped user namespace",
    ));
    features.push(namespace_feature(
        "uts_namespace",
        "uts namespace",
        &facts.uts_namespace,
        "unshare(CLONE_NEWUTS) inside a mapped user namespace",
    ));

    features.push(match &facts.landlock_abi {
        Ok(abi) if *abi >= 1 => Feature::new(
            "landlock",
            "Landlock",
            FeatureState::Ok,
            format!("landlock_create_ruleset(VERSION) reports ABI {abi}"),
            None::<String>,
            true,
        ),
        Ok(abi) => Feature::new(
            "landlock",
            "Landlock",
            FeatureState::Degraded,
            format!("Landlock reports ABI {abi}, but sbx needs at least ABI 1"),
            Some("Enable CONFIG_SECURITY_LANDLOCK (Linux >= 5.13)."),
            true,
        ),
        Err(e) => Feature::new(
            "landlock",
            "Landlock",
            FeatureState::Unavailable,
            e.clone(),
            Some("Enable CONFIG_SECURITY_LANDLOCK (Linux >= 5.13); check LSM policy."),
            true,
        ),
    });

    let mode_text = match &facts.seccomp_mode {
        Ok(mode) => format!("; current seccomp mode {mode}"),
        Err(e) => format!("; seccomp mode query failed: {e}"),
    };
    features.push(match &facts.seccomp_filter {
        Ok(()) => Feature::new(
            "seccomp_filter",
            "seccomp filter",
            FeatureState::Ok,
            format!("SECCOMP_SET_MODE_FILTER accepted a probe filter{mode_text}"),
            None::<String>,
            true,
        ),
        Err(e) => Feature::new(
            "seccomp_filter",
            "seccomp filter",
            FeatureState::Unavailable,
            e.clone(),
            Some("Enable CONFIG_SECCOMP_FILTER; check the container runtime's seccomp policy."),
            true,
        ),
    });
    features.push(match &facts.seccomp_user_notif {
        Ok(true) => Feature::new(
            "seccomp_user_notif",
            "SECCOMP_RET_USER_NOTIF",
            FeatureState::Ok,
            "seccomp(SECCOMP_GET_ACTION_AVAIL) accepts USER_NOTIF".to_string(),
            None::<String>,
            true,
        ),
        Ok(false) => Feature::new(
            "seccomp_user_notif",
            "SECCOMP_RET_USER_NOTIF",
            FeatureState::Unavailable,
            "kernel reports the USER_NOTIF action as unavailable".to_string(),
            Some("Needs Linux >= 5.0 with CONFIG_SECCOMP_FILTER and user-notify enabled."),
            true,
        ),
        Err(e) => Feature::new(
            "seccomp_user_notif",
            "SECCOMP_RET_USER_NOTIF",
            FeatureState::Unavailable,
            e.clone(),
            Some("Needs Linux >= 5.0 with CONFIG_SECCOMP_FILTER and user-notify enabled."),
            true,
        ),
    });

    features.push(match &facts.no_new_privs {
        Ok(()) => Feature::new(
            "no_new_privs",
            "no_new_privs",
            FeatureState::Ok,
            "PR_SET_NO_NEW_PRIVS succeeded and PR_GET_NO_NEW_PRIVS returned 1",
            None::<String>,
            true,
        ),
        Err(e) => Feature::new(
            "no_new_privs",
            "no_new_privs",
            FeatureState::Unavailable,
            e.clone(),
            Some("PR_SET_NO_NEW_PRIVS requires Linux >= 3.5."),
            true,
        ),
    });

    features.push(Feature::new(
        "cgroup_v2",
        "cgroup v2",
        if facts.cgroup_v2 {
            FeatureState::Ok
        } else {
            FeatureState::Unavailable
        },
        if facts.cgroup_v2 {
            "/sys/fs/cgroup/cgroup.controllers is present"
        } else {
            "/sys/fs/cgroup/cgroup.controllers is absent"
        },
        None::<String>,
        false,
    ));
    features.push(Feature::new(
        "kvm",
        "/dev/kvm",
        if facts.kvm {
            FeatureState::Ok
        } else {
            FeatureState::Unavailable
        },
        if facts.kvm {
            "/dev/kvm is present (hardware-virtualisation information only)"
        } else {
            "/dev/kvm is absent (hardware-virtualisation information only)"
        },
        None::<String>,
        false,
    ));

    DoctorReport::new(version, kernel, kernel_version, features)
}

/// Human-readable table. Fix hints are printed on a continuation line so each
/// row stays one line but the hint is never hidden.
pub fn render_table(report: &DoctorReport) -> String {
    let feature_width = report
        .features
        .iter()
        .map(|f| f.label.len())
        .max()
        .unwrap_or(7)
        .max("FEATURE".len());
    let status_width = 11.max("STATUS".len());

    let mut out = String::new();
    out.push_str(&format!(
        "{:<feature_width$}  {:<status_width$}  {}\n",
        "FEATURE", "STATUS", "DETAIL"
    ));
    out.push_str(&format!(
        "{:<feature_width$}  {:<status_width$}  {}\n",
        "-".repeat(feature_width),
        "-".repeat(status_width),
        "-".repeat(48)
    ));
    for feature in &report.features {
        out.push_str(&format!(
            "{:<feature_width$}  {:<status_width$}  {}\n",
            feature.label,
            feature.state.label(),
            feature.detail
        ));
        if let Some(fix) = &feature.fix {
            out.push_str(&format!(
                "{:<feature_width$}  {:<status_width$}  fix: {}\n",
                "", "", fix
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_facts() -> ProbeFacts {
        ProbeFacts {
            kernel_release: Ok("6.11.3-arch1-1".to_string()),
            machine: Ok("x86_64".to_string()),
            user_namespaces: Ok(()),
            mount_namespace: Ok(()),
            pid_namespace: Ok(()),
            net_namespace: Ok(()),
            ipc_namespace: Ok(()),
            uts_namespace: Ok(()),
            landlock_abi: Ok(6),
            seccomp_mode: Ok(0),
            seccomp_filter: Ok(()),
            seccomp_user_notif: Ok(true),
            no_new_privs: Ok(()),
            cgroup_v2: true,
            kvm: true,
        }
    }

    fn feature<'a>(report: &'a DoctorReport, name: &str) -> &'a Feature {
        report
            .features
            .iter()
            .find(|f| f.name == name)
            .expect("feature exists")
    }

    #[test]
    fn healthy_host_is_ready() {
        let report = report_from_facts("0.1.0", &healthy_facts());
        assert!(report.milestones_1_3_ready);
        assert_eq!(report.kernel, "6.11.3-arch1-1");
        assert_eq!(report.kernel_version, KernelVersion::parse("6.11.3"));
        assert_eq!(feature(&report, "landlock").state, FeatureState::Ok);
        assert_eq!(feature(&report, "kvm").state, FeatureState::Ok);
    }

    #[test]
    fn userns_failure_blocks_the_milestones() {
        let mut facts = healthy_facts();
        facts.user_namespaces = Err("unshare(CLONE_NEWUSER) failed with EPERM (errno 1)".into());
        let report = report_from_facts("0.1.0", &facts);
        assert!(!report.milestones_1_3_ready);
        assert_eq!(
            feature(&report, "user_namespaces").state,
            FeatureState::Unavailable
        );
        assert!(feature(&report, "user_namespaces").fix.is_some());
    }

    #[test]
    fn old_landlock_abi_is_degraded_and_blocks() {
        let mut facts = healthy_facts();
        facts.landlock_abi = Ok(0);
        let report = report_from_facts("0.1.0", &facts);
        assert!(!report.milestones_1_3_ready);
        assert_eq!(feature(&report, "landlock").state, FeatureState::Degraded);
    }

    #[test]
    fn missing_user_notif_blocks() {
        let mut facts = healthy_facts();
        facts.seccomp_user_notif = Ok(false);
        let report = report_from_facts("0.1.0", &facts);
        assert!(!report.milestones_1_3_ready);
        assert_eq!(
            feature(&report, "seccomp_user_notif").state,
            FeatureState::Unavailable
        );
    }

    #[test]
    fn informational_failures_do_not_block() {
        let mut facts = healthy_facts();
        facts.cgroup_v2 = false;
        facts.kvm = false;
        let report = report_from_facts("0.1.0", &facts);
        assert!(report.milestones_1_3_ready);
        assert_eq!(
            feature(&report, "cgroup_v2").state,
            FeatureState::Unavailable
        );
    }

    #[test]
    fn unparsable_kernel_is_degraded_but_not_required() {
        let mut facts = healthy_facts();
        facts.kernel_release = Ok("vendor-kernel".to_string());
        let report = report_from_facts("0.1.0", &facts);
        assert_eq!(report.kernel_version, None);
        assert_eq!(feature(&report, "kernel").state, FeatureState::Degraded);
        assert!(report.milestones_1_3_ready);
    }

    #[test]
    fn table_never_hides_a_fix_hint() {
        let mut facts = healthy_facts();
        facts.landlock_abi = Err("ENOSYS (errno 38)".to_string());
        let report = report_from_facts("0.1.0", &facts);
        let table = render_table(&report);
        assert!(table.contains("Landlock"));
        assert!(table.contains("unavailable"));
        assert!(table.contains("fix:"));
        assert!(table.contains("Landlock"));
    }
}
