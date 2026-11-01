#![forbid(unsafe_code)]
//! Smoke test for the machine-readable doctor output.
//!
//! This runs the real binary and the real probes. It deliberately does not
//! require the host to support every feature: GitHub-hosted runners may forbid
//! user namespaces. It requires the schema to be stable and honest either way.

use std::process::Command;

#[test]
fn doctor_json_is_valid_and_has_expected_keys() {
    let output = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["doctor", "--json"])
        .output()
        .expect("run sbx doctor --json");

    // 0 = all required features available; 124 = explicit refusal. Anything
    // else means the doctor command itself crashed.
    assert!(
        matches!(output.status.code(), Some(0) | Some(124)),
        "unexpected exit status: {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout was not valid JSON: {e}\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });

    for key in [
        "tool",
        "version",
        "kernel",
        "features",
        "milestones_1_3_ready",
    ] {
        assert!(
            value.get(key).is_some(),
            "missing top-level key {key}: {value}"
        );
    }
    assert_eq!(value["tool"], "sbx");
    assert!(value["version"].is_string());
    assert!(value["kernel"].is_string());
    let ready = value["milestones_1_3_ready"]
        .as_bool()
        .expect("milestones_1_3_ready is a boolean");

    let features = value["features"].as_array().expect("features is an array");
    assert!(!features.is_empty());
    for feature in features {
        for key in ["name", "label", "state", "detail", "required"] {
            assert!(
                feature.get(key).is_some(),
                "feature missing {key}: {feature}"
            );
        }
        let state = feature["state"].as_str().unwrap_or_default();
        assert!(
            matches!(state, "ok" | "degraded" | "unavailable"),
            "unexpected state {state}"
        );
    }

    let names: Vec<&str> = features.iter().filter_map(|f| f["name"].as_str()).collect();
    for required in [
        "user_namespaces",
        "mount_namespace",
        "pid_namespace",
        "net_namespace",
        "ipc_namespace",
        "uts_namespace",
        "landlock",
        "seccomp_filter",
        "seccomp_user_notif",
        "no_new_privs",
    ] {
        assert!(names.contains(&required), "missing feature {required}");
    }

    // The readiness flag must agree with the required feature states.
    let all_required_ok = features
        .iter()
        .filter(|f| f["required"].as_bool() == Some(true))
        .all(|f| f["state"] == "ok");
    assert_eq!(ready, all_required_ok);
    assert_eq!(output.status.code() == Some(0), ready);
}
