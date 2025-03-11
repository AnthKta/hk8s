use hk8s::checks::*;
use k8s_openapi::api::core::v1::{Pod, PodSpec, Container, SecurityContext};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::api::rbac::v1::{RoleBinding, RoleRef};
use k8s_openapi::api::networking::v1::NetworkPolicy;

#[test]
fn test_pod_no_security_context() {
    let pod = Pod {
        metadata: ObjectMeta { name: Some("pod-no-sc".into()), ..Default::default() },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "container1".into(),
                security_context: None,
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let warnings = analyze_pod_insecure_workloads(&pod);
    assert!(warnings.contains(&"[K01] Pod 'pod-no-sc' container 'container1' has no security context defined".into()));
    assert_eq!(warnings.len(), 1);
}

#[test]
fn test_pod_missing_run_as_non_root() {
    let sc = SecurityContext {
        run_as_non_root: None,
        privileged: Some(false),
        ..Default::default()
    };
    let pod = Pod {
        metadata: ObjectMeta { name: Some("pod-missing-run-as".into()), ..Default::default() },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "container1".into(),
                security_context: Some(sc),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let warnings = analyze_pod_insecure_workloads(&pod);
    assert!(warnings.contains(&"[K01] Pod 'pod-missing-run-as' container 'container1' has no runAsNonRoot setting".into()));
    assert_eq!(warnings.len(), 1);
}

#[test]
fn test_pod_run_as_non_root_false_and_privileged_true() {
    let sc = SecurityContext {
        run_as_non_root: Some(false),
        privileged: Some(true),
        ..Default::default()
    };
    let pod = Pod {
        metadata: ObjectMeta { name: Some("pod-insecure".into()), ..Default::default() },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "container1".into(),
                security_context: Some(sc),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let warnings = analyze_pod_insecure_workloads(&pod);
    assert!(warnings.contains(&"[K01] Pod 'pod-insecure' container 'container1' may run as root (runAsNonRoot is false)".into()));
    assert!(warnings.contains(&"[K01] Pod 'pod-insecure' container 'container1' is running in privileged mode".into()));
    assert_eq!(warnings.len(), 2);
}

#[test]
fn test_role_binding_cluster_admin() {
    let rb = RoleBinding {
        metadata: ObjectMeta { name: Some("rb1".into()), ..Default::default() },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".into(),
            kind: "ClusterRole".into(),
            name: "cluster-admin".into(),
        },
        ..Default::default()
    };
    let result = analyze_role_binding(&rb);
    assert!(result.is_some());
    assert!(result.unwrap().contains("cluster-admin"));
}

#[test]
fn test_role_binding_non_admin_cluster_role() {
    let rb = RoleBinding {
        metadata: ObjectMeta { name: Some("rb2".into()), ..Default::default() },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".into(),
            kind: "ClusterRole".into(),
            name: "view".into(),
        },
        ..Default::default()
    };
    let result = analyze_role_binding(&rb);
    assert!(result.is_none());
}

#[test]
fn test_role_binding_role_instead_of_cluster_role() {
    let rb = RoleBinding {
        metadata: ObjectMeta { name: Some("rb3".into()), ..Default::default() },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".into(),
            kind: "Role".into(),
            name: "cluster-admin".into(),
        },
        ..Default::default()
    };
    let result = analyze_role_binding(&rb);
    assert!(result.is_none());
}

#[test]
fn test_network_policies_empty() {
    let policies: Vec<NetworkPolicy> = Vec::new();
    let result = analyze_network_policies(&policies);
    assert!(result.is_some());
    assert!(result.unwrap().contains("No NetworkPolicies found"));
}

#[test]
fn test_network_policies_one() {
    let np = NetworkPolicy {
        metadata: ObjectMeta { name: Some("np1".into()), ..Default::default() },
        ..Default::default()
    };
    let policies = vec![np];
    let result = analyze_network_policies(&policies);
    assert!(result.is_some());
    assert!(result.unwrap().contains("Found 1 NetworkPolicy"));
}

#[test]
fn test_network_policies_multiple() {
    let np1 = NetworkPolicy {
        metadata: ObjectMeta { name: Some("np1".into()), ..Default::default() },
        ..Default::default()
    };
    let np2 = NetworkPolicy {
        metadata: ObjectMeta { name: Some("np2".into()), ..Default::default() },
        ..Default::default()
    };
    let np3 = NetworkPolicy {
        metadata: ObjectMeta { name: Some("np3".into()), ..Default::default() },
        ..Default::default()
    };
    let policies = vec![np1, np2, np3];
    let result = analyze_network_policies(&policies);
    assert!(result.is_some());
    assert!(result.unwrap().contains("Found 3 NetworkPolicy"));
}

#[test]
fn test_outdated_component_with_versioned_image() {
    let pod = Pod {
        metadata: ObjectMeta { name: Some("airflow-web-1".into()), ..Default::default() },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "web".into(),
                image: Some("apache/airflow:2.5.1".into()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let warnings = analyze_outdated_components(&pod);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("apache/airflow:2.5.1"));
}

#[test]
fn test_outdated_component_with_latest_image() {
    let pod = Pod {
        metadata: ObjectMeta { name: Some("airflow-web-2".into()), ..Default::default() },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "web".into(),
                image: Some("apache/airflow:latest".into()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let warnings = analyze_outdated_components(&pod);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("apache/airflow:latest"));
}

#[test]
fn test_outdated_component_no_image() {
    let pod = Pod {
        metadata: ObjectMeta { name: Some("airflow-web-3".into()), ..Default::default() },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "web".into(),
                image: None,
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let warnings = analyze_outdated_components(&pod);
    assert!(warnings.is_empty());
}

