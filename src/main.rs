// Cargo.toml dependencies:
// [dependencies]
// kube = { version = "0.90", features = ["runtime", "derive"] }
// k8s-openapi = "0.14"
// tokio = { version = "1", features = ["full"] }
// anyhow = "1.0"

use kube::{api::{Api, ListParams}, Client};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::rbac::v1::RoleBinding;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use anyhow::Result;
use tokio::time::{sleep, Duration};

/// --- Helper Functions for Each Check ---

/// K01: Insecure Workload Configurations
/// Analyzes a Pod and returns warnings based on container security context settings.
fn analyze_pod_insecure_workloads(pod: &Pod) -> Vec<String> {
    let mut warnings = Vec::new();
    let pod_name = pod.metadata.name.clone().unwrap_or("<unknown>".into());
    if let Some(spec) = &pod.spec {
        for container in &spec.containers {
            let container_name = container.name.clone();
            if let Some(sc) = &container.security_context {
                if let Some(run_as_non_root) = sc.run_as_non_root {
                    if !run_as_non_root {
                        warnings.push(format!(
                            "[K01] Pod '{}' container '{}' may run as root (runAsNonRoot is false)",
                            pod_name, container_name
                        ));
                    }
                } else {
                    warnings.push(format!(
                        "[K01] Pod '{}' container '{}' has no runAsNonRoot setting",
                        pod_name, container_name
                    ));
                }
                if let Some(privileged) = sc.privileged {
                    if privileged {
                        warnings.push(format!(
                            "[K01] Pod '{}' container '{}' is running in privileged mode",
                            pod_name, container_name
                        ));
                    }
                }
            } else {
                warnings.push(format!(
                    "[K01] Pod '{}' container '{}' has no security context defined",
                    pod_name, container_name
                ));
            }
        }
    }
    warnings
}

/// K03: Overly Permissive RBAC Configurations
/// Analyzes a RoleBinding and returns a warning if its role_ref is a ClusterRole with "cluster-admin" in its name.
fn analyze_role_binding(rb: &RoleBinding) -> Option<String> {
    let rb_name = rb.metadata.name.clone().unwrap_or("<unknown>".into());
    let role_ref = &rb.role_ref; // role_ref is required.
    if role_ref.kind == "ClusterRole" && role_ref.name.to_lowercase().contains("cluster-admin") {
        Some(format!(
            "[K03] RoleBinding '{}' binds a high-privilege ClusterRole '{}'",
            rb_name, role_ref.name
        ))
    } else {
        None
    }
}

/// K07: Missing Network Segmentation Controls
/// Analyzes a slice of NetworkPolicy objects and returns a message.
fn analyze_network_policies(nps: &[NetworkPolicy]) -> Option<String> {
    if nps.is_empty() {
        Some(String::from(
            "[K07] No NetworkPolicies found. Consider implementing network segmentation controls.",
        ))
    } else {
        Some(format!("[K07] Found {} NetworkPolicy object(s).", nps.len()))
    }
}

/// K10: Outdated and Vulnerable Components (simplified check)
/// For each container in a Pod, returns a message with its image.
fn analyze_outdated_components(pod: &Pod) -> Vec<String> {
    let mut warnings = Vec::new();
    let pod_name = pod.metadata.name.clone().unwrap_or("<unknown>".into());
    if let Some(spec) = &pod.spec {
        for container in &spec.containers {
            if let Some(image) = &container.image {
                warnings.push(format!(
                    "[K10] Pod '{}' container '{}' is running image '{}'",
                    pod_name, container.name, image
                ));
            }
        }
    }
    warnings
}

/// --- Continuous Monitoring Functions ---
/// These functions call the helper functions after fetching live objects from the cluster.
/// (For brevity, these functions simply print messages.)

async fn check_insecure_workloads(client: Client, namespace: &str) -> Result<()> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default();
    let pod_list = pods.list(&lp).await?;
    for p in pod_list.items {
        let warnings = analyze_pod_insecure_workloads(&p);
        for w in warnings {
            println!("{}", w);
        }
    }
    Ok(())
}

async fn check_overly_permissive_rbac(client: Client, namespace: &str) -> Result<()> {
    let role_bindings: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default();
    let rb_list = role_bindings.list(&lp).await?;
    for rb in rb_list.items {
        if let Some(msg) = analyze_role_binding(&rb) {
            println!("{}", msg);
        }
    }
    Ok(())
}

async fn check_network_policies(client: Client, namespace: &str) -> Result<()> {
    let netpols: Api<NetworkPolicy> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default();
    let netpol_list = netpols.list(&lp).await?;
    if let Some(msg) = analyze_network_policies(&netpol_list.items) {
        println!("{}", msg);
    }
    Ok(())
}

async fn check_outdated_components(client: Client, namespace: &str) -> Result<()> {
    // Here we assume Airflow webserver pods are labeled with "component=webserver"
    let lp = ListParams::default().labels("component=webserver");
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let pod_list = pods.list(&lp).await?;
    for p in pod_list.items {
        let warnings = analyze_outdated_components(&p);
        for w in warnings {
            println!("{}", w);
        }
    }
    Ok(())
}

/// The main monitoring service runs in an infinite loop, calling all checks periodically.
#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::try_default().await?;
    let namespace = "airflow"; // adjust as needed

    println!("Starting continuous Kubernetes monitoring service in namespace '{}'", namespace);

    loop {
        println!("--- Running security checks ---");

        let (res1, res2, res3, res4) = tokio::join!(
            check_insecure_workloads(client.clone(), namespace),
            check_overly_permissive_rbac(client.clone(), namespace),
            check_network_policies(client.clone(), namespace),
            check_outdated_components(client.clone(), namespace),
        );

        if let Err(e) = res1 { eprintln!("Error in insecure workloads check: {:?}", e); }
        if let Err(e) = res2 { eprintln!("Error in RBAC check: {:?}", e); }
        if let Err(e) = res3 { eprintln!("Error in network policies check: {:?}", e); }
        if let Err(e) = res4 { eprintln!("Error in outdated components check: {:?}", e); }

        println!("--- Security checks complete ---\n");

        sleep(Duration::from_secs(30)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Pod, PodSpec, Container, SecurityContext};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::api::rbac::v1::{RoleBinding, RoleRef};
    use k8s_openapi::api::networking::v1::NetworkPolicy;

    // --- Tests for analyze_pod_insecure_workloads (K01) ---

    #[test]
    fn test_pod_no_security_context() {
        // Test case 1: A pod with a container that has no security context.
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
        // Test case 2: A pod with a container that has a security context but no runAsNonRoot setting.
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
        // Test case 3: A pod with a container that explicitly sets runAsNonRoot=false and privileged=true.
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

    // --- Tests for analyze_role_binding (K03) ---

    #[test]
    fn test_role_binding_cluster_admin() {
        // Test case 1: RoleBinding with a ClusterRole named "cluster-admin"
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
        // Test case 2: RoleBinding with a ClusterRole that is not admin
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
        // Test case 3: RoleBinding with a Role (not ClusterRole) even if name contains "cluster-admin"
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

    // --- Tests for analyze_network_policies (K07) ---

    #[test]
    fn test_network_policies_empty() {
        // Test case 1: No NetworkPolicies provided.
        let policies: Vec<NetworkPolicy> = Vec::new();
        let result = analyze_network_policies(&policies);
        assert!(result.is_some());
        assert!(result.unwrap().contains("No NetworkPolicies found"));
    }

    #[test]
    fn test_network_policies_one() {
        // Test case 2: One NetworkPolicy exists.
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
        // Test case 3: Three NetworkPolicies exist.
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

    // --- Tests for analyze_outdated_components (K10) ---

    #[test]
    fn test_outdated_component_with_versioned_image() {
        // Test case 1: A pod with a container using an image tagged with a specific version.
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
        // Test case 2: A pod with a container using the "latest" tag.
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
        // Test case 3: A pod with a container that has no image set (should produce no warning).
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
}

