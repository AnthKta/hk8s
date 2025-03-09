use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::rbac::v1::RoleBinding;
use k8s_openapi::api::networking::v1::NetworkPolicy;

/// K01: Insecure Workload Configurations
/// Analyze a Pod and return warning messages based on container security context settings.
pub fn analyze_pod_insecure_workloads(pod: &Pod) -> Vec<String> {
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
/// Analyze a RoleBinding and return a warning if its role_ref indicates a high-privilege binding.
pub fn analyze_role_binding(rb: &RoleBinding) -> Option<String> {
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
/// Analyze a slice of NetworkPolicy objects and return a message.
pub fn analyze_network_policies(nps: &[NetworkPolicy]) -> Option<String> {
    if nps.is_empty() {
        Some(String::from(
            "[K07] No NetworkPolicies found. Consider implementing network segmentation controls.",
        ))
    } else {
        Some(format!("[K07] Found {} NetworkPolicy object(s).", nps.len()))
    }
}

/// K10: Outdated and Vulnerable Components (simplified)
/// For each container in a Pod, return a message with its image.
pub fn analyze_outdated_components(pod: &Pod) -> Vec<String> {
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

