use k8s_openapi::api::core::v1::{Pod, Node, ConfigMap, ServiceAccount};
use k8s_openapi::api::rbac::v1::RoleBinding;
use k8s_openapi::api::networking::v1::NetworkPolicy;

/// K01: Insecure Workload Configurations
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
                    "[K01] Pod '{}' container '{}' is an insecure container running as root",
                    pod_name, container_name
                ));
            }
        }
    }
    warnings
}

/// K02: Supply Chain Vulnerabilities
pub fn analyze_supply_chain_vulnerabilities(pod: &Pod) -> Vec<String> {
    let mut warnings = Vec::new();
    // List of allowed registry prefixes.
    let allowed_registries = vec!["docker.io", "gcr.io", "quay.io", "registry.k8s.io"];
    let pod_name = pod.metadata.name.clone().unwrap_or("<unknown>".into());
    if let Some(spec) = &pod.spec {
        for container in &spec.containers {
            if let Some(image) = &container.image {
                // If the image string contains a slash and the first part contains a dot,
                // assume it is a registry domain.
                if image.contains('/') {
                    let parts: Vec<&str> = image.split('/').collect();
                    if parts.len() > 1 && parts[0].contains('.') {
                        if !allowed_registries.iter().any(|r| parts[0].starts_with(r)) {
                            warnings.push(format!(
                                "[K02] Pod '{}' container '{}' uses untrusted registry '{}'",
                                pod_name, container.name, parts[0]
                            ));
                        }
                    }
                }
            }
        }
    }
    warnings
}

/// K03: Overly Permissive RBAC Configurations
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

/// K04: Lack of Centralized Policy Enforcement
pub async fn analyze_policy_enforcement(client: kube::Client) -> Option<String> {
    let configmaps: kube::Api<ConfigMap> = kube::Api::namespaced(client, "kube-system");
    match configmaps.get("policy-controller-config").await {
        Ok(_) => None,
        Err(_) => Some(String::from("[K04] Centralized policy enforcement ConfigMap 'policy-controller-config' not found in kube-system.")),
    }
}

/// K05: Inadequate Logging and Monitoring
pub async fn analyze_logging_monitoring(client: kube::Client) -> Option<String> {
    let configmaps: kube::Api<ConfigMap> = kube::Api::namespaced(client, "kube-system");
    match configmaps.get("audit-policy").await {
        Ok(_) => None,
        Err(_) => Some(String::from("[K05] Audit policy ConfigMap 'audit-policy' not found in kube-system. Logging and monitoring may be inadequate.")),
    }
}

/// K06: Broken Authentication Mechanisms
pub async fn analyze_broken_authentication(client: kube::Client, namespace: &str) -> Option<String> {
    let service_accounts: kube::Api<ServiceAccount> = kube::Api::namespaced(client, namespace);
    match service_accounts.get("default").await {
        Ok(sa) => {
            if let Some(secrets) = sa.secrets {
                if secrets.len() <= 1 {
                    return Some(format!("[K06] Default ServiceAccount in namespace '{}' may be using default credentials.", namespace));
                }
            } else {
                return Some(format!("[K06] Default ServiceAccount in namespace '{}' has no associated secrets.", namespace));
            }
            None
        },
        Err(_) => Some(format!("[K06] Default ServiceAccount in namespace '{}' not found.", namespace)),
    }
}

/// K07: Missing Network Segmentation Controls
pub fn analyze_network_policies(nps: &[NetworkPolicy]) -> Option<String> {
    if nps.is_empty() {
        Some(String::from(
            "[K07] No NetworkPolicies found. Consider implementing network segmentation controls.",
        ))
    } else {
        Some(format!("[K07] Found {} NetworkPolicy object(s).", nps.len()))
    }
}

/// K08: Secrets Management Failures
pub async fn analyze_secrets_management(client: kube::Client, namespace: &str) -> Vec<String> {
    let secrets_api: kube::Api<k8s_openapi::api::core::v1::Secret> = kube::Api::namespaced(client, namespace);
    let lp = kube::api::ListParams::default();
    let mut warnings = Vec::new();
    if let Ok(secret_list) = secrets_api.list(&lp).await {
        for s in secret_list.items {
            if let Some(name) = s.metadata.name {
                let lower = name.to_lowercase();
                if lower.contains("password") || lower.contains("aws_access_key") || lower.contains("secret") {
                    warnings.push(format!(
                        "[K08] Secret '{}' in namespace '{}' may contain sensitive data. Ensure it is properly managed.",
                        name, namespace
                    ));
                }
            }
        }
    }
    warnings
}

/// K09: Misconfigured Cluster Components
pub fn analyze_cluster_components(nodes: &[Node]) -> Vec<String> {
    let mut warnings = Vec::new();
    for node in nodes {
        let node_name = node.metadata.name.clone().unwrap_or("<unknown>".into());
        if let Some(annotations) = &node.metadata.annotations {
            if let Some(value) = annotations.get("kubelet.anonymous-auth") {
                if value == "true" {
                    warnings.push(format!(
                        "[K09] Node '{}' has kubelet.anonymous-auth set to true. This is insecure.",
                        node_name
                    ));
                }
            }
        }
    }
    warnings
}

/// K10: Outdated and Vulnerable Components (simplified)
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

