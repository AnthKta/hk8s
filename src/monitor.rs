use anyhow::Result;
use kube::{api::{Api, ListParams}, Client};
use k8s_openapi::api::core::v1::{Pod, Node};
use k8s_openapi::api::rbac::v1::RoleBinding;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use crate::checks::{
    analyze_pod_insecure_workloads, analyze_role_binding, analyze_network_policies, analyze_outdated_components,
    analyze_supply_chain_vulnerabilities, analyze_cluster_components,
    analyze_policy_enforcement, analyze_logging_monitoring, analyze_broken_authentication, analyze_secrets_management,
};
use tokio::time::{sleep, Duration};

pub async fn check_insecure_workloads(client: Client, namespace: &str) -> Result<()> {
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

pub async fn check_overly_permissive_rbac(client: Client, namespace: &str) -> Result<()> {
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

pub async fn check_network_policies(client: Client, namespace: &str) -> Result<()> {
    let netpols: Api<NetworkPolicy> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default();
    let netpol_list = netpols.list(&lp).await?;
    if let Some(msg) = analyze_network_policies(&netpol_list.items) {
        println!("{}", msg);
    }
    Ok(())
}

pub async fn check_outdated_components(client: Client, namespace: &str) -> Result<()> {
    // We assume Airflow webserver pods are labeled with "component=webserver"
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

pub async fn check_supply_chain_vulnerabilities(client: Client, namespace: &str) -> Result<()> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default();
    let pod_list = pods.list(&lp).await?;
    for p in pod_list.items {
        let warnings = analyze_supply_chain_vulnerabilities(&p);
        for w in warnings {
            println!("{}", w);
        }
    }
    Ok(())
}

pub async fn check_policy_enforcement(client: Client) -> Result<()> {
    if let Some(msg) = analyze_policy_enforcement(client.clone()).await {
        println!("{}", msg);
    }
    Ok(())
}

pub async fn check_logging_monitoring(client: Client) -> Result<()> {
    if let Some(msg) = analyze_logging_monitoring(client.clone()).await {
        println!("{}", msg);
    }
    Ok(())
}

pub async fn check_broken_authentication(client: Client, namespace: &str) -> Result<()> {
    if let Some(msg) = analyze_broken_authentication(client.clone(), namespace).await {
        println!("{}", msg);
    }
    Ok(())
}

pub async fn check_secrets_management(client: Client, namespace: &str) -> Result<()> {
    let warnings = analyze_secrets_management(client.clone(), namespace).await;
    for w in warnings {
        println!("{}", w);
    }
    Ok(())
}

pub async fn check_cluster_components(client: Client) -> Result<()> {
    let nodes: Api<Node> = Api::all(client.clone());
    let lp = ListParams::default();
    let node_list = nodes.list(&lp).await?;
    let warnings = analyze_cluster_components(&node_list.items);
    for w in warnings {
        println!("{}", w);
    }
    Ok(())
}

pub async fn run_monitoring_service() -> Result<()> {
    let client = Client::try_default().await?;
    let namespace = "airflow"; // adjust as needed

    println!("Starting continuous Kubernetes monitoring service in namespace '{}'", namespace);

    loop {
        println!("--- Running security checks ---");

        let (res1, res2, res3, res4, res5, res6, res7, res8, res9, res10) = tokio::join!(
            check_insecure_workloads(client.clone(), namespace),
            check_overly_permissive_rbac(client.clone(), namespace),
            check_network_policies(client.clone(), namespace),
            check_outdated_components(client.clone(), namespace),
            check_supply_chain_vulnerabilities(client.clone(), namespace),
            check_policy_enforcement(client.clone()),
            check_logging_monitoring(client.clone()),
            check_broken_authentication(client.clone(), namespace),
            check_secrets_management(client.clone(), namespace),
            check_cluster_components(client.clone())
        );

        if let Err(e) = res1 { eprintln!("Error in insecure workloads check: {:?}", e); }
        if let Err(e) = res2 { eprintln!("Error in RBAC check: {:?}", e); }
        if let Err(e) = res3 { eprintln!("Error in network policies check: {:?}", e); }
        if let Err(e) = res4 { eprintln!("Error in outdated components check: {:?}", e); }
        if let Err(e) = res5 { eprintln!("Error in supply chain check: {:?}", e); }
        if let Err(e) = res6 { eprintln!("Error in policy enforcement check: {:?}", e); }
        if let Err(e) = res7 { eprintln!("Error in logging monitoring check: {:?}", e); }
        if let Err(e) = res8 { eprintln!("Error in broken authentication check: {:?}", e); }
        if let Err(e) = res9 { eprintln!("Error in secrets management check: {:?}", e); }
        if let Err(e) = res10 { eprintln!("Error in cluster components check: {:?}", e); }

        println!("--- Security checks complete ---\n");

        sleep(Duration::from_secs(30)).await;
    }
}
