use anyhow::Result;
use kube::{api::{Api, ListParams}, Client};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::rbac::v1::RoleBinding;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use crate::checks::{analyze_pod_insecure_workloads, analyze_role_binding, analyze_network_policies, analyze_outdated_components};
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
    // For this demo, we assume Airflow webserver pods are labeled with "component=webserver"
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

pub async fn run_monitoring_service() -> Result<()> {
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

