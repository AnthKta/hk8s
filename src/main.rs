use hk8s::monitor::run_monitoring_service;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    run_monitoring_service().await
}
