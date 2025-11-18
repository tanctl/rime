use std::{env, time::Duration};

use rime_lightclient::rpc::{GrpcRpcClient, RpcClient, RpcConfig};

fn rpc_tests_enabled() -> bool {
    env::var("LIGHTWALLETD_RPC_TESTS")
        .map(|v| v != "0")
        .unwrap_or(false)
}

#[tokio::test]
async fn fetch_latest_block_and_range() {
    if !rpc_tests_enabled() {
        eprintln!("skipping live rpc tests; set LIGHTWALLETD_RPC_TESTS=1 to enable");
        return;
    }

    let config = RpcConfig {
        timeout: Duration::from_secs(15),
        ..RpcConfig::default()
    };
    let client = GrpcRpcClient::connect(config.clone())
        .await
        .expect("connects to lightwalletd");

    let latest = client.get_latest_block().await.expect("latest block");
    assert!(latest.height > 0, "latest height should be nonzero");

    let height = latest.height as u32;
    let block = client.get_block(height).await.expect("fetch block");
    assert_eq!(block.height as u32, height);

    let start = height.saturating_sub(1);
    let range = client
        .get_block_range(start, height)
        .await
        .expect("fetch block range");
    assert!(!range.is_empty(), "block range should not be empty");
    assert!(
        range.first().unwrap().height as u32 >= start,
        "range should start at or after requested start"
    );

    let tree_height = height.saturating_sub(1);
    if tree_height > 0 {
        let tree = client
            .get_tree_state(tree_height)
            .await
            .expect("fetch tree state");
        assert_eq!(tree.height, tree_height as u64);
    }
}
