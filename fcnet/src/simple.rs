use tokio_tun::TunBuilder;

use crate::{get_link_index, run_iptables, FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkOperation};

pub async fn run(
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
    operation: FirecrackerNetworkOperation,
) -> Result<(), FirecrackerNetworkError> {
    match operation {
        FirecrackerNetworkOperation::Add => add(network, netlink_handle).await,
        FirecrackerNetworkOperation::Check => check(network, netlink_handle).await,
        FirecrackerNetworkOperation::Delete => delete(network, netlink_handle).await,
    }
}

async fn add(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    TunBuilder::new()
        .name(&network.tap_name)
        .tap()
        .persist()
        .up()
        .try_build()
        .map_err(FirecrackerNetworkError::TapDeviceError)?;
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await?;
    netlink_handle
        .address()
        .add(tap_idx, network.tap_ip.address(), network.tap_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    run_iptables(
        &network.iptables_path,
        format!("-t nat -A POSTROUTING -o {} -j MASQUERADE", network.iface_name),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!("-A FORWARD -i {} -o {} -j ACCEPT", network.tap_name, network.iface_name),
    )
    .await
}

async fn delete(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await?;
    netlink_handle
        .link()
        .del(tap_idx)
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    run_iptables(
        &network.iptables_path,
        format!("-t nat -D POSTROUTING -o {} -j MASQUERADE", network.iface_name),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        "-D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!("-D FORWARD -i {} -o {} -j ACCEPT", network.tap_name, network.iface_name),
    )
    .await
}

async fn check(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    get_link_index(network.tap_name.clone(), &netlink_handle).await?;

    run_iptables(
        &network.iptables_path,
        format!("-t nat -C POSTROUTING -o {} -j MASQUERADE", network.iface_name),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        "-C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!("-C FORWARD -i {} -o {} -j ACCEPT", network.tap_name, network.iface_name),
    )
    .await
}
