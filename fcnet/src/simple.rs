use std::sync::Arc;

use tokio_tun::TunBuilder;

use crate::{get_link_index, FirecrackerNetworkError, FirecrackerNetworkInner};

pub async fn add(
    network: Arc<FirecrackerNetworkInner>,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    TunBuilder::new()
        .name(&network.tap_name)
        .tap()
        .persist()
        .up()
        .try_build()
        .map_err(FirecrackerNetworkError::TapDeviceError)?;
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await;
    netlink_handle
        .address()
        .add(tap_idx, network.tap_ip.address(), network.tap_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    network
        .run_iptables(format!("-t nat -A POSTROUTING -o {} -j MASQUERADE", network.iface_name))
        .await?;
    network
        .run_iptables("-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string())
        .await?;
    network
        .run_iptables(format!(
            "-A FORWARD -i {} -o {} -j ACCEPT",
            network.tap_name, network.iface_name
        ))
        .await
}

pub async fn delete(
    network: Arc<FirecrackerNetworkInner>,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await;
    netlink_handle
        .link()
        .del(tap_idx)
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    network
        .run_iptables(format!("-t nat -D POSTROUTING -o {} -j MASQUERADE", network.iface_name))
        .await?;
    network
        .run_iptables("-D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string())
        .await?;
    network
        .run_iptables(format!(
            "-D FORWARD -i {} -o {} -j ACCEPT",
            network.tap_name, network.iface_name
        ))
        .await
}

pub async fn check(
    network: Arc<FirecrackerNetworkInner>,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    get_link_index(network.tap_name.clone(), &netlink_handle).await;

    network
        .run_iptables(format!("-t nat -C POSTROUTING -o {} -j MASQUERADE", network.iface_name))
        .await?;
    network
        .run_iptables("-C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string())
        .await?;
    network
        .run_iptables(format!(
            "-C FORWARD -i {} -o {} -j ACCEPT",
            network.tap_name, network.iface_name
        ))
        .await
}
