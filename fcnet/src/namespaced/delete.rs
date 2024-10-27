use crate::{netns::NetNs, FirecrackerNetwork, FirecrackerNetworkError};

use super::NamespacedData;

pub(super) async fn delete(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
) -> Result<(), FirecrackerNetworkError> {
    NetNs::get(&namespaced_data.netns_name)
        .map_err(FirecrackerNetworkError::NetnsError)?
        .remove()
        .map_err(FirecrackerNetworkError::NetnsError)?;

    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-t nat -D POSTROUTING -s {} -o {} -j MASQUERADE",
    //         namespaced_data.veth2_ip, network.iface_name
    //     ),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-D FORWARD -i {} -o {} -j ACCEPT",
    //         network.iface_name, namespaced_data.veth1_name
    //     ),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-D FORWARD -o {} -i {} -j ACCEPT",
    //         network.iface_name, namespaced_data.veth1_name
    //     ),
    // )
    // .await
    Ok(())
}
