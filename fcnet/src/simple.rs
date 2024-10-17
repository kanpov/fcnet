use tokio_tun::TunBuilder;

use crate::{get_link_index, FirecrackerNetwork};

pub async fn add_without_netns(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) {
    TunBuilder::new()
        .name(&network.tap_name)
        .tap()
        .persist()
        .up()
        .try_build()
        .expect("Could not create tap device");
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await;
    netlink_handle
        .address()
        .add(tap_idx, network.tap_ip.address(), network.tap_ip.network_length())
        .execute()
        .await
        .expect("Could not assign IP to tap device");

    network
        .run_iptables(format!("-t nat -A POSTROUTING -o {} -j MASQUERADE", network.iface_name))
        .await;
    network
        .run_iptables("-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string())
        .await;
    network
        .run_iptables(format!(
            "-A FORWARD -i {} -o {} -j ACCEPT",
            network.tap_name, network.iface_name
        ))
        .await;
}

async fn del_without_netns(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) {
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await;
    netlink_handle
        .link()
        .del(tap_idx)
        .execute()
        .await
        .expect("Could not delete tap device");

    network
        .run_iptables(format!("-t nat -D POSTROUTING -o {} -j MASQUERADE", network.iface_name))
        .await;
    network
        .run_iptables("-D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string())
        .await;
    network
        .run_iptables(format!(
            "-D FORWARD -i {} -o {} -j ACCEPT",
            network.tap_name, network.iface_name
        ))
        .await;
}

async fn check_without_netns(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) {
    get_link_index(network.tap_name.clone(), &netlink_handle).await;

    network
        .run_iptables(format!("-t nat -C POSTROUTING -o {} -j MASQUERADE", network.iface_name))
        .await;
    network
        .run_iptables("-C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string())
        .await;
    network
        .run_iptables(format!(
            "-C FORWARD -i {} -o {} -j ACCEPT",
            network.tap_name, network.iface_name
        ))
        .await;
}
