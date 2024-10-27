use std::net::IpAddr;

use cidr::IpInet;

use crate::{FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkOperation, FirecrackerNetworkType};

mod add;
use add::add;
mod check;
use check::check;
mod delete;
use delete::delete;

struct NamespacedData<'a> {
    netns_name: &'a str,
    veth1_name: &'a str,
    veth2_name: &'a str,
    veth1_ip: &'a IpInet,
    veth2_ip: &'a IpInet,
    guest_ip: &'a IpAddr,
    forwarded_guest_ip: &'a Option<IpAddr>,
}

pub async fn run(
    operation: FirecrackerNetworkOperation,
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    let namespaced_data = match network.network_type {
        #[cfg(feature = "simple")]
        FirecrackerNetworkType::Simple => unreachable!(),
        FirecrackerNetworkType::Namespaced {
            ref netns_name,
            ref veth1_name,
            ref veth2_name,
            ref veth1_ip,
            ref veth2_ip,
            ref guest_ip,
            ref forwarded_guest_ip,
        } => NamespacedData {
            netns_name,
            veth1_name,
            veth2_name,
            veth1_ip,
            veth2_ip,
            guest_ip,
            forwarded_guest_ip,
        },
    };

    match operation {
        FirecrackerNetworkOperation::Add => add(namespaced_data, network, netlink_handle).await,
        FirecrackerNetworkOperation::Check => check(namespaced_data, network, netlink_handle).await,
        FirecrackerNetworkOperation::Delete => delete(namespaced_data, network).await,
    }
}
