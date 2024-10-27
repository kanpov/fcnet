use std::net::IpAddr;

use futures_util::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::IpVersion;

use crate::{FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkObject};

use super::{use_netns_in_thread, NamespacedData};

pub(super) async fn check(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-t nat -C POSTROUTING -s {} -o {} -j MASQUERADE",
    //         namespaced_data.veth2_ip, network.iface_name
    //     ),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-C FORWARD -i {} -o {} -j ACCEPT",
    //         network.iface_name, namespaced_data.veth1_name
    //     ),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-C FORWARD -o {} -i {} -j ACCEPT",
    //         network.iface_name, namespaced_data.veth1_name
    //     ),
    // )
    // .await?;

    {
        // let iptables_path = network.iptables_path.clone();
        let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
        let veth2_name = namespaced_data.veth2_name.to_string();
        let veth2_ip = *namespaced_data.veth2_ip;
        let guest_ip = network.guest_ip;
        use_netns_in_thread(namespaced_data.netns_name.to_string(), async move {
            // run_iptables(
            //     &iptables_path,
            //     format!(
            //         "-t nat -C POSTROUTING -o {} -s {} -j SNAT --to {}",
            //         veth2_name,
            //         guest_ip,
            //         veth2_ip.address()
            //     ),
            // )
            // .await?;

            if let Some(ref forwarded_guest_ip) = forwarded_guest_ip {
                // run_iptables(
                //     &iptables_path,
                //     format!(
                //         "-t nat -C PREROUTING -i {} -d {} -j DNAT --to {}",
                //         veth2_name, forwarded_guest_ip, guest_ip
                //     ),
                // )
                // .await?;
            }

            Ok(())
        })
        .await?;
    }

    if let Some(forwarded_guest_ip) = namespaced_data.forwarded_guest_ip {
        let ip_version = match forwarded_guest_ip {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        };
        let mut route_message = None;
        let mut route_message_stream = netlink_handle.route().get(ip_version).execute();

        while let Ok(Some(current_route_message)) = route_message_stream.try_next().await {
            for attribute in &current_route_message.attributes {
                if let RouteAttribute::Destination(route_addr) = attribute {
                    let ip_addr = match route_addr {
                        RouteAddress::Inet(i) => IpAddr::V4(*i),
                        RouteAddress::Inet6(i) => IpAddr::V6(*i),
                        _ => continue,
                    };

                    if ip_addr == *forwarded_guest_ip {
                        route_message = Some(current_route_message);
                        break;
                    }
                }
            }
        }

        if route_message.is_none() {
            return Err(FirecrackerNetworkError::ObjectNotFound(FirecrackerNetworkObject::IpRoute));
        }
    }

    Ok(())
}
