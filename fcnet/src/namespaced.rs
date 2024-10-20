use std::{net::IpAddr, os::fd::AsRawFd};

use cidr::IpInet;
use futures_util::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::IpVersion;
use tokio_tun::TunBuilder;

use crate::{
    get_link_index, netns::NetNs, run_iptables, use_netns_in_thread, FirecrackerNetwork, FirecrackerNetworkError,
    FirecrackerNetworkOperation, FirecrackerNetworkType,
};

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

async fn add(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    outer_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    outer_handle
        .link()
        .add()
        .veth(namespaced_data.veth1_name.to_string(), namespaced_data.veth2_name.to_string())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let veth1_idx = get_link_index(namespaced_data.veth1_name.to_string(), &outer_handle).await?;
    outer_handle
        .address()
        .add(
            veth1_idx,
            namespaced_data.veth1_ip.address(),
            namespaced_data.veth1_ip.network_length(),
        )
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
    outer_handle
        .link()
        .set(veth1_idx)
        .up()
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
    outer_handle
        .link()
        .set(get_link_index(namespaced_data.veth2_name.to_string(), &outer_handle).await?)
        .setns_by_fd(
            NetNs::new(&namespaced_data.netns_name)
                .map_err(FirecrackerNetworkError::NetnsError)?
                .file()
                .as_raw_fd(),
        )
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    {
        let tap_name = network.tap_name.clone();
        let tap_ip = network.tap_ip.clone();
        let iptables_path = network.iptables_path.clone();
        let veth2_name = namespaced_data.veth2_name.to_string();
        let veth2_ip = *namespaced_data.veth2_ip;
        let guest_ip = *namespaced_data.guest_ip;
        let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
        use_netns_in_thread(namespaced_data.netns_name.to_string(), async move {
            TunBuilder::new()
                .name(&tap_name)
                .tap()
                .persist()
                .up()
                .try_build()
                .map_err(FirecrackerNetworkError::TapDeviceError)?;
            let (connection, inner_handle, _) = rtnetlink::new_connection().map_err(FirecrackerNetworkError::IoError)?;
            tokio::task::spawn(connection);

            let veth2_idx = get_link_index(veth2_name.clone(), &inner_handle).await?;
            inner_handle
                .address()
                .add(veth2_idx, veth2_ip.address(), veth2_ip.network_length())
                .execute()
                .await
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
            inner_handle
                .link()
                .set(veth2_idx)
                .up()
                .execute()
                .await
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

            match veth2_ip {
                IpInet::V4(ref veth1_ip) => inner_handle
                    .route()
                    .add()
                    .v4()
                    .gateway(veth1_ip.address())
                    .execute()
                    .await
                    .map_err(FirecrackerNetworkError::NetlinkOperationError)?,
                IpInet::V6(ref veth1_ip) => inner_handle
                    .route()
                    .add()
                    .v6()
                    .gateway(veth1_ip.address())
                    .execute()
                    .await
                    .map_err(FirecrackerNetworkError::NetlinkOperationError)?,
            }

            let tap_idx = get_link_index(tap_name, &inner_handle).await?;
            inner_handle
                .address()
                .add(tap_idx, tap_ip.address(), tap_ip.network_length())
                .execute()
                .await
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
            inner_handle
                .link()
                .set(tap_idx)
                .up()
                .execute()
                .await
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

            run_iptables(
                &iptables_path,
                format!(
                    "-t nat -A POSTROUTING -o {} -s {} -j SNAT --to {}",
                    veth2_name,
                    guest_ip,
                    veth2_ip.address()
                ),
            )
            .await?;

            if let Some(forwarded_guest_ip) = forwarded_guest_ip {
                run_iptables(
                    &iptables_path,
                    format!(
                        "-t nat -A PREROUTING -i {} -d {} -j DNAT --to {}",
                        veth2_name, forwarded_guest_ip, guest_ip
                    ),
                )
                .await?;
            }

            Ok(())
        })
        .await?;
    }

    run_iptables(
        &network.iptables_path,
        format!(
            "-t nat -A POSTROUTING -s {} -o {} -j MASQUERADE",
            namespaced_data.veth2_ip, network.iface_name
        ),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!(
            "-A FORWARD -i {} -o {} -j ACCEPT",
            network.iface_name, namespaced_data.veth1_name
        ),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!(
            "-A FORWARD -o {} -i {} -j ACCEPT",
            network.iface_name, namespaced_data.veth1_name
        ),
    )
    .await?;

    if let Some(forwarded_guest_ip) = namespaced_data.forwarded_guest_ip {
        match forwarded_guest_ip {
            IpAddr::V4(v4) => outer_handle
                .route()
                .add()
                .v4()
                .destination_prefix(*v4, 32)
                .gateway(match namespaced_data.veth2_ip.address() {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => panic!("Veth2 IP and host forward IP must be both v4, or both v6"),
                })
                .execute()
                .await
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?,
            IpAddr::V6(v6) => outer_handle
                .route()
                .add()
                .v6()
                .destination_prefix(*v6, 128)
                .gateway(match namespaced_data.veth2_ip.address() {
                    IpAddr::V4(_) => panic!("Veth2 IP and host forward IP must be both v4, or both v6"),
                    IpAddr::V6(v6) => v6,
                })
                .execute()
                .await
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?,
        };
    }

    Ok(())
}

async fn delete(namespaced_data: NamespacedData<'_>, network: &FirecrackerNetwork) -> Result<(), FirecrackerNetworkError> {
    NetNs::get(&namespaced_data.netns_name)
        .map_err(FirecrackerNetworkError::NetnsError)?
        .remove()
        .map_err(FirecrackerNetworkError::NetnsError)?;

    run_iptables(
        &network.iptables_path,
        format!(
            "-t nat -D POSTROUTING -s {} -o {} -j MASQUERADE",
            namespaced_data.veth2_ip, network.iface_name
        ),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!(
            "-D FORWARD -i {} -o {} -j ACCEPT",
            network.iface_name, namespaced_data.veth1_name
        ),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!(
            "-D FORWARD -o {} -i {} -j ACCEPT",
            network.iface_name, namespaced_data.veth1_name
        ),
    )
    .await
}

async fn check(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    run_iptables(
        &network.iptables_path,
        format!(
            "-t nat -C POSTROUTING -s {} -o {} -j MASQUERADE",
            namespaced_data.veth2_ip, network.iface_name
        ),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!(
            "-C FORWARD -i {} -o {} -j ACCEPT",
            network.iface_name, namespaced_data.veth1_name
        ),
    )
    .await?;
    run_iptables(
        &network.iptables_path,
        format!(
            "-C FORWARD -o {} -i {} -j ACCEPT",
            network.iface_name, namespaced_data.veth1_name
        ),
    )
    .await?;

    {
        let iptables_path = network.iptables_path.clone();
        let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
        let veth2_name = namespaced_data.veth2_name.to_string();
        let veth2_ip = *namespaced_data.veth2_ip;
        let guest_ip = *namespaced_data.guest_ip;
        use_netns_in_thread(namespaced_data.netns_name.to_string(), async move {
            run_iptables(
                &iptables_path,
                format!(
                    "-t nat -C POSTROUTING -o {} -s {} -j SNAT --to {}",
                    veth2_name,
                    guest_ip,
                    veth2_ip.address()
                ),
            )
            .await?;

            if let Some(ref forwarded_guest_ip) = forwarded_guest_ip {
                run_iptables(
                    &iptables_path,
                    format!(
                        "-t nat -C PREROUTING -i {} -d {} -j DNAT --to {}",
                        veth2_name, forwarded_guest_ip, guest_ip
                    ),
                )
                .await?;
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
            return Err(FirecrackerNetworkError::RouteNotFound);
        }
    }

    Ok(())
}
