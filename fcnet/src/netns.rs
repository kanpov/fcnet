use std::{net::IpAddr, os::fd::AsRawFd, sync::Arc};

use cidr::IpInet;
use futures_util::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use netns_rs::NetNs;
use rtnetlink::IpVersion;
use tokio_tun::TunBuilder;

use crate::{
    get_link_index, run_iptables, use_netns_in_thread, FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkOperation,
    FirecrackerNetworkType,
};

pub struct NamespacedData {
    netns_name: String,
    veth1_name: String,
    veth2_name: String,
    veth1_ip: IpInet,
    veth2_ip: IpInet,
    guest_ip: IpAddr,
    forwarded_guest_ip: Option<IpAddr>,
}

pub async fn run(
    operation: FirecrackerNetworkOperation,
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    fn make_namespaced_data(network: &FirecrackerNetwork) -> Arc<NamespacedData> {
        Arc::new(match network.network_type.clone() {
            #[cfg(feature = "simple")]
            FirecrackerNetworkType::Simple => unreachable!(),
            FirecrackerNetworkType::Namespaced {
                netns_name,
                veth1_name,
                veth2_name,
                veth1_ip,
                veth2_ip,
                guest_ip,
                forwarded_guest_ip,
            } => NamespacedData {
                netns_name,
                veth1_name,
                veth2_name,
                veth1_ip,
                veth2_ip,
                guest_ip,
                forwarded_guest_ip,
            },
        })
    }

    match operation {
        FirecrackerNetworkOperation::Add => add(make_namespaced_data(network), network, netlink_handle).await,
        FirecrackerNetworkOperation::Check => check(make_namespaced_data(network), network, netlink_handle).await,
        FirecrackerNetworkOperation::Delete => delete(make_namespaced_data(network), network).await,
    }
}

async fn add(
    namespaced_data: Arc<NamespacedData>,
    network: &FirecrackerNetwork,
    outer_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    outer_handle
        .link()
        .add()
        .veth(namespaced_data.veth1_name.clone(), namespaced_data.veth2_name.clone())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let veth1_idx = get_link_index(namespaced_data.veth1_name.clone(), &outer_handle).await?;
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
        .set(get_link_index(namespaced_data.veth2_name.clone(), &outer_handle).await?)
        .setns_by_fd(
            NetNs::new(&namespaced_data.netns_name)
                .map_err(FirecrackerNetworkError::NetnsError)?
                .file()
                .as_raw_fd(),
        )
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let cloned_tap_name = network.tap_name.clone();
    let cloned_tap_ip = network.tap_ip.clone();
    let cloned_iptables_path = network.iptables_path.clone();
    use_netns_in_thread(
        namespaced_data.netns_name.clone(),
        namespaced_data.clone(),
        move |namespaced_data| async move {
            TunBuilder::new()
                .name(&cloned_tap_name)
                .tap()
                .persist()
                .up()
                .try_build()
                .map_err(FirecrackerNetworkError::TapDeviceError)?;
            let (connection, inner_handle, _) = rtnetlink::new_connection().map_err(FirecrackerNetworkError::IoError)?;
            tokio::task::spawn(connection);

            let veth2_idx = get_link_index(namespaced_data.veth2_name.clone(), &inner_handle).await?;
            inner_handle
                .address()
                .add(
                    veth2_idx,
                    namespaced_data.veth2_ip.address(),
                    namespaced_data.veth2_ip.network_length(),
                )
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

            match namespaced_data.veth1_ip {
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

            let tap_idx = get_link_index(cloned_tap_name, &inner_handle).await?;
            inner_handle
                .address()
                .add(tap_idx, cloned_tap_ip.address(), cloned_tap_ip.network_length())
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
                &cloned_iptables_path,
                format!(
                    "-t nat -A POSTROUTING -o {} -s {} -j SNAT --to {}",
                    namespaced_data.veth2_name,
                    namespaced_data.guest_ip,
                    namespaced_data.veth2_ip.address()
                ),
            )
            .await?;

            if let Some(forwarded_guest_ip) = namespaced_data.forwarded_guest_ip {
                run_iptables(
                    &cloned_iptables_path,
                    format!(
                        "-t nat -A PREROUTING -i {} -d {} -j DNAT --to {}",
                        namespaced_data.veth2_name, forwarded_guest_ip, namespaced_data.guest_ip
                    ),
                )
                .await?;
            }

            Ok(())
        },
    )
    .await?;

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
                .destination_prefix(v4, 32)
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
                .destination_prefix(v6, 128)
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

async fn delete(namespaced_data: Arc<NamespacedData>, network: &FirecrackerNetwork) -> Result<(), FirecrackerNetworkError> {
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
    namespaced_data: Arc<NamespacedData>,
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

    let cloned_iptables_path = network.iptables_path.clone();
    use_netns_in_thread(
        namespaced_data.netns_name.clone(),
        namespaced_data.clone(),
        |namespaced_data| async move {
            run_iptables(
                &cloned_iptables_path,
                format!(
                    "-t nat -C POSTROUTING -o {} -s {} -j SNAT --to {}",
                    namespaced_data.veth2_name,
                    namespaced_data.guest_ip,
                    namespaced_data.veth2_ip.address()
                ),
            )
            .await?;

            if let Some(ref forwarded_guest_ip) = namespaced_data.forwarded_guest_ip {
                run_iptables(
                    &cloned_iptables_path,
                    format!(
                        "-t nat -C PREROUTING -i {} -d {} -j DNAT --to {}",
                        namespaced_data.veth2_name, forwarded_guest_ip, namespaced_data.guest_ip
                    ),
                )
                .await?;
            }

            Ok(())
        },
    )
    .await?;

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

                    if ip_addr == forwarded_guest_ip {
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
