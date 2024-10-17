use std::{future::Future, net::IpAddr, os::fd::AsRawFd};

use cidr::IpInet;
use futures_util::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use netns_rs::NetNs;
use rtnetlink::IpVersion;
use tokio_tun::TunBuilder;

use crate::{get_link_index, FirecrackerNetwork};

pub struct NetNsMetadata {
    pub netns_name: String,
    pub veth1_name: String,
    pub veth2_name: String,
    pub veth1_ip: IpInet,
    pub veth2_ip: IpInet,
    pub guest_ip: IpAddr,
    pub forwarded_guest_ip: Option<IpAddr>,
}

pub async fn add_with_netns(network: &FirecrackerNetwork, outer_handle: rtnetlink::Handle, netns_metadata: NetNsMetadata) {
    let netns = NetNs::new(netns_metadata.netns_name).expect("Could not create netns");

    outer_handle
        .link()
        .add()
        .veth(netns_metadata.veth1_name.clone(), netns_metadata.veth2_name.clone())
        .execute()
        .await
        .expect("Could not create veth pair");
    let veth1_idx = get_link_index(netns_metadata.veth1_name.clone(), &outer_handle).await;
    outer_handle
        .address()
        .add(
            veth1_idx,
            netns_metadata.veth1_ip.address(),
            netns_metadata.veth1_ip.network_length(),
        )
        .execute()
        .await
        .expect("Could not set veth1 IP");
    outer_handle
        .link()
        .set(veth1_idx)
        .up()
        .execute()
        .await
        .expect("Could not up veth1");
    outer_handle
        .link()
        .set(get_link_index(netns_metadata.veth2_name.clone(), &outer_handle).await)
        .setns_by_fd(netns.file().as_raw_fd())
        .execute()
        .await
        .expect("Could not move veth2 into netns");

    netns
        .run_async(|| async {
            TunBuilder::new()
                .name(&network.tap_name)
                .tap()
                .persist()
                .up()
                .try_build()
                .expect("Could not create tap device in netns");
            let (conn, inner_handle, _) = rtnetlink::new_connection().expect("Could not connect to rtnetlink in netns");
            tokio::spawn(conn);

            let veth2_idx = get_link_index(netns_metadata.veth2_name.clone(), &inner_handle).await;
            inner_handle
                .address()
                .add(
                    veth2_idx,
                    netns_metadata.veth2_ip.address(),
                    netns_metadata.veth2_ip.network_length(),
                )
                .execute()
                .await
                .expect("Could not set veth2 IP in netns");
            inner_handle
                .link()
                .set(veth2_idx)
                .up()
                .execute()
                .await
                .expect("Could not up veth2 in netns");

            match netns_metadata.veth1_ip {
                IpInet::V4(ref veth1_ip) => inner_handle
                    .route()
                    .add()
                    .v4()
                    .gateway(veth1_ip.address())
                    .execute()
                    .await
                    .expect("Could not add default route in netns"),
                IpInet::V6(ref veth1_ip) => inner_handle
                    .route()
                    .add()
                    .v6()
                    .gateway(veth1_ip.address())
                    .execute()
                    .await
                    .expect("Could not add default route in netns"),
            }

            let tap_idx = get_link_index(network.tap_name.clone(), &inner_handle).await;
            inner_handle
                .address()
                .add(tap_idx, network.tap_ip.address(), network.tap_ip.network_length())
                .execute()
                .await
                .expect("Could not set tap IP in netns");
            inner_handle
                .link()
                .set(tap_idx)
                .up()
                .execute()
                .await
                .expect("Could not up tap in netns");

            network
                .run_iptables(format!(
                    "-t nat -A POSTROUTING -o {} -s {} -j SNAT --to {}",
                    netns_metadata.veth2_name,
                    netns_metadata.guest_ip,
                    netns_metadata.veth2_ip.address()
                ))
                .await;

            if let Some(forwarded_guest_ip) = netns_metadata.forwarded_guest_ip {
                network
                    .run_iptables(format!(
                        "-t nat -A PREROUTING -i {} -d {} -j DNAT --to {}",
                        netns_metadata.veth2_name, forwarded_guest_ip, netns_metadata.guest_ip
                    ))
                    .await;
            }
        })
        .await;

    network
        .run_iptables(format!(
            "-t nat -A POSTROUTING -s {} -o {} -j MASQUERADE",
            netns_metadata.veth2_ip, network.iface_name
        ))
        .await;
    network
        .run_iptables(format!(
            "-A FORWARD -i {} -o {} -j ACCEPT",
            network.iface_name, netns_metadata.veth1_name
        ))
        .await;
    network
        .run_iptables(format!(
            "-A FORWARD -o {} -i {} -j ACCEPT",
            network.iface_name, netns_metadata.veth1_name
        ))
        .await;

    if let Some(forwarded_guest_ip) = netns_metadata.forwarded_guest_ip {
        match forwarded_guest_ip {
            IpAddr::V4(v4) => {
                outer_handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix(v4, 32)
                    .gateway(match netns_metadata.veth2_ip.address() {
                        IpAddr::V4(v4) => v4,
                        IpAddr::V6(_) => panic!("Veth2 IP and host forward IP must be both v4, or both v6"),
                    })
                    .execute()
                    .await
                    .expect("Could not create forwarding route");
            }
            IpAddr::V6(v6) => outer_handle
                .route()
                .add()
                .v6()
                .destination_prefix(v6, 128)
                .gateway(match netns_metadata.veth2_ip.address() {
                    IpAddr::V4(_) => panic!("Veth2 IP and host forward IP must be both v4, or both v6"),
                    IpAddr::V6(v6) => v6,
                })
                .execute()
                .await
                .expect("Could not create forwarding route"),
        };
    }
}

async fn del_with_netns(network: &FirecrackerNetwork, netns_metadata: NetNsMetadata) {
    NetNs::get(netns_metadata.netns_name)
        .expect("Could not get netns")
        .remove()
        .expect("Could not remove netns");

    network
        .run_iptables(format!(
            "-t nat -D POSTROUTING -s {} -o {} -j MASQUERADE",
            netns_metadata.veth2_ip, network.iface_name
        ))
        .await;
    network
        .run_iptables(format!(
            "-D FORWARD -i {} -o {} -j ACCEPT",
            network.iface_name, netns_metadata.veth1_name
        ))
        .await;
    network
        .run_iptables(format!(
            "-D FORWARD -o {} -i {} -j ACCEPT",
            network.iface_name, netns_metadata.veth1_name
        ))
        .await;
}

async fn check_with_netns(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle, netns_metadata: NetNsMetadata) {
    let netns = NetNs::get(netns_metadata.netns_name).expect("Could not get netns");

    network
        .run_iptables(format!(
            "-t nat -C POSTROUTING -s {} -o {} -j MASQUERADE",
            netns_metadata.veth2_ip, network.iface_name
        ))
        .await;
    network
        .run_iptables(format!(
            "-C FORWARD -i {} -o {} -j ACCEPT",
            network.iface_name, netns_metadata.veth1_name
        ))
        .await;
    network
        .run_iptables(format!(
            "-C FORWARD -o {} -i {} -j ACCEPT",
            network.iface_name, netns_metadata.veth1_name
        ))
        .await;

    netns
        .run_async(|| async {
            network
                .run_iptables(format!(
                    "-t nat -C POSTROUTING -o {} -s {} -j SNAT --to {}",
                    netns_metadata.veth2_name,
                    netns_metadata.guest_ip,
                    netns_metadata.veth2_ip.address()
                ))
                .await;

            if let Some(ref forwarded_guest_ip) = netns_metadata.forwarded_guest_ip {
                network
                    .run_iptables(format!(
                        "-t nat -C PREROUTING -i {} -d {} -j DNAT --to {}",
                        netns_metadata.veth2_name, forwarded_guest_ip, netns_metadata.guest_ip
                    ))
                    .await;
            }
        })
        .await;

    if let Some(forwarded_guest_ip) = netns_metadata.forwarded_guest_ip {
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

        route_message.expect("Could not find expected forwarding route");
    }
}

trait AsyncNetnsRun {
    fn run_async<F, Fut>(&self, closure: F) -> impl Future<Output = ()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>;
}

impl AsyncNetnsRun for NetNs {
    async fn run_async<F, Fut>(&self, closure: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        let prev_netns = netns_rs::get_from_current_thread().expect("Could not get prev netns");
        self.enter().expect("Could not enter new netns");
        closure().await;
        prev_netns.enter().expect("Could not enter prev netns");
    }
}
