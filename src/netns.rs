use std::{future::Future, net::IpAddr, os::fd::AsRawFd};

use cidr::IpInet;
use futures::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use netns_rs::NetNs;
use rtnetlink::IpVersion;
use tokio_tun::TunBuilder;

use crate::{get_link_index, run_iptables, Cli};

pub struct NetNsMetadata {
    pub netns_name: String,
    pub veth1_name: String,
    pub veth2_name: String,
    pub veth1_ip: IpInet,
    pub veth2_ip: IpInet,
    pub forward: Option<(IpAddr, IpAddr)>,
}

pub async fn run(cli: Cli, netlink_handle: rtnetlink::Handle, netns_metadata: NetNsMetadata) {
    if cli.operation_group.add {
        add_with_netns(cli, netlink_handle, netns_metadata).await;
    } else if cli.operation_group.del {
        del_with_netns(cli, netns_metadata).await;
    } else {
        check_with_netns(cli, netlink_handle, netns_metadata).await;
    }
}

async fn add_with_netns(cli: Cli, outer_handle: rtnetlink::Handle, netns_metadata: NetNsMetadata) {
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
                .name(&cli.tap_name)
                .tap(true)
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
                IpInet::V4(ref ipv4) => inner_handle
                    .route()
                    .add()
                    .v4()
                    .gateway(ipv4.address())
                    .execute()
                    .await
                    .expect("Could not add default route in netns"),
                IpInet::V6(ref ipv6) => inner_handle
                    .route()
                    .add()
                    .v6()
                    .gateway(ipv6.address())
                    .execute()
                    .await
                    .expect("Could not add default route in netns"),
            }

            let tap_idx = get_link_index(cli.tap_name.clone(), &inner_handle).await;
            inner_handle
                .address()
                .add(tap_idx, cli.tap_ip.address(), cli.tap_ip.network_length())
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

            run_iptables(
                &cli,
                format!("-t nat -A POSTROUTING -o {} -j MASQUERADE", netns_metadata.veth2_name),
            )
            .await;
            run_iptables(
                &cli,
                "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
            )
            .await;
            run_iptables(
                &cli,
                format!("-A FORWARD -i {} -o {} -j ACCEPT", cli.tap_name, netns_metadata.veth2_name),
            )
            .await;

            if let Some((ref host_ip, ref guest_ip)) = netns_metadata.forward {
                run_iptables(
                    &cli,
                    format!(
                        "-t nat -A PREROUTING -i {} -d {} -j DNAT --to {}",
                        netns_metadata.veth2_name, host_ip, guest_ip
                    ),
                )
                .await;
            }
        })
        .await;

    run_iptables(
        &cli,
        format!(
            "-t nat -A POSTROUTING -s {} -o {} -j MASQUERADE",
            netns_metadata.veth2_ip, cli.iface_name
        ),
    )
    .await;
    run_iptables(
        &cli,
        format!("-A FORWARD -i {} -o {} -j ACCEPT", cli.iface_name, netns_metadata.veth1_name),
    )
    .await;
    run_iptables(
        &cli,
        format!("-A FORWARD -o {} -i {} -j ACCEPT", cli.iface_name, netns_metadata.veth1_name),
    )
    .await;

    if let Some((host_ip, _)) = netns_metadata.forward {
        match host_ip {
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

async fn del_with_netns(cli: Cli, netns_metadata: NetNsMetadata) {
    NetNs::get(netns_metadata.netns_name)
        .expect("Could not get netns")
        .remove()
        .expect("Could not remove netns");

    run_iptables(
        &cli,
        format!(
            "-t nat -D POSTROUTING -s {} -o {} -j MASQUERADE",
            netns_metadata.veth2_ip, cli.iface_name
        ),
    )
    .await;
    run_iptables(
        &cli,
        format!("-D FORWARD -i {} -o {} -j ACCEPT", cli.iface_name, netns_metadata.veth1_name),
    )
    .await;
    run_iptables(
        &cli,
        format!("-D FORWARD -o {} -i {} -j ACCEPT", cli.iface_name, netns_metadata.veth1_name),
    )
    .await;
}

async fn check_with_netns(cli: Cli, netlink_handle: rtnetlink::Handle, netns_metadata: NetNsMetadata) {
    let netns = NetNs::get(netns_metadata.netns_name).expect("Could not get netns");

    run_iptables(
        &cli,
        format!(
            "-t nat -C POSTROUTING -s {} -o {} -j MASQUERADE",
            netns_metadata.veth2_ip, cli.iface_name
        ),
    )
    .await;
    run_iptables(
        &cli,
        format!("-C FORWARD -i {} -o {} -j ACCEPT", cli.iface_name, netns_metadata.veth1_name),
    )
    .await;
    run_iptables(
        &cli,
        format!("-C FORWARD -o {} -i {} -j ACCEPT", cli.iface_name, netns_metadata.veth1_name),
    )
    .await;

    netns
        .run_async(|| async {
            run_iptables(
                &cli,
                format!("-t nat -C POSTROUTING -o {} -j MASQUERADE", netns_metadata.veth2_name),
            )
            .await;
            run_iptables(
                &cli,
                "-C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
            )
            .await;
            run_iptables(
                &cli,
                format!("-C FORWARD -i {} -o {} -j ACCEPT", cli.tap_name, netns_metadata.veth2_name),
            )
            .await;

            if let Some((ref host_ip, ref guest_ip)) = netns_metadata.forward {
                run_iptables(
                    &cli,
                    format!(
                        "-t nat -C PREROUTING -i {} -d {} -j DNAT --to {}",
                        netns_metadata.veth2_name, host_ip, guest_ip
                    ),
                )
                .await;
            }
        })
        .await;

    if let Some((host_ip, _)) = netns_metadata.forward {
        let ip_version = match host_ip {
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

                    if ip_addr == host_ip {
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
