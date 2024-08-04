use std::{future::Future, net::IpAddr, os::fd::AsRawFd};

use cidr::IpInet;
use netns_rs::NetNs;
use tokio_tun::TunBuilder;

use crate::{get_link_index, run_iptables, Cli};

pub struct NetNsMetadata {
    pub netns_name: String,
    pub veth1_name: String,
    pub veth2_name: String,
    pub veth1_ip: IpInet,
    pub veth2_ip: IpInet,
    pub outer_ip: IpAddr,
    pub guest_ip: IpAddr,
}

pub async fn run(cli: &Cli, netlink_handle: &rtnetlink::Handle, netns_metadata: NetNsMetadata) {
    if cli.operation_group.add {
        add_with_netns(cli, netlink_handle, netns_metadata).await;
    } else if cli.operation_group.del {
        del_with_netns(cli, netlink_handle, netns_metadata).await;
    } else {
        check_with_netns(cli, netlink_handle, netns_metadata).await;
    }
}

async fn add_with_netns(cli: &Cli, outer_handle: &rtnetlink::Handle, netns_metadata: NetNsMetadata) {
    let netns = NetNs::new(netns_metadata.netns_name).expect("Could not create netns");
    let default_netns = netns_rs::get_from_current_thread().expect("Could not get default netns");

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
            let tap_idx = get_link_index(cli.tap_name.clone(), &inner_handle).await;
            inner_handle
                .address()
                .add(tap_idx, cli.tap_ip.address(), cli.tap_ip.network_length())
                .execute()
                .await
                .expect("Could not assign IP to tap device in netns");

            inner_handle
                .link()
                .add()
                .veth(netns_metadata.veth1_name.clone(), netns_metadata.veth2_name.clone())
                .execute()
                .await
                .expect("Could not create veth in netns");
            let veth1_idx = get_link_index(netns_metadata.veth1_name.clone(), &inner_handle).await;
            inner_handle
                .link()
                .set(veth1_idx)
                .setns_by_fd(default_netns.file().as_raw_fd())
                .execute()
                .await
                .expect("Could not move veth1 out of netns");

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
                .expect("Could not set IP for veth2 in netns");
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

            run_iptables(
                cli,
                format!(
                    "-t nat -A POSTROUTING -o {} -s {} -j SNAT --to {}",
                    netns_metadata.veth2_name, netns_metadata.guest_ip, netns_metadata.outer_ip
                ),
            )
            .await;
            run_iptables(
                cli,
                format!(
                    "-t nat -A PREROUTING -i {} -d {} -j DNAT --to {}",
                    netns_metadata.veth2_name, netns_metadata.outer_ip, netns_metadata.guest_ip
                ),
            )
            .await;
        })
        .await;

    let veth1_idx = get_link_index(netns_metadata.veth1_name.clone(), outer_handle).await;
    outer_handle
        .address()
        .add(
            veth1_idx,
            netns_metadata.veth1_ip.address(),
            netns_metadata.veth1_ip.network_length(),
        )
        .execute()
        .await
        .expect("Could not set IP for veth1");
    outer_handle
        .link()
        .set(veth1_idx)
        .up()
        .execute()
        .await
        .expect("Could not up veth1");
}

async fn del_with_netns(cli: &Cli, netlink_handle: &rtnetlink::Handle, netns_metadata: NetNsMetadata) {
    NetNs::get(netns_metadata.netns_name)
        .expect("Could not get netns")
        .remove()
        .expect("Could not remove netns");
}

async fn check_with_netns(cli: &Cli, netlink_handle: &rtnetlink::Handle, netns_metadata: NetNsMetadata) {
    NetNs::get(netns_metadata.netns_name).expect("Could not get netns");
}

trait AsyncNetnsRun {
    fn run_async<F, Fut>(&self, closure: F) -> impl Future<Output = ()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>;
}

impl AsyncNetnsRun for NetNs {
    fn run_async<F, Fut>(&self, closure: F) -> impl Future<Output = ()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        async move {
            let prev_netns = netns_rs::get_from_current_thread().expect("Could not get prev netns");
            self.enter().expect("Could not enter new netns");
            closure().await;
            prev_netns.enter().expect("Could not enter prev netns");
        }
    }
}
