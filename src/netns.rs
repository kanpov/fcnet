use std::future::Future;

use cidr::IpInet;
use netns_rs::NetNs;
use tokio_tun::TunBuilder;

use crate::{get_link_index, Cli};

pub struct NetNsMetadata {
    pub netns_name: String,
    pub veth1_name: String,
    pub veth2_name: String,
    pub veth1_ip: IpInet,
    pub veth2_ip: IpInet,
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
        })
        .await;
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
