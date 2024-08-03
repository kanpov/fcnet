use std::{future::Future, os::fd::AsRawFd};

use futures::TryStreamExt;
use netns_rs::NetNs;

use crate::{run_iptables, Args};

pub async fn add_netns(args: &Args, netlink_handle: &rtnetlink::Handle) {
    // create veth pair and set IP of veth
    netlink_handle
        .link()
        .add()
        .veth(args.veth.to_owned(), args.vpeer.to_owned())
        .execute()
        .await
        .expect("Could not create veth pair via rtnetlink");

    let veth_idx = get_link_index(args.veth.to_owned(), netlink_handle).await;
    let vpeer_idx = get_link_index(args.vpeer.to_owned(), netlink_handle).await;
    netlink_handle
        .address()
        .add(
            veth_idx,
            args.veth_ip.address(),
            args.veth_ip.network_length(),
        )
        .execute()
        .await
        .expect("Failed to set IP of veth");

    // create netns, move in vpeer, up veth
    let netns = NetNs::new(args.netns.as_ref().unwrap()).expect("Could not create netns");
    netlink_handle
        .link()
        .set(vpeer_idx)
        .setns_by_fd(netns.file().as_raw_fd())
        .execute()
        .await
        .expect("Failed to move vpeer into netns");
    netlink_handle
        .link()
        .set(veth_idx)
        .up()
        .execute()
        .await
        .expect("Failed to up veth");

    // inside netns, up vpeer and loopback, set vpeer IP
    netns
        .run_async(|| async {
            let (conn, inner_handle, _) =
                rtnetlink::new_connection().expect("Could not connect to rtnetlink inside netns");
            tokio::spawn(conn);
            let vpeer_idx = get_link_index(args.vpeer.to_owned(), &inner_handle).await;
            inner_handle
                .link()
                .set(vpeer_idx)
                .up()
                .execute()
                .await
                .expect("Could not up vpeer inside netns");
            inner_handle
                .address()
                .add(
                    vpeer_idx,
                    args.vpeer_ip.address(),
                    args.vpeer_ip.network_length(),
                )
                .execute()
                .await
                .expect("Could not set IP of vpeer inside netns");
            let loopback_idx = get_link_index("lo".to_owned(), &inner_handle).await;
            inner_handle
                .link()
                .set(loopback_idx)
                .up()
                .execute()
                .await
                .expect("Could not up loopback inside netns");
        })
        .await;

    // set up veth pair routing
    run_iptables(
        args,
        format!(
            "-t nat -A POSTROUTING -s {} -o {} -j MASQUERADE",
            args.veth_ip.to_string(),
            args.main_iface
        ),
    )
    .await;
    run_iptables(
        args,
        format!(
            "-A FORWARD -i {} -o {} -j ACCEPT",
            args.main_iface,
            args.veth_ip.address()
        ),
    )
    .await;
    run_iptables(
        args,
        format!(
            "-A FORWARD -o {} -i {} -j ACCEPT",
            args.main_iface,
            args.veth_ip.address()
        ),
    )
    .await;
}

pub async fn del_netns(args: &Args) {
    let netns = NetNs::get(args.netns.as_ref().unwrap())
        .expect("Could not retrieve given netns for deletion");
    netns.remove().expect("Could not delete netns");

    run_iptables(
        args,
        format!(
            "-t nat -D POSTROUTING -s {} -o {} -j MASQUERADE",
            args.veth_ip.to_string(),
            args.main_iface
        ),
    )
    .await;
    run_iptables(
        args,
        format!(
            "-D FORWARD -i {} -o {} -j ACCEPT",
            args.main_iface,
            args.veth_ip.address()
        ),
    )
    .await;
    run_iptables(
        args,
        format!(
            "-D FORWARD -o {} -i {} -j ACCEPT",
            args.main_iface,
            args.veth_ip.address()
        ),
    )
    .await;
}

async fn get_link_index(link: String, netlink_handle: &rtnetlink::Handle) -> u32 {
    netlink_handle
        .link()
        .get()
        .match_name(link)
        .execute()
        .try_next()
        .await
        .expect("Could not query for a link's index")
        .unwrap()
        .header
        .index
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
