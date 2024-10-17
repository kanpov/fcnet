use std::{net::IpAddr, path::PathBuf};

use cidr::IpInet;
use futures_util::TryStreamExt;
use tokio::process::Command;

mod netns;
mod simple;

pub struct FirecrackerNetwork {
    pub iptables_path: PathBuf,
    pub iface_name: String,
    pub tap_name: String,
    pub tap_ip: IpInet,
    pub network_type: FirecrackerNetworkType,
}

impl FirecrackerNetwork {
    async fn run_iptables(&self, iptables_cmd: String) {
        let mut command = Command::new(&self.iptables_path);
        for iptables_arg in iptables_cmd.split(' ') {
            command.arg(iptables_arg);
        }

        let status = command.status().await.expect("Could not invoke iptables");
        if !status.success() {
            panic!("Iptables invocation failed with exit status: {}", status);
        }
    }
}

pub enum FirecrackerNetworkType {
    Simple,
    Namespaced {
        netns_name: String,
        veth1_name: String,
        veth2_name: String,
        veth1_ip: IpInet,
        veth2_ip: IpInet,
        guest_ip: IpAddr,
        forwarded_guest_ip: Option<IpAddr>,
    },
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
