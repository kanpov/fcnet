use std::{net::IpAddr, str::FromStr};

use cidr::IpInet;
use clap::{Args, Parser, Subcommand};
use futures::TryStreamExt;
use netns::NetNsMetadata;
use tokio::process::Command;

mod netns;
mod simple;

#[derive(Parser)]
#[command(
    name = "nat-helper",
    version = "0.1",
    about = "NAT helper for Firecracker workloads",
    propagate_version = true
)]
pub struct Cli {
    #[arg(
        help = "Path to the iptables binary to use for veth and NAT-related routing, iptables-nft is supported",
        long = "iptables-path",
        default_value = "/usr/sbin/iptables"
    )]
    iptables_path: String,
    #[arg(
        help = "Network interface in the default netns that handles real connectivity",
        long = "iface",
        default_value = "eth0"
    )]
    iface_name: String,
    #[arg(help = "Name of the tap device to create", long = "tap", default_value = "tap0")]
    tap_name: String,
    #[arg(help = "The CIDR IP of the tap device to create", long = "tap-ip", default_value_t = IpInet::from_str("172.16.0.1/24").unwrap())]
    tap_ip: IpInet,
    #[command(flatten)]
    operation_group: OperationGroup,
    #[command(subcommand)]
    subcommands: Subcommands,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct OperationGroup {
    #[arg(short = 'A', long = "add", help = "Add the given network")]
    add: bool,
    #[arg(short = 'D', long = "del", help = "Delete the given network")]
    del: bool,
    #[arg(short = 'C', long = "check", help = "Check the given network")]
    check: bool,
}

#[derive(Subcommand, Clone)]
pub enum Subcommands {
    #[command(about = "Use a simple configuration in the default netns")]
    Simple,
    #[command(about = "Use a configuration involving a new netns")]
    Netns {
        #[arg(help = "Name of the network namespace", long = "netns", default_value = "fcnet")]
        netns_name: String,
        #[arg(help = "The first end of the veth pair", long = "veth1", default_value = "veth1")]
        veth1_name: String,
        #[arg(help = "The second end of the veth pair", long = "veth2", default_value = "veth2")]
        veth2_name: String,
        #[arg(
            help = "The CIDR IP of the first end of the veth pair",
            long = "veth1-ip",
            default_value_t = IpInet::from_str("10.0.0.1/24").unwrap()
        )]
        veth1_ip: IpInet,
        #[arg(
            help = "The CIDR IP of the second end of the veth pair",
            long = "veth2-ip",
            default_value_t = IpInet::from_str("10.0.0.2/24").unwrap()
        )]
        veth2_ip: IpInet,
        #[arg(help = "The IP by which the VM will be accessible in the default netns", long = "outer-ip", default_value_t = IpAddr::from_str("192.168.0.3").unwrap())]
        outer_ip: IpAddr,
        #[arg(
            help = "Optionally, a forwarding pair for accessing guest IP on default netns. Example: 10.0.0.1:10.0.0.2 will expose 10.0.0.1 on the default netns that goes to guest 10.0.0.2",
            long = "guest-ip-forward"
        )]
        guest_ip_forward: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let (connection, netlink_handle, _) = rtnetlink::new_connection().expect("Could not connect to rtnetlink");
    tokio::spawn(connection);

    match cli.subcommands.clone() {
        Subcommands::Simple => {
            simple::run(cli, netlink_handle).await;
        }
        #[allow(unused)]
        Subcommands::Netns {
            netns_name,
            veth1_name,
            veth2_name,
            veth1_ip,
            veth2_ip,
            outer_ip,
            guest_ip_forward,
        } => {
            let mut parsed = None;
            if let Some(guest_ip_forward) = guest_ip_forward {
                let (split1, split2) = guest_ip_forward
                    .split_once(':')
                    .expect("IP forward pair is incorrectly formatted: no ':' delimiter");
                parsed = Some((
                    IpAddr::from_str(split1).unwrap_or_else(|_| panic!("{} is not an IP", split1)),
                    IpAddr::from_str(split2).unwrap_or_else(|_| panic!("{} is not an IP", split2)),
                ));
            }

            netns::run(
                cli,
                netlink_handle,
                NetNsMetadata {
                    netns_name,
                    veth1_name,
                    veth2_name,
                    veth1_ip,
                    veth2_ip,
                    guest_ip_forward: parsed,
                },
            )
            .await
        }
    };
}

// utils

pub async fn get_link_index(link: String, netlink_handle: &rtnetlink::Handle) -> u32 {
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

pub async fn run_iptables(cli: &Cli, iptables_cmd: String) {
    dbg!(&iptables_cmd);
    let mut command = Command::new(cli.iptables_path.as_str());
    for iptables_arg in iptables_cmd.split(' ') {
        command.arg(iptables_arg);
    }

    let status = command.status().await.expect("Could not invoke iptables");
    if !status.success() {
        panic!("Iptables invocation failed with exit status: {}", status);
    }
}
