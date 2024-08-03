use std::str::FromStr;

use cidr::IpInet;
use clap::{Parser, Subcommand};
use tokio::process::Command;

mod netns;

#[derive(Parser)]
#[command(
    name = "nat-helper",
    version = "0.1",
    about = "NAT helper for Firecracker workloads",
    propagate_version = true
)]
pub struct Args {
    #[arg(
        help = "Optionally, a network namespace to be created and connected",
        long = "netns"
    )]
    netns: Option<String>,
    #[arg(
        help = "The outer end of the veth pair, applicable for a netns config",
        long = "veth",
        default_value = "veth0"
    )]
    veth: String,
    #[arg(
        help = "The inner end of the veth pair, applicable for a netns config",
        long = "vpeer",
        default_value = "vpeer0"
    )]
    vpeer: String,
    #[arg(
        help = "The CIDR IP of the outer end of the veth pair, applicable for a netns config",
        long = "veth-ip",
        default_value_t = IpInet::from_str("10.0.0.1/24").unwrap()
    )]
    veth_ip: IpInet,
    #[arg(
        help = "The CIDR IP of the inner end of the veth pair, applicable for a netns config",
        long = "vpeer-ip",
        default_value_t = IpInet::from_str("10.0.0.2/24").unwrap()
    )]
    vpeer_ip: IpInet,
    #[arg(
        help = "Path to the iptables binary to use for veth and NAT-related routing, iptables-nft is supported",
        long = "iptables-path",
        default_value = "/usr/sbin/iptables"
    )]
    iptables_path: String,
    #[arg(
        help = "Network interface in the default netns that handles real connectivity",
        long = "backing-iface",
        default_value = "eth0"
    )]
    main_iface: String,
    #[command(subcommand)]
    subcommand: Subcommands,
}

#[derive(Subcommand)]
pub enum Subcommands {
    #[command(about = "Creates the given network")]
    Add,
    #[command(about = "Deletes the given network")]
    Del,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let (connection, netlink_handle, _) =
        rtnetlink::new_connection().expect("Could not connect to rtnetlink");
    tokio::spawn(connection);

    if args.netns.is_some() {
        netns::add_netns(&args, &netlink_handle).await;
        netns::del_netns(&args).await;
    }
}

pub async fn run_iptables(args: &Args, iptables_cmd: String) {
    let mut command = Command::new(args.iptables_path.as_str());
    for iptables_arg in iptables_cmd.split(' ') {
        command.arg(iptables_arg);
    }

    let status = command.status().await.expect("Could not invoke iptables");
    if !status.success() {
        panic!("Iptables invocation failed with exit status: {}", status);
    }
}
