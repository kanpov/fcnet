use std::{net::IpAddr, str::FromStr};

use cidr::IpInet;
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "fcnet-cli",
    version = "0.1.0",
    about = "A CLI wrapper around the fcnet library for Firecracker microVM networking",
    propagate_version = true
)]
pub struct Cli {
    #[arg(help = "Optional explicit path to the \"nft\" binary", long = "nft-path")]
    pub nft_path: Option<String>,
    #[arg(help = "Whether to use IPv6 support", long = "ipv6")]
    pub ipv6: bool,
    #[arg(
        help = "Network interface in the default netns that handles real connectivity",
        long = "iface",
        default_value = "eth0"
    )]
    pub iface_name: String,
    #[arg(help = "Name of the tap device to create", long = "tap", default_value = "tap0")]
    pub tap_name: String,
    #[arg(help = "The CIDR IP of the tap device to create", long = "tap-ip", default_value_t = IpInet::from_str("172.16.0.1/24").unwrap())]
    pub tap_ip: IpInet,
    #[command(flatten)]
    pub operation_group: OperationGroup,
    #[command(subcommand)]
    pub subcommands: Subcommands,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct OperationGroup {
    #[arg(short = 'A', long = "add", help = "Add the given network")]
    pub add: bool,
    #[arg(short = 'D', long = "del", help = "Delete the given network")]
    pub delete: bool,
    #[arg(short = 'C', long = "check", help = "Check the given network")]
    pub check: bool,
}

#[derive(Subcommand, Clone)]
pub enum Subcommands {
    #[command(about = "Use a simple configuration in the default netns")]
    Simple,
    #[command(about = "Use a configuration involving a new netns")]
    Namespaced {
        #[arg(help = "Name of the network namespace", long = "netns", default_value = "fcnet")]
        netns_name: String,
        #[arg(help = "The first end of the veth pair", long = "veth1", default_value = "veth1")]
        veth1_name: String,
        #[arg(help = "The second end of the veth pair", long = "veth2", default_value = "veth0")]
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
        #[arg(
            help = "The IP of the guest (not the tap device)",
            long = "guest-ip",
            default_value_t = IpAddr::from_str("172.16.0.2").unwrap()
        )]
        guest_ip: IpAddr,
        #[arg(
            help = "Optionally, an IP for forwarding connections to the guest from outside the netns (inside, use the actual guest IP)",
            long = "forwarded-guest-ip"
        )]
        forwarded_guest_ip: Option<IpAddr>,
    },
}
