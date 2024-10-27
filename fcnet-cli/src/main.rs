use arguments::{Cli, Subcommands};
use clap::Parser;
use fcnet::{FirecrackerNetwork, FirecrackerNetworkOperation, FirecrackerNetworkType};

mod arguments;

fn main() {
    let cli = Cli::parse();

    let network_type = match cli.subcommands {
        Subcommands::Simple => FirecrackerNetworkType::Simple,
        Subcommands::Namespaced {
            netns_name,
            veth1_name,
            veth2_name,
            veth1_ip,
            veth2_ip,
            guest_ip,
            forwarded_guest_ip,
        } => FirecrackerNetworkType::Namespaced {
            netns_name,
            veth1_name,
            veth2_name,
            veth1_ip,
            veth2_ip,
            guest_ip,
            forwarded_guest_ip,
        },
    };

    let network = FirecrackerNetwork {
        nft_path: cli.nft_path,
        ip_stack: cli.ip_stack.into(),
        iface_name: cli.iface_name,
        tap_name: cli.tap_name,
        tap_ip: cli.tap_ip,
        network_type,
    };

    let future = {
        if cli.operation_group.add {
            network.run(FirecrackerNetworkOperation::Add)
        } else if cli.operation_group.delete {
            network.run(FirecrackerNetworkOperation::Delete)
        } else {
            network.run(FirecrackerNetworkOperation::Check)
        }
    };

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Could not build Tokio runtime for blocking on the main future")
        .block_on(future)
        .expect("Network operation failed");
}
