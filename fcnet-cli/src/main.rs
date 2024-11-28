use arguments::{Cli, Subcommands};
use clap::Parser;
use fcnet::backend::TokioBackend;
use fcnet_types::{FirecrackerNetwork, FirecrackerNetworkOperation, FirecrackerNetworkType};

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
            forwarded_guest_ip,
        } => FirecrackerNetworkType::Namespaced {
            netns_name,
            veth1_name,
            veth2_name,
            veth1_ip,
            veth2_ip,
            forwarded_guest_ip,
        },
    };

    let network = FirecrackerNetwork {
        nft_path: cli.nft_path,
        ip_stack: cli.ip_stack.into(),
        guest_ip: cli.guest_ip,
        iface_name: cli.iface_name,
        tap_name: cli.tap_name,
        tap_ip: cli.tap_ip,
        network_type,
    };

    let future = {
        if cli.operation_group.add {
            fcnet::run::<TokioBackend>(&network, FirecrackerNetworkOperation::Add)
        } else if cli.operation_group.delete {
            fcnet::run::<TokioBackend>(&network, FirecrackerNetworkOperation::Delete)
        } else {
            fcnet::run::<TokioBackend>(&network, FirecrackerNetworkOperation::Check)
        }
    };

    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        eprintln!("Could not start a Tokio runtime");
        return;
    };

    if let Err(err) = runtime.block_on(future) {
        eprintln!("{err}");
    }
}
