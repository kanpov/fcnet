#[cfg(all(not(feature = "simple"), not(feature = "namespaced")))]
compile_error!("Either \"simple\" or \"namespaced\" networking feature flags must be enabled");

use fcnet::{FirecrackerNetwork, FirecrackerNetworkOperation, FirecrackerNetworkType};
use nftables::helper::NftablesError;

#[cfg(feature = "namespaced")]
mod namespaced;
#[cfg(feature = "namespaced")]
mod netns;
#[cfg(feature = "namespaced")]
pub use netns::NetNsError;
#[cfg(feature = "simple")]
mod simple;

pub(crate) mod util;

const NFT_TABLE: &str = "fcnet";
const NFT_POSTROUTING_CHAIN: &str = "postrouting";
#[cfg(feature = "namespaced")]
const NFT_PREROUTING_CHAIN: &str = "prerouting";
const NFT_FILTER_CHAIN: &str = "filter";

/// An error that can be emitted by embedded fcnet.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("An rtnetlink operation failed: `{0}`")]
    NetlinkOperationError(rtnetlink::Error),
    #[error("Creating or deleting a tap device failed: `{0}`")]
    TapDeviceError(tokio_tun::Error),
    #[cfg(feature = "namespaced")]
    #[error("Interacting with a network namespace failed: `{0}`")]
    NetnsError(NetNsError),
    #[error("A generic I/O error occurred: `{0}`")]
    IoError(std::io::Error),
    #[cfg(feature = "namespaced")]
    #[error("Receiving from a supporting oneshot channel failed: `{0}`")]
    ChannelRecvError(tokio::sync::oneshot::error::RecvError),
    #[error("Invoking nftables failed: `{0}`")]
    NftablesError(NftablesError),
    #[error("An nftables object was not found in the current ruleset")]
    ObjectNotFound(ObjectType),
    #[error("In a netlink route, both an IPv4 and an IPv6 address are being used (address, gateway)")]
    ForbiddenDualStackInRoute,
}

/// An object created by the integrated Firecracker networking backend.
#[derive(Debug)]
pub enum ObjectType {
    IpLink,
    IpRoute,
    NfTable,
    NfPostroutingChain,
    #[cfg(feature = "namespaced")]
    NfPreroutingChain,
    NfFilterChain,
    NfMasqueradeRule,
    NfEgressForwardRule,
    NfIngressForwardRule,
    #[cfg(feature = "namespaced")]
    NfEgressSnatRule,
    #[cfg(feature = "namespaced")]
    NfIngressDnatRule,
}

/// Run an operation on a [FirecrackerNetwork] via the integrated backend.
pub async fn run(network: &FirecrackerNetwork, operation: FirecrackerNetworkOperation) -> Result<(), Error> {
    let (connection, netlink_handle, _) = rtnetlink::new_connection().map_err(Error::IoError)?;
    tokio::task::spawn(connection);

    match &network.network_type {
        #[cfg(feature = "simple")]
        FirecrackerNetworkType::Simple => simple::run(network, netlink_handle, operation).await,
        #[cfg(feature = "namespaced")]
        FirecrackerNetworkType::Namespaced {
            netns_name: _,
            veth1_name: _,
            veth2_name: _,
            veth1_ip: _,
            veth2_ip: _,
            forwarded_guest_ip: _,
        } => namespaced::run(operation, network, netlink_handle).await,
    }
}
