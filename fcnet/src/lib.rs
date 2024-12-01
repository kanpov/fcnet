#![cfg_attr(docsrs, feature(doc_cfg))]

use backend::Backend;
use fcnet_types::{FirecrackerNetwork, FirecrackerNetworkOperation, FirecrackerNetworkType};
use nftables::helper::NftablesError;

#[cfg(feature = "namespaced")]
mod namespaced;
#[cfg(feature = "namespaced")]
mod netns;
#[cfg(feature = "namespaced")]
#[cfg_attr(docsrs, doc(cfg(feature = "namespaced")))]
pub use netns::NetNsError;
#[cfg(feature = "simple")]
mod simple;

pub mod backend;
pub(crate) mod util;

const NFT_TABLE: &str = "fcnet";
const NFT_POSTROUTING_CHAIN: &str = "postrouting";
#[cfg(feature = "namespaced")]
const NFT_PREROUTING_CHAIN: &str = "prerouting";
const NFT_FILTER_CHAIN: &str = "filter";

/// An error that can be emitted by embedded fcnet.
#[derive(Debug)]
pub enum FirecrackerNetworkError {
    NetlinkOperationError(rtnetlink::Error),
    TapDeviceError(tokio_tun::Error),
    #[cfg(feature = "namespaced")]
    #[cfg_attr(docsrs, doc(cfg(feature = "namespaced")))]
    NetnsError(NetNsError),
    IoError(std::io::Error),
    #[cfg(feature = "namespaced")]
    #[cfg_attr(docsrs, doc(cfg(feature = "namespaced")))]
    ChannelCancelError(futures_channel::oneshot::Canceled),
    NftablesError(NftablesError),
    ObjectNotFound(FirecrackerNetworkObjectType),
    ForbiddenDualStackInRoute,
}

impl std::fmt::Display for FirecrackerNetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirecrackerNetworkError::NetlinkOperationError(err) => write!(f, "An rtnetlink operation failed: {err}"),
            FirecrackerNetworkError::TapDeviceError(err) => write!(f, "Creating or deleting a tap device failed: {err}"),
            #[cfg(feature = "namespaced")]
            FirecrackerNetworkError::NetnsError(err) => {
                write!(f, "Interacting wtih a network namespace failed: {err}")
            }
            FirecrackerNetworkError::IoError(err) => write!(f, "A generic I/O error occurred: {err}"),
            #[cfg(feature = "namespaced")]
            FirecrackerNetworkError::ChannelCancelError(err) => {
                write!(f, "Receiving from a supporting oneshot channel failed: {err}")
            }
            FirecrackerNetworkError::NftablesError(err) => write!(f, "Invoking nftables failed: {err}"),
            FirecrackerNetworkError::ObjectNotFound(object_type) => {
                write!(f, "An nftables object was not found in the current ruleset: {object_type:?}")
            }
            FirecrackerNetworkError::ForbiddenDualStackInRoute => write!(
                f,
                "In a netlink route, both an IPv4 and an IPv6 support are being used (address, gateway)"
            ),
        }
    }
}

/// An object created by the integrated Firecracker networking backend.
#[derive(Debug)]
pub enum FirecrackerNetworkObjectType {
    IpLink,
    IpRoute,
    NfTable,
    NfPostroutingChain,
    #[cfg(feature = "namespaced")]
    #[cfg_attr(docsrs, doc(cfg(feature = "namespaced")))]
    NfPreroutingChain,
    NfFilterChain,
    NfMasqueradeRule,
    NfEgressForwardRule,
    NfIngressForwardRule,
    #[cfg(feature = "namespaced")]
    #[cfg_attr(docsrs, doc(cfg(feature = "namespaced")))]
    NfEgressSnatRule,
    #[cfg(feature = "namespaced")]
    #[cfg_attr(docsrs, doc(cfg(feature = "namespaced")))]
    NfIngressDnatRule,
}

/// Run an operation on a [FirecrackerNetwork] via the integrated backend.
pub async fn run<B: Backend>(
    network: &FirecrackerNetwork,
    operation: FirecrackerNetworkOperation,
) -> Result<(), FirecrackerNetworkError> {
    let (connection, netlink_handle, _) =
        rtnetlink::new_connection_with_socket::<B::NetlinkSocket>().map_err(FirecrackerNetworkError::IoError)?;
    B::spawn_connection(connection);

    match &network.network_type {
        #[cfg(feature = "simple")]
        FirecrackerNetworkType::Simple => simple::run::<B>(network, netlink_handle, operation).await,
        #[cfg(feature = "namespaced")]
        FirecrackerNetworkType::Namespaced {
            netns_name: _,
            veth1_name: _,
            veth2_name: _,
            veth1_ip: _,
            veth2_ip: _,
            forwarded_guest_ip: _,
        } => namespaced::run::<B>(operation, network, netlink_handle).await,
    }
}
