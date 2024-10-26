#[cfg(all(not(feature = "simple"), not(feature = "namespaced")))]
compile_error!("Either \"simple\" or \"namespaced\" networking feature flags must be enabled");

#[cfg(feature = "namespaced")]
use std::{future::Future, net::IpAddr};
use std::{path::PathBuf, process::ExitStatus};

use cidr::IpInet;
use futures_util::TryStreamExt;
use nftables::types::NfFamily;
use tokio::process::Command;

#[cfg(feature = "namespaced")]
mod namespaced;
#[cfg(feature = "namespaced")]
mod netns;
#[cfg(feature = "namespaced")]
pub use netns::NetNsError;
#[cfg(feature = "simple")]
mod simple;

const NFT_NAT_TABLE: &str = "fcnet-nat";
const NFT_NAT_POSTROUTING_CHAIN: &str = "POSTROUTING";
const NFT_FILTER_TABLE: &str = "fcnet-filter";
const NFT_FILTER_FORWARD_CHAIN: &str = "POSTROUTING";

/// A configuration for a Firecracker microVM network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FirecrackerNetwork {
    /// The optional explicit path to "nft" to use when invoking it.
    pub nft_path: Option<String>,
    /// Whether to use IPv6.
    pub ipv6: bool,
    /// The name of the host network interface that handles real connectivity (i.e. via Ethernet or Wi-Fi).
    pub iface_name: String,
    /// The name of the tap device to direct Firecracker to use.
    pub tap_name: String,
    /// The IP of the tap device to direct Firecracker to use.
    pub tap_ip: IpInet,
    /// The type of network to create, the available options depend on the feature flags enabled.
    pub network_type: FirecrackerNetworkType,
}

/// The type of Firecracker network to work with.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FirecrackerNetworkType {
    /// A "simple" network configuration, with a tap device bound to the host interface via 1 set of forwarding rules.
    /// The most optimal and performant choice for the majority of use-cases.
    #[cfg(feature = "simple")]
    Simple,
    /// A namespaced network configuration, with the tap device residing in a separate network namespace and being
    /// bound to the host interface via 2 sets of forwarding rules.
    /// The better choice exclusively for multiple running microVM sharing the same snapshot data (i.e. so-called "clones").
    #[cfg(feature = "namespaced")]
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

/// An error that can be emitted by a Firecracker network operation.
#[derive(Debug, thiserror::Error)]
pub enum FirecrackerNetworkError {
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
    #[error("Invoking a process failed due to its non-zero exit status: `{0}`")]
    FailedInvocation(ExitStatus),
    #[error("An expected IP route was not found on the host")]
    RouteNotFound,
    #[error("An expected IP link was not found on the host")]
    LinkNotFound,
}

/// An operation that can be made with a FirecrackerNetwork.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FirecrackerNetworkOperation {
    /// Add this network to the host.
    Add,
    /// Check that this network already exists on the host.
    Check,
    /// Delete this network from the host.
    Delete,
}

impl FirecrackerNetwork {
    fn nf_family(&self) -> NfFamily {
        match self.ipv6 {
            true => NfFamily::IP6,
            false => NfFamily::IP,
        }
    }

    /// Run an operation on this network (add, check or delete).
    pub async fn run(&self, operation: FirecrackerNetworkOperation) -> Result<(), FirecrackerNetworkError> {
        let (connection, netlink_handle, _) = rtnetlink::new_connection().map_err(FirecrackerNetworkError::IoError)?;
        tokio::task::spawn(connection);

        match &self.network_type {
            #[cfg(feature = "simple")]
            FirecrackerNetworkType::Simple => simple::run(self, netlink_handle, operation).await,
            #[cfg(feature = "namespaced")]
            FirecrackerNetworkType::Namespaced {
                netns_name: _,
                veth1_name: _,
                veth2_name: _,
                veth1_ip: _,
                veth2_ip: _,
                guest_ip: _,
                forwarded_guest_ip: _,
            } => namespaced::run(operation, self, netlink_handle).await,
        }
    }

    /// Format a kernel boot argument that can be added so that all routing setup in the guest is performed
    /// by the kernel automatically with iproute2 not needed in the guest.
    pub fn guest_ip_boot_arg(&self, guest_ip: &IpInet, guest_iface_name: impl AsRef<str>) -> String {
        format!(
            "ip={}::{}:{}::{}:off",
            guest_ip.address().to_string(),
            self.tap_ip.address().to_string(),
            guest_ip.mask().to_string(),
            guest_iface_name.as_ref()
        )
    }
}

async fn get_link_index(link: String, netlink_handle: &rtnetlink::Handle) -> Result<u32, FirecrackerNetworkError> {
    Ok(netlink_handle
        .link()
        .get()
        .match_name(link)
        .execute()
        .try_next()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?
        .ok_or(FirecrackerNetworkError::LinkNotFound)?
        .header
        .index)
}

#[cfg(feature = "namespaced")]
async fn use_netns_in_thread(
    netns_name: String,
    future: impl 'static + Send + Future<Output = Result<(), FirecrackerNetworkError>>,
) -> Result<(), FirecrackerNetworkError> {
    use netns::NetNs;

    let netns = NetNs::get(netns_name).map_err(FirecrackerNetworkError::NetnsError)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();

    std::thread::spawn(move || {
        let result = {
            match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(async move {
                    netns.enter().map_err(FirecrackerNetworkError::NetnsError)?;
                    future.await
                }),
                Err(err) => Err(FirecrackerNetworkError::IoError(err)),
            }
        };

        let _ = sender.send(result);
    });

    match receiver.await {
        Ok(result) => result,
        Err(err) => Err(FirecrackerNetworkError::ChannelRecvError(err)),
    }
}

async fn run_iptables(iptables_path: &PathBuf, iptables_cmd: String) -> Result<(), FirecrackerNetworkError> {
    let mut command = Command::new(&iptables_path);
    for iptables_arg in iptables_cmd.split(' ') {
        command.arg(iptables_arg);
    }

    let status = command.status().await.map_err(FirecrackerNetworkError::IoError)?;
    if !status.success() {
        return Err(FirecrackerNetworkError::FailedInvocation(status));
    }

    Ok(())
}
