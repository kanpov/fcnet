#[cfg(all(not(feature = "simple"), not(feature = "namespaced")))]
compile_error!("Either \"simple\" or \"namespaced\" networking feature flags must be enabled");

#[cfg(feature = "namespaced")]
use std::net::IpAddr;

use cidr::IpInet;
use futures_util::TryStreamExt;
use nftables::{
    batch::Batch,
    helper::NftablesError,
    schema::{Chain, NfListObject, NfObject, Nftables, Table},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

#[cfg(feature = "namespaced")]
mod namespaced;
#[cfg(feature = "namespaced")]
mod netns;
#[cfg(feature = "namespaced")]
pub use netns::NetNsError;
#[cfg(feature = "simple")]
mod simple;

const NFT_TABLE: &str = "fcnet";
const NFT_POSTROUTING_CHAIN: &str = "postrouting";
#[cfg(feature = "namespaced")]
const NFT_PREROUTING_CHAIN: &str = "prerouting";
const NFT_FILTER_CHAIN: &str = "filter";

/// A configuration for a Firecracker microVM network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FirecrackerNetwork {
    /// The optional explicit path to "nft" to use when invoking it.
    pub nft_path: Option<String>,
    /// The IP stack to use.
    pub ip_stack: FirecrackerIpStack,
    /// The name of the host network interface that handles real connectivity (i.e. via Ethernet or Wi-Fi).
    pub iface_name: String,
    /// The name of the tap device to direct Firecracker to use.
    pub tap_name: String,
    /// The IP of the tap device to direct Firecracker to use.
    pub tap_ip: IpInet,
    /// The IP of the guest.
    pub guest_ip: IpInet,
    /// The type of network to create, the available options depend on the feature flags enabled.
    pub network_type: FirecrackerNetworkType,
}

/// The IP stack to use for networking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FirecrackerIpStack {
    /// IPv4, translated to "ip" chains in nftables.
    V4,
    /// IPv6, translated to "ip6" chains in nftables.
    V6,
    /// Both IPv4 and IPv6, translated to "inet" chains in nftables.
    Dual,
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
    #[error("Invoking nftables failed: `{0}`")]
    NftablesError(NftablesError),
    #[error("An nftables object was not found in the current ruleset")]
    ObjectNotFound(FirecrackerNetworkObject),
    #[error("In a netlink route, both an IPv4 and an IPv6 address are being used (address, gateway)")]
    ForbiddenDualStackInRoute,
}

/// An object created by the Firecracker networking.
#[derive(Debug)]
pub enum FirecrackerNetworkObject {
    IpLink,
    IpRoute,
    NfTable,
    NfPostroutingChain,
    NfPreroutingChain,
    NfFilterChain,
    NfMasqueradeRule,
    NfEgressForwardRule,
    NfIngressForwardRule,
    NfEgressSnatRule,
    NfIngressDnatRule,
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
    #[inline]
    fn nf_family(&self) -> NfFamily {
        match self.ip_stack {
            FirecrackerIpStack::V4 => NfFamily::IP,
            FirecrackerIpStack::V6 => NfFamily::IP6,
            FirecrackerIpStack::Dual => NfFamily::INet,
        }
    }

    #[inline]
    fn nf_program(&self) -> Option<&str> {
        self.nft_path.as_ref().map(|p| p.as_str())
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
                forwarded_guest_ip: _,
            } => namespaced::run(operation, self, netlink_handle).await,
        }
    }

    /// Format a kernel boot argument that can be added so that all routing setup in the guest is performed
    /// by the kernel automatically with iproute2 not needed in the guest.
    pub fn guest_ip_boot_arg(&self, guest_iface_name: impl AsRef<str>) -> String {
        format!(
            "ip={}::{}:{}::{}:off",
            self.guest_ip.address().to_string(),
            self.tap_ip.address().to_string(),
            self.guest_ip.mask().to_string(),
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
        .ok_or(FirecrackerNetworkError::ObjectNotFound(FirecrackerNetworkObject::IpLink))?
        .header
        .index)
}

fn add_base_chains_if_needed(
    network: &FirecrackerNetwork,
    current_ruleset: &Nftables,
    batch: &mut Batch,
) -> Result<(), FirecrackerNetworkError> {
    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut filter_chain_exists = false;

    for object in &current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match object.as_ref() {
                NfListObject::Table(table) if table.name == NFT_TABLE && table.family == network.nf_family() => {
                    table_exists = true;
                }
                NfListObject::Chain(chain) => {
                    if chain.name == NFT_POSTROUTING_CHAIN && chain.table == NFT_TABLE {
                        postrouting_chain_exists = true;
                    } else if chain.name == NFT_FILTER_CHAIN && chain.table == NFT_TABLE {
                        filter_chain_exists = true;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if !table_exists {
        batch.add(NfListObject::Table(Table {
            family: network.nf_family(),
            name: NFT_TABLE.to_string(),
            handle: None,
        }));
    }

    if !postrouting_chain_exists {
        batch.add(NfListObject::Chain(Chain {
            family: network.nf_family(),
            table: NFT_TABLE.to_string(),
            name: NFT_POSTROUTING_CHAIN.to_string(),
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Postrouting),
            prio: Some(100),
            policy: Some(NfChainPolicy::Accept),
            newname: None,
            dev: None,
            handle: None,
        }));
    }

    if !filter_chain_exists {
        batch.add(NfListObject::Chain(Chain {
            family: network.nf_family(),
            table: NFT_TABLE.to_string(),
            name: NFT_FILTER_CHAIN.to_string(),
            _type: Some(NfChainType::Filter),
            hook: Some(NfHook::Forward),
            prio: Some(0),
            policy: Some(NfChainPolicy::Accept),
            handle: None,
            newname: None,
            dev: None,
        }));
    }

    Ok(())
}

fn check_base_chains(network: &FirecrackerNetwork, current_ruleset: &Nftables) -> Result<(), FirecrackerNetworkError> {
    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut filter_chain_exists = false;

    for object in &current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match object.as_ref() {
                NfListObject::Table(table) if table.name == NFT_TABLE && table.family == network.nf_family() => {
                    table_exists = true;
                }
                NfListObject::Chain(chain) if chain.table == NFT_TABLE => {
                    if chain.name == NFT_POSTROUTING_CHAIN {
                        postrouting_chain_exists = true;
                    } else if chain.name == NFT_FILTER_CHAIN {
                        filter_chain_exists = true;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if !table_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(FirecrackerNetworkObject::NfTable));
    }

    if !postrouting_chain_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfPostroutingChain,
        ));
    }

    if !filter_chain_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfFilterChain,
        ));
    }

    Ok(())
}

#[inline]
fn nat_proto_from_addr(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(_) => "ip".to_string(),
        IpAddr::V6(_) => "ip6".to_string(),
    }
}
