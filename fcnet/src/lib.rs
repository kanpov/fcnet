#[cfg(all(not(feature = "simple"), not(feature = "namespaced")))]
compile_error!("Either \"simple\" or \"namespaced\" networking feature flags must be enabled");

use std::net::IpAddr;

use cidr::IpInet;

/// A configuration for a Firecracker microVM network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type"))]
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

impl FirecrackerNetwork {
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

/// An operation that can be made with a FirecrackerNetwork.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FirecrackerNetworkOperation {
    /// Add this network to the host.
    Add,
    /// Check that this network already exists on the host.
    Check,
    /// Delete this network from the host.
    Delete,
}
