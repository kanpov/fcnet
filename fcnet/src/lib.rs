use std::{future::Future, net::IpAddr, path::PathBuf, process::ExitStatus, sync::Arc};

use cidr::IpInet;
use futures_util::TryStreamExt;
use netns::NamespacedData;
use netns_rs::NetNs;
use tokio::process::Command;

mod netns;
mod simple;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FirecrackerNetwork {
    pub iptables_path: PathBuf,
    pub iface_name: String,
    pub tap_name: String,
    pub tap_ip: IpInet,
    pub network_type: FirecrackerNetworkType,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FirecrackerNetworkType {
    Simple,
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

#[derive(Debug)]
pub enum FirecrackerNetworkError {
    NetlinkOperationError(rtnetlink::Error),
    TapDeviceError(tokio_tun::Error),
    NetnsError(netns_rs::Error),
    IoError(std::io::Error),
    ChannelRecvError(tokio::sync::oneshot::error::RecvError),
    FailedInvocation(ExitStatus),
    RouteNotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FirecrackerNetworkOperation {
    Add,
    Check,
    Delete,
}

impl FirecrackerNetwork {
    pub async fn run(self: Arc<Self>, operation: FirecrackerNetworkOperation) -> Result<(), FirecrackerNetworkError> {
        let (connection, netlink_handle, _) = rtnetlink::new_connection().map_err(FirecrackerNetworkError::IoError)?;
        tokio::task::spawn(connection);

        match &self.network_type {
            FirecrackerNetworkType::Simple => simple::run(self, netlink_handle, operation).await,
            FirecrackerNetworkType::Namespaced {
                netns_name: _,
                veth1_name: _,
                veth2_name: _,
                veth1_ip: _,
                veth2_ip: _,
                guest_ip: _,
                forwarded_guest_ip: _,
            } => netns::run(operation, self, netlink_handle).await,
        }
    }

    async fn run_iptables(&self, iptables_cmd: String) -> Result<(), FirecrackerNetworkError> {
        let mut command = Command::new(&self.iptables_path);
        for iptables_arg in iptables_cmd.split(' ') {
            command.arg(iptables_arg);
        }

        let status = command.status().await.map_err(FirecrackerNetworkError::IoError)?;
        if !status.success() {
            return Err(FirecrackerNetworkError::FailedInvocation(status));
        }

        Ok(())
    }
}

async fn get_link_index(link: String, netlink_handle: &rtnetlink::Handle) -> u32 {
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

async fn use_netns_in_thread<
    F: 'static + Send + FnOnce(Arc<FirecrackerNetwork>, Arc<NamespacedData>) -> Fut,
    Fut: Send + Future<Output = Result<(), FirecrackerNetworkError>>,
>(
    netns_name: String,
    network: Arc<FirecrackerNetwork>,
    namespaced_data: Arc<NamespacedData>,
    function: F,
) -> Result<(), FirecrackerNetworkError> {
    let netns = NetNs::get(netns_name).map_err(FirecrackerNetworkError::NetnsError)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();

    std::thread::spawn(move || {
        let result = {
            match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(async move {
                    netns.enter().map_err(FirecrackerNetworkError::NetnsError)?;
                    function(network, namespaced_data).await
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
