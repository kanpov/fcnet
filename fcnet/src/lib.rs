use std::{future::Future, net::IpAddr, path::PathBuf, process::ExitStatus, sync::Arc};

use cidr::IpInet;
use futures_util::TryStreamExt;
use netns::NamespacedData;
use netns_rs::NetNs;
use tokio::process::Command;

mod netns;
mod simple;

pub struct FirecrackerNetwork(Arc<FirecrackerNetworkInner>);

struct FirecrackerNetworkInner {
    iptables_path: PathBuf,
    iface_name: String,
    tap_name: String,
    tap_ip: IpInet,
    network_type: FirecrackerNetworkType,
}

impl FirecrackerNetwork {
    pub async fn add(&self) -> Result<(), FirecrackerNetworkError> {
        let (connection, netlink_handle, _) = rtnetlink::new_connection().map_err(FirecrackerNetworkError::IoError)?;
        tokio::task::spawn(connection);

        match self.0.clone().network_type.clone() {
            FirecrackerNetworkType::Simple => simple::add(self.0.clone(), netlink_handle).await,
            FirecrackerNetworkType::Namespaced {
                netns_name,
                veth1_name,
                veth2_name,
                veth1_ip,
                veth2_ip,
                guest_ip,
                forwarded_guest_ip,
            } => {
                netns::add(
                    self.0.clone(),
                    netlink_handle,
                    Arc::new(NamespacedData {
                        netns_name,
                        veth1_name,
                        veth2_name,
                        veth1_ip,
                        veth2_ip,
                        guest_ip,
                        forwarded_guest_ip,
                    }),
                )
                .await
            }
        }
    }

    pub async fn delete(&self) -> Result<(), FirecrackerNetworkError> {
        let (connection, netlink_handle, _) = rtnetlink::new_connection().map_err(FirecrackerNetworkError::IoError)?;
        tokio::task::spawn(connection);

        match self.0.clone().network_type.clone() {
            FirecrackerNetworkType::Simple => simple::delete(self.0.clone(), netlink_handle).await,
            FirecrackerNetworkType::Namespaced {
                netns_name,
                veth1_name,
                veth2_name,
                veth1_ip,
                veth2_ip,
                guest_ip,
                forwarded_guest_ip,
            } => {
                netns::delete(
                    self.0.clone(),
                    NamespacedData {
                        netns_name,
                        veth1_name,
                        veth2_name,
                        veth1_ip,
                        veth2_ip,
                        guest_ip,
                        forwarded_guest_ip,
                    },
                )
                .await
            }
        }
    }

    pub async fn check(&self) -> Result<(), FirecrackerNetworkError> {
        let (connection, netlink_handle, _) = rtnetlink::new_connection().map_err(FirecrackerNetworkError::IoError)?;
        tokio::task::spawn(connection);

        match self.0.clone().network_type.clone() {
            FirecrackerNetworkType::Simple => simple::check(self.0.clone(), netlink_handle).await,
            FirecrackerNetworkType::Namespaced {
                netns_name,
                veth1_name,
                veth2_name,
                veth1_ip,
                veth2_ip,
                guest_ip,
                forwarded_guest_ip,
            } => {
                netns::check(
                    self.0.clone(),
                    netlink_handle,
                    Arc::new(NamespacedData {
                        netns_name,
                        veth1_name,
                        veth2_name,
                        veth1_ip,
                        veth2_ip,
                        guest_ip,
                        forwarded_guest_ip,
                    }),
                )
                .await
            }
        }
    }
}

impl FirecrackerNetworkInner {
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

#[derive(Debug, Clone)]
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

pub enum FirecrackerNetworkError {
    NetlinkOperationError(rtnetlink::Error),
    TapDeviceError(tokio_tun::Error),
    NetnsError(netns_rs::Error),
    IoError(std::io::Error),
    ChannelRecvError(tokio::sync::oneshot::error::RecvError),
    FailedInvocation(ExitStatus),
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
    F: 'static + Send + FnOnce(Arc<FirecrackerNetworkInner>, Arc<NamespacedData>) -> Fut,
    Fut: Send + Future<Output = Result<(), FirecrackerNetworkError>>,
>(
    netns_name: String,
    network: Arc<FirecrackerNetworkInner>,
    namespaced_data: Arc<NamespacedData>,
    function: F,
) -> Result<(), FirecrackerNetworkError> {
    let netns = NetNs::new(netns_name).map_err(FirecrackerNetworkError::NetnsError)?;
    let (sender, receiver) = tokio::sync::oneshot::channel();

    std::thread::spawn(move || {
        let result = {
            match tokio::runtime::Builder::new_current_thread().build() {
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
