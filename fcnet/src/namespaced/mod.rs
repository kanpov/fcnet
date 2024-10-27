use std::net::IpAddr;

use cidr::IpInet;
use nftables::{
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    stmt::{Match, Operator, Statement},
};

use crate::{
    nat_proto_from_addr, FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkOperation, FirecrackerNetworkType,
};
use std::future::Future;

mod add;
use add::add;
mod check;
use check::check;
mod delete;
use delete::delete;

struct NamespacedData<'a> {
    netns_name: &'a str,
    veth1_name: &'a str,
    veth2_name: &'a str,
    veth1_ip: &'a IpInet,
    veth2_ip: &'a IpInet,
    forwarded_guest_ip: &'a Option<IpAddr>,
}

pub async fn run(
    operation: FirecrackerNetworkOperation,
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    let namespaced_data = match network.network_type {
        #[cfg(feature = "simple")]
        FirecrackerNetworkType::Simple => unreachable!(),
        FirecrackerNetworkType::Namespaced {
            ref netns_name,
            ref veth1_name,
            ref veth2_name,
            ref veth1_ip,
            ref veth2_ip,
            ref forwarded_guest_ip,
        } => NamespacedData {
            netns_name,
            veth1_name,
            veth2_name,
            veth1_ip,
            veth2_ip,
            forwarded_guest_ip,
        },
    };

    match operation {
        FirecrackerNetworkOperation::Add => add(namespaced_data, network, netlink_handle).await,
        FirecrackerNetworkOperation::Check => check(namespaced_data, network, netlink_handle).await,
        FirecrackerNetworkOperation::Delete => delete(namespaced_data, network).await,
    }
}

#[cfg(feature = "namespaced")]
async fn use_netns_in_thread(
    netns_name: String,
    future: impl 'static + Send + Future<Output = Result<(), FirecrackerNetworkError>>,
) -> Result<(), FirecrackerNetworkError> {
    use crate::netns::NetNs;

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

fn outer_masq_expr(network: &FirecrackerNetwork, namespaced_data: &NamespacedData<'_>) -> Vec<Statement> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                protocol: nat_proto_from_addr(namespaced_data.veth2_ip.address()),
                field: "saddr".to_string(),
            }))),
            right: Expression::String(namespaced_data.veth2_ip.address().to_string()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(network.iface_name.to_string()),
            op: Operator::EQ,
        }),
        Statement::Masquerade(None),
    ]
}

fn outer_ingress_forward_expr(network: &FirecrackerNetwork, namespaced_data: &NamespacedData<'_>) -> Vec<Statement> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
            right: Expression::String(network.iface_name.clone()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(namespaced_data.veth1_name.to_string()),
            op: Operator::EQ,
        }),
        Statement::Accept(None),
    ]
}

fn outer_egress_forward_expr(network: &FirecrackerNetwork, namespaced_data: &NamespacedData<'_>) -> Vec<Statement> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(network.iface_name.clone()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
            right: Expression::String(namespaced_data.veth1_name.to_string()),
            op: Operator::EQ,
        }),
        Statement::Accept(None),
    ]
}
