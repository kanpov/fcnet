use std::{net::IpAddr, os::fd::AsRawFd, vec};

use cidr::IpInet;
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    schema::{Chain, NfListObject, Rule, Table},
    stmt::{Match, NATFamily, Operator, Statement, NAT},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};
use nftables_async::{apply_ruleset, get_current_ruleset};
use tokio_tun::TunBuilder;

use crate::{
    add_base_chains_if_needed, get_link_index, nat_proto_from_addr, netns::NetNs, FirecrackerNetwork, FirecrackerNetworkError,
    NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN, NFT_PREROUTING_CHAIN, NFT_TABLE,
};

use super::{outer_egress_forward_expr, outer_ingress_forward_expr, outer_masq_expr, use_netns_in_thread, NamespacedData};

pub(super) async fn add(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    outer_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    setup_outer_interfaces(&namespaced_data, &outer_handle).await?;

    let tap_name = network.tap_name.clone();
    let tap_ip = network.tap_ip.clone();
    let nft_path = network.nft_path.clone();
    let veth2_name = namespaced_data.veth2_name.to_string();
    let veth1_ip = *namespaced_data.veth1_ip;
    let veth2_ip = *namespaced_data.veth2_ip;
    let guest_ip = network.guest_ip;
    let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
    let nf_family = network.nf_family();
    use_netns_in_thread(namespaced_data.netns_name.to_string(), async move {
        setup_inner_interfaces(tap_name, tap_ip, veth2_name.clone(), veth2_ip, veth1_ip).await?;
        setup_inner_nf_rules(nf_family, nft_path, veth2_name, veth2_ip, forwarded_guest_ip, guest_ip).await
    })
    .await?;

    setup_outer_nf_rules(&namespaced_data, network).await?;
    setup_outer_forward_route(&namespaced_data, &outer_handle).await
}

async fn setup_outer_interfaces(
    namespaced_data: &NamespacedData<'_>,
    outer_handle: &rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    outer_handle
        .link()
        .add()
        .veth(namespaced_data.veth1_name.to_string(), namespaced_data.veth2_name.to_string())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let veth1_idx = get_link_index(namespaced_data.veth1_name.to_string(), &outer_handle).await?;
    outer_handle
        .address()
        .add(
            veth1_idx,
            namespaced_data.veth1_ip.address(),
            namespaced_data.veth1_ip.network_length(),
        )
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    outer_handle
        .link()
        .set(veth1_idx)
        .up()
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    outer_handle
        .link()
        .set(get_link_index(namespaced_data.veth2_name.to_string(), &outer_handle).await?)
        .setns_by_fd(
            NetNs::new(&namespaced_data.netns_name)
                .map_err(FirecrackerNetworkError::NetnsError)?
                .file()
                .as_raw_fd(),
        )
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)
}

async fn setup_outer_nf_rules(
    namespaced_data: &NamespacedData<'_>,
    network: &FirecrackerNetwork,
) -> Result<(), FirecrackerNetworkError> {
    let current_ruleset = get_current_ruleset(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut batch = Batch::new();
    add_base_chains_if_needed(network, &current_ruleset, &mut batch)?;

    // masquerade veth packets as host iface packets
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_POSTROUTING_CHAIN.to_string(),
        expr: outer_masq_expr(network, namespaced_data),
        handle: None,
        index: None,
        comment: None,
    }));

    // forward ingress packets from host iface to veth
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_FILTER_CHAIN.to_string(),
        expr: outer_ingress_forward_expr(network, namespaced_data),
        handle: None,
        index: None,
        comment: None,
    }));

    // forward egress packets from veth to host iface
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_FILTER_CHAIN.to_string(),
        expr: outer_egress_forward_expr(network, namespaced_data),
        handle: None,
        index: None,
        comment: None,
    }));

    apply_ruleset(&batch.to_nftables(), network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

async fn setup_outer_forward_route(
    namespaced_data: &NamespacedData<'_>,
    outer_handle: &rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    // route packets going to forwarded guest ip into the netns, where they are then resolved via DNAT to the
    // guest ip available only in the netns
    if let Some(forwarded_guest_ip) = namespaced_data.forwarded_guest_ip {
        match forwarded_guest_ip {
            IpAddr::V4(v4) => outer_handle
                .route()
                .add()
                .v4()
                .destination_prefix(*v4, 32)
                .gateway(match namespaced_data.veth2_ip.address() {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => return Err(FirecrackerNetworkError::ForbiddenDualStackInRoute),
                })
                .execute()
                .await
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?,
            IpAddr::V6(v6) => outer_handle
                .route()
                .add()
                .v6()
                .destination_prefix(*v6, 128)
                .gateway(match namespaced_data.veth2_ip.address() {
                    IpAddr::V4(_) => return Err(FirecrackerNetworkError::ForbiddenDualStackInRoute),
                    IpAddr::V6(v6) => v6,
                })
                .execute()
                .await
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?,
        };
    }
    Ok(())
}

async fn setup_inner_interfaces(
    tap_name: String,
    tap_ip: IpInet,
    veth2_name: String,
    veth2_ip: IpInet,
    veth1_ip: IpInet,
) -> Result<(), FirecrackerNetworkError> {
    TunBuilder::new()
        .name(&tap_name)
        .tap()
        .persist()
        .up()
        .try_build()
        .map_err(FirecrackerNetworkError::TapDeviceError)?;
    let (connection, inner_handle, _) = rtnetlink::new_connection().map_err(FirecrackerNetworkError::IoError)?;
    tokio::task::spawn(connection);

    let veth2_idx = get_link_index(veth2_name.clone(), &inner_handle).await?;
    inner_handle
        .address()
        .add(veth2_idx, veth2_ip.address(), veth2_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
    inner_handle
        .link()
        .set(veth2_idx)
        .up()
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    match veth1_ip {
        IpInet::V4(ref veth1_ip) => inner_handle
            .route()
            .add()
            .v4()
            .gateway(veth1_ip.address())
            .execute()
            .await
            .map_err(FirecrackerNetworkError::NetlinkOperationError)?,
        IpInet::V6(ref veth1_ip) => inner_handle
            .route()
            .add()
            .v6()
            .gateway(veth1_ip.address())
            .execute()
            .await
            .map_err(FirecrackerNetworkError::NetlinkOperationError)?,
    }

    let tap_idx = get_link_index(tap_name, &inner_handle).await?;
    inner_handle
        .address()
        .add(tap_idx, tap_ip.address(), tap_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;
    inner_handle
        .link()
        .set(tap_idx)
        .up()
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)
}

async fn setup_inner_nf_rules(
    nf_family: NfFamily,
    nft_path: Option<String>,
    veth2_name: String,
    veth2_ip: IpInet,
    forwarded_guest_ip: Option<IpAddr>,
    guest_ip: IpInet,
) -> Result<(), FirecrackerNetworkError> {
    let mut batch = Batch::new();

    // create table, postrouting and prerouting chains (prerouting only needed when using forwarding)
    batch.add(NfListObject::Table(Table {
        family: nf_family,
        name: NFT_TABLE.to_string(),
        handle: None,
    }));

    batch.add(NfListObject::Chain(Chain {
        family: nf_family,
        table: NFT_TABLE.to_string(),
        name: NFT_POSTROUTING_CHAIN.to_string(),
        newname: None,
        handle: None,
        _type: Some(NfChainType::NAT),
        hook: Some(NfHook::Postrouting),
        prio: Some(100),
        dev: None,
        policy: Some(NfChainPolicy::Accept),
    }));

    if let Some(_) = forwarded_guest_ip {
        batch.add(NfListObject::Chain(Chain {
            family: nf_family,
            table: NFT_TABLE.to_string(),
            name: NFT_PREROUTING_CHAIN.to_string(),
            newname: None,
            handle: None,
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Prerouting),
            prio: Some(-100),
            policy: Some(NfChainPolicy::Accept),
            dev: None,
        }));
    }

    // SNAT packets coming from the guest ip to the veth2 ip so that outer netns forwards them not from the
    // guest ip local to the inner netns, but from the known veth2 ip
    batch.add(NfListObject::Rule(Rule {
        family: nf_family,
        table: NFT_TABLE.to_string(),
        chain: NFT_POSTROUTING_CHAIN.to_string(),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
                right: Expression::String(veth2_name.clone()),
                op: Operator::EQ,
            }),
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                    protocol: nat_proto_from_addr(guest_ip.address()),
                    field: "saddr".to_string(),
                }))),
                right: Expression::String(guest_ip.address().to_string()),
                op: Operator::EQ,
            }),
            Statement::SNAT(Some(NAT {
                addr: Some(Expression::String(veth2_ip.address().to_string())),
                family: Some(nat_family_from_inet(&veth2_ip)),
                port: None,
                flags: None,
            })),
        ],
        handle: None,
        index: None,
        comment: None,
    }));

    // DNAT packets coming to the forwarded guest ip via a route in the outer netns to the actual guest
    // ip local to the inner netns
    if let Some(forwarded_guest_ip) = forwarded_guest_ip {
        batch.add(NfListObject::Rule(Rule {
            family: nf_family,
            table: NFT_TABLE.to_string(),
            chain: NFT_PREROUTING_CHAIN.to_string(),
            expr: vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
                    right: Expression::String(veth2_name),
                    op: Operator::EQ,
                }),
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                        protocol: nat_proto_from_addr(forwarded_guest_ip),
                        field: "daddr".to_string(),
                    }))),
                    right: Expression::String(forwarded_guest_ip.to_string()),
                    op: Operator::EQ,
                }),
                Statement::DNAT(Some(NAT {
                    addr: Some(Expression::String(guest_ip.address().to_string())),
                    family: Some(nat_family_from_inet(&guest_ip)),
                    port: None,
                    flags: None,
                })),
            ],
            handle: None,
            index: None,
            comment: None,
        }));
    }

    apply_ruleset(&batch.to_nftables(), nft_path.as_deref(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

fn nat_family_from_inet(inet: &IpInet) -> NATFamily {
    match inet {
        IpInet::V4(_) => NATFamily::IP,
        IpInet::V6(_) => NATFamily::IP6,
    }
}
