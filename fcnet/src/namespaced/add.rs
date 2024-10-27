use std::{net::IpAddr, os::fd::AsRawFd, vec};

use cidr::IpInet;
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    schema::{NfListObject, Rule},
    stmt::{Match, Operator, Statement},
};
use nftables_async::{apply_ruleset, get_current_ruleset};
use tokio_tun::TunBuilder;

use crate::{
    add_base_chains_if_needed, get_link_index, nat_proto_from_inet, netns::NetNs, FirecrackerNetwork, FirecrackerNetworkError,
    NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN, NFT_TABLE,
};

use super::{use_netns_in_thread, NamespacedData};

pub(super) async fn add(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    outer_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    setup_outer_interfaces(&namespaced_data, &outer_handle).await?;

    {
        let tap_name = network.tap_name.clone();
        let tap_ip = network.tap_ip.clone();
        let nft_path = network.nft_path.clone();
        let veth2_name = namespaced_data.veth2_name.to_string();
        let veth2_ip = *namespaced_data.veth2_ip;
        let guest_ip = network.guest_ip;
        let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
        use_netns_in_thread(namespaced_data.netns_name.to_string(), async move {
            setup_inner_interfaces(tap_name, tap_ip, veth2_name.clone(), veth2_ip).await?;
            setup_inner_nf_rules(nft_path, veth2_name, veth2_ip, forwarded_guest_ip, guest_ip).await
        })
        .await?;
    }

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
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                    protocol: nat_proto_from_inet(&namespaced_data.veth2_ip),
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
        ],
        handle: None,
        index: None,
        comment: None,
    }));

    // forward packets from host iface to veth
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_FILTER_CHAIN.to_string(),
        expr: vec![
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
        ],
        handle: None,
        index: None,
        comment: None,
    }));

    // forward packets from veth to host iface
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_FILTER_CHAIN.to_string(),
        expr: vec![
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
        ],
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

    match veth2_ip {
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
    nft_path: Option<String>,
    veth2_name: String,
    veth2_ip: IpInet,
    forwarded_guest_ip: Option<IpAddr>,
    guest_ip: IpInet,
) -> Result<(), FirecrackerNetworkError> {
    // run_iptables(
    //     &iptables_path,
    //     format!(
    //         "-t nat -A POSTROUTING -o {} -s {} -j SNAT --to {}",
    //         veth2_name,
    //         guest_ip,
    //         veth2_ip.address()
    //     ),
    // )
    // .await?;

    if let Some(forwarded_guest_ip) = forwarded_guest_ip {
        // run_iptables(
        //     &iptables_path,
        //     format!(
        //         "-t nat -A PREROUTING -i {} -d {} -j DNAT --to {}",
        //         veth2_name, forwarded_guest_ip, guest_ip
        //     ),
        // )
        // .await?;
    }

    Ok(())
}
