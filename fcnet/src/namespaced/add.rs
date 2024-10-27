use std::{net::IpAddr, os::fd::AsRawFd, vec};

use cidr::IpInet;
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression},
    schema::{NfListObject, Rule},
    stmt::{Match, NATFamily, Operator, Statement, NAT},
};
use nftables_async::{apply_ruleset, get_current_ruleset};
use tokio_tun::TunBuilder;

use crate::{
    add_base_chains_if_needed, get_link_index, nat_proto_from_inet, netns::NetNs, FirecrackerNetwork, FirecrackerNetworkError,
    NFT_POSTROUTING_CHAIN, NFT_TABLE,
};

use super::{use_netns_in_thread, NamespacedData};

pub(super) async fn add(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    outer_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    add_interfaces(&namespaced_data, &outer_handle).await?;

    {
        let tap_name = network.tap_name.clone();
        let tap_ip = network.tap_ip.clone();
        let nft_path = network.nft_path.clone();
        let veth2_name = namespaced_data.veth2_name.to_string();
        let veth2_ip = *namespaced_data.veth2_ip;
        let guest_ip = network.guest_ip;
        let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
        use_netns_in_thread(namespaced_data.netns_name.to_string(), async move {
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
                .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

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
        })
        .await?;
    }

    add_outer_rules(&namespaced_data, network).await?;
    add_forward_route(&namespaced_data, &outer_handle).await
}

async fn add_interfaces(
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

async fn add_outer_rules(
    namespaced_data: &NamespacedData<'_>,
    network: &FirecrackerNetwork,
) -> Result<(), FirecrackerNetworkError> {
    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-t nat -A POSTROUTING -s {} -o {} -j MASQUERADE",
    //         namespaced_data.veth2_ip, network.iface_name
    //     ),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-A FORWARD -i {} -o {} -j ACCEPT",
    //         network.iface_name, namespaced_data.veth1_name
    //     ),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!(
    //         "-A FORWARD -o {} -i {} -j ACCEPT",
    //         network.iface_name, namespaced_data.veth1_name
    //     ),
    // )
    // .await?;

    let current_ruleset = get_current_ruleset(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut batch = Batch::new();
    add_base_chains_if_needed(network, &current_ruleset, &mut batch)?;

    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_POSTROUTING_CHAIN.to_string(),
        expr: vec![
            // Statement::SNAT(Some(NAT {
            //     family: Some(nat_proto_from_inet(namespaced_data.veth2_ip)),
            //     addr: Some(Expression::String(namespaced_data.veth2_ip.address().tostr)),
            //     port: None,
            //     flags: None,
            // })),
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

    apply_ruleset(&batch.to_nftables(), network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

async fn add_forward_route(
    namespaced_data: &NamespacedData<'_>,
    outer_handle: &rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
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
