use std::net::IpAddr;

use futures_util::TryStreamExt;
use netlink_packet_route::route::{RouteAddress, RouteAttribute};
use nftables::schema::{NfListObject, NfObject};
use nftables_async::get_current_ruleset;
use rtnetlink::IpVersion;

use crate::{
    check_base_chains, FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkObject, NFT_FILTER_CHAIN,
    NFT_POSTROUTING_CHAIN, NFT_TABLE,
};

use super::{outer_egress_forward_expr, outer_ingress_forward_expr, outer_masq_expr, use_netns_in_thread, NamespacedData};

pub(super) async fn check(
    namespaced_data: NamespacedData<'_>,
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    check_outer_nf_rules(network, &namespaced_data).await?;

    {
        let nft_path = network.nft_path.clone();
        let forwarded_guest_ip = *namespaced_data.forwarded_guest_ip;
        let veth2_name = namespaced_data.veth2_name.to_string();
        let veth2_ip = *namespaced_data.veth2_ip;
        let guest_ip = network.guest_ip;
        use_netns_in_thread(namespaced_data.netns_name.to_string(), async move {
            check_inner_nf_rules(nft_path, forwarded_guest_ip).await
        })
        .await?;
    }

    check_outer_forward_route(namespaced_data, netlink_handle).await
}

async fn check_outer_nf_rules(
    network: &FirecrackerNetwork,
    namespaced_data: &NamespacedData<'_>,
) -> Result<(), FirecrackerNetworkError> {
    let current_ruleset = get_current_ruleset(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    check_base_chains(network, &current_ruleset)?;

    let mut outer_masq_rule_exists = false;
    let mut outer_ingress_forward_rule_exists = false;
    let mut outer_egress_forward_rule_exists = false;

    for object in current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match *object {
                NfListObject::Rule(rule) if rule.table == NFT_TABLE.to_string() => {
                    if rule.chain == NFT_POSTROUTING_CHAIN && rule.expr == outer_masq_expr(network, &namespaced_data) {
                        outer_masq_rule_exists = true;
                    } else if rule.chain == NFT_FILTER_CHAIN {
                        if rule.expr == outer_ingress_forward_expr(network, &namespaced_data) {
                            outer_ingress_forward_rule_exists = true;
                        } else if rule.expr == outer_egress_forward_expr(network, &namespaced_data) {
                            outer_egress_forward_rule_exists = true;
                        }
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if !outer_masq_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfMasqueradeRule,
        ));
    }

    if !outer_ingress_forward_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfIngressForwardRule,
        ));
    }

    if !outer_egress_forward_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfEgressForwardRule,
        ));
    }

    Ok(())
}

async fn check_outer_forward_route(
    namespaced_data: NamespacedData<'_>,
    netlink_handle: rtnetlink::Handle,
) -> Result<(), FirecrackerNetworkError> {
    if let Some(forwarded_guest_ip) = namespaced_data.forwarded_guest_ip {
        let ip_version = match forwarded_guest_ip {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        };
        let mut route_message = None;
        let mut route_message_stream = netlink_handle.route().get(ip_version).execute();

        while let Ok(Some(current_route_message)) = route_message_stream.try_next().await {
            for attribute in &current_route_message.attributes {
                if let RouteAttribute::Destination(route_addr) = attribute {
                    let ip_addr = match route_addr {
                        RouteAddress::Inet(i) => IpAddr::V4(*i),
                        RouteAddress::Inet6(i) => IpAddr::V6(*i),
                        _ => continue,
                    };

                    if ip_addr == *forwarded_guest_ip {
                        route_message = Some(current_route_message);
                        break;
                    }
                }
            }
        }

        if route_message.is_none() {
            return Err(FirecrackerNetworkError::ObjectNotFound(FirecrackerNetworkObject::IpRoute));
        }
    }

    Ok(())
}

async fn check_inner_nf_rules(
    nft_path: Option<String>,
    forwarded_guest_ip: Option<IpAddr>,
) -> Result<(), FirecrackerNetworkError> {
    let current_ruleset = get_current_ruleset(nft_path.as_deref(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;

    // run_iptables(
    //     &iptables_path,
    //     format!(
    //         "-t nat -C POSTROUTING -o {} -s {} -j SNAT --to {}",
    //         veth2_name,
    //         guest_ip,
    //         veth2_ip.address()
    //     ),
    // )
    // .await?;

    if let Some(ref forwarded_guest_ip) = forwarded_guest_ip {
        // run_iptables(
        //     &iptables_path,
        //     format!(
        //         "-t nat -C PREROUTING -i {} -d {} -j DNAT --to {}",
        //         veth2_name, forwarded_guest_ip, guest_ip
        //     ),
        // )
        // .await?;
    }

    Ok(())
}
