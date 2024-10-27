use fcnet_core::FirecrackerNetwork;
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    schema::{NfListObject, NfObject, Rule},
    stmt::{Match, Operator, Statement},
};
use nftables_async::{apply_ruleset, get_current_ruleset};
use tokio_tun::TunBuilder;

use crate::{
    util::{add_base_chains_if_needed, check_base_chains, get_link_index, nat_proto_from_addr, FirecrackerNetworkExt},
    FirecrackerNetworkError, FirecrackerNetworkObject, FirecrackerNetworkOperation, NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN,
    NFT_TABLE,
};

pub async fn run(
    network: &FirecrackerNetwork,
    netlink_handle: rtnetlink::Handle,
    operation: FirecrackerNetworkOperation,
) -> Result<(), FirecrackerNetworkError> {
    match operation {
        FirecrackerNetworkOperation::Add => add(network, netlink_handle).await,
        FirecrackerNetworkOperation::Check => check(network, netlink_handle).await,
        FirecrackerNetworkOperation::Delete => delete(network, netlink_handle).await,
    }
}

async fn add(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    TunBuilder::new()
        .name(&network.tap_name)
        .tap()
        .persist()
        .up()
        .try_build()
        .map_err(FirecrackerNetworkError::TapDeviceError)?;
    let tap_idx = crate::util::get_link_index(network.tap_name.clone(), &netlink_handle).await?;
    netlink_handle
        .address()
        .add(tap_idx, network.tap_ip.address(), network.tap_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let current_ruleset = get_current_ruleset(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut masquerade_rule_exists = false;

    for object in &current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match object.as_ref() {
                NfListObject::Rule(rule)
                    if rule.chain == NFT_POSTROUTING_CHAIN && rule.table == NFT_TABLE && rule.expr == masq_expr(network) =>
                {
                    masquerade_rule_exists = true;
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    let mut batch = Batch::new();
    add_base_chains_if_needed(&network, &current_ruleset, &mut batch)?;

    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_FILTER_CHAIN.to_string(),
        expr: forward_expr(network),
        handle: None,
        index: None,
        comment: None,
    }));

    if !masquerade_rule_exists {
        batch.add(NfListObject::Rule(Rule {
            family: network.nf_family(),
            table: NFT_TABLE.to_string(),
            chain: NFT_POSTROUTING_CHAIN.to_string(),
            expr: masq_expr(network),
            handle: None,
            index: None,
            comment: None,
        }));
    }

    apply_ruleset(&batch.to_nftables(), network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

async fn delete(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await?;
    netlink_handle
        .link()
        .del(tap_idx)
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let current_ruleset = get_current_ruleset(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;

    let mut forward_rule_handle = None;
    let mut masquerade_rule_handle = None;

    for object in current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match *object {
                NfListObject::Rule(rule) if rule.table == NFT_TABLE => {
                    if rule.chain == NFT_FILTER_CHAIN && rule.expr == forward_expr(network) {
                        forward_rule_handle = rule.handle;
                    } else if rule.chain == NFT_POSTROUTING_CHAIN && rule.expr == masq_expr(network) {
                        masquerade_rule_handle = rule.handle;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if forward_rule_handle.is_none() {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfEgressForwardRule,
        ));
    }
    if masquerade_rule_handle.is_none() {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfMasqueradeRule,
        ));
    }

    let mut batch = Batch::new();
    batch.delete(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_FILTER_CHAIN.to_string(),
        expr: forward_expr(network),
        handle: forward_rule_handle,
        index: None,
        comment: None,
    }));
    batch.delete(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_POSTROUTING_CHAIN.to_string(),
        expr: masq_expr(network),
        handle: masquerade_rule_handle,
        index: None,
        comment: None,
    }));

    apply_ruleset(&batch.to_nftables(), network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

async fn check(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    get_link_index(network.tap_name.clone(), &netlink_handle).await?;

    let current_ruleset = get_current_ruleset(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut masquerade_rule_exists = false;
    let mut forward_rule_exists = false;

    check_base_chains(network, &current_ruleset)?;

    for object in current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match *object {
                NfListObject::Rule(rule) => {
                    if rule.chain == NFT_POSTROUTING_CHAIN && rule.expr == masq_expr(network) {
                        masquerade_rule_exists = true;
                    } else if rule.chain == NFT_FILTER_CHAIN && rule.expr == forward_expr(network) {
                        forward_rule_exists = true;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if !masquerade_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfMasqueradeRule,
        ));
    }

    if !forward_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfEgressForwardRule,
        ));
    }

    Ok(())
}

#[inline]
fn masq_expr(network: &FirecrackerNetwork) -> Vec<Statement> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
                protocol: nat_proto_from_addr(network.guest_ip.address()),
                field: "saddr".to_string(),
            }))),
            right: Expression::String(network.guest_ip.address().to_string()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(network.iface_name.clone()),
            op: Operator::EQ,
        }),
        Statement::Masquerade(None),
    ]
}

#[inline]
fn forward_expr(network: &FirecrackerNetwork) -> Vec<Statement> {
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Iifname })),
            right: Expression::String(network.tap_name.clone()),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(network.iface_name.clone()),
            op: Operator::EQ,
        }),
        Statement::Accept(None),
    ]
}
