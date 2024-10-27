use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression},
    schema::{Chain, NfListObject, NfObject, Rule, Table},
    stmt::{Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfHook},
};
use nftables_async::{apply_ruleset, get_current_ruleset};
use tokio_tun::TunBuilder;

use crate::{
    get_link_index, FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkObject, FirecrackerNetworkOperation,
    NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN, NFT_TABLE,
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
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await?;
    netlink_handle
        .address()
        .add(tap_idx, network.tap_ip.address(), network.tap_ip.network_length())
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    let current_ruleset = get_current_ruleset(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut filter_chain_exists = false;
    let mut masquerade_rule_exists = false;

    for object in current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match *object {
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

    // accept from tap to iface, created once per network
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_TABLE.to_string(),
        chain: NFT_FILTER_CHAIN.to_string(),
        expr: forward_expr(network),
        handle: None,
        index: None,
        comment: None,
    }));
    // masquerade from iface, created only once
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

    for object in current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match *object {
                NfListObject::Rule(rule) => {
                    if rule.table == NFT_TABLE && rule.chain == NFT_FILTER_CHAIN && rule.expr == forward_expr(network) {
                        forward_rule_handle = rule.handle;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    if forward_rule_handle.is_none() {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfForwardRule,
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
    apply_ruleset(&batch.to_nftables(), network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)
}

async fn check(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    get_link_index(network.tap_name.clone(), &netlink_handle).await?;

    let current_ruleset = get_current_ruleset(network.nf_program(), None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut filter_chain_exists = false;
    let mut masquerade_rule_exists = false;
    let mut forward_rule_exists = false;

    for object in current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match *object {
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

    if !masquerade_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfMasqueradeRule,
        ));
    }

    if !forward_rule_exists {
        return Err(FirecrackerNetworkError::ObjectNotFound(
            FirecrackerNetworkObject::NfForwardRule,
        ));
    }

    Ok(())
}

#[inline]
fn masq_expr(network: &FirecrackerNetwork) -> Vec<Statement> {
    vec![
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
