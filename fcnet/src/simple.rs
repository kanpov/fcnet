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
    get_link_index, FirecrackerNetwork, FirecrackerNetworkError, FirecrackerNetworkOperation, NFT_FILTER_FORWARD_CHAIN,
    NFT_FILTER_TABLE, NFT_NAT_POSTROUTING_CHAIN, NFT_NAT_TABLE,
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

    let current_ruleset = get_current_ruleset(None, None)
        .await
        .map_err(FirecrackerNetworkError::NftablesError)?;
    let mut nat_table_exists = false;
    let mut nat_chain_exists = false;
    let mut filter_table_exists = false;
    let mut filter_chain_exists = false;
    let mut masquerade_rule_exists = false;
    let masquerade_expr = vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
            right: Expression::String(network.iface_name.clone()),
            op: Operator::EQ,
        }),
        Statement::Masquerade(None),
    ];

    for object in current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match *object {
                NfListObject::Table(table) => {
                    if table.name == NFT_NAT_TABLE && table.family == network.nf_family() {
                        nat_table_exists = true;
                    } else if table.name == NFT_FILTER_TABLE && table.family == network.nf_family() {
                        filter_table_exists = true;
                    }
                }
                NfListObject::Chain(chain) => {
                    if chain.name == NFT_NAT_POSTROUTING_CHAIN && chain.table == NFT_NAT_TABLE {
                        nat_chain_exists = true;
                    } else if chain.name == NFT_FILTER_FORWARD_CHAIN && chain.table == NFT_FILTER_TABLE {
                        filter_chain_exists = true;
                    }
                }
                NfListObject::Rule(rule) => {
                    dbg!(&rule);
                    if rule.chain == NFT_NAT_POSTROUTING_CHAIN && rule.table == NFT_NAT_TABLE && rule.expr == masquerade_expr {
                        masquerade_rule_exists = true;
                    }
                }
                _ => continue,
            },
            _ => continue,
        }
    }

    let mut batch = Batch::new();
    if !nat_table_exists {
        batch.add(NfListObject::Table(Table {
            family: network.nf_family(),
            name: NFT_NAT_TABLE.to_string(),
            handle: None,
        }));
    }

    if !nat_chain_exists {
        batch.add(NfListObject::Chain(Chain {
            family: network.nf_family(),
            table: NFT_NAT_TABLE.to_string(),
            name: NFT_NAT_POSTROUTING_CHAIN.to_string(),
            _type: Some(NfChainType::NAT),
            hook: Some(NfHook::Postrouting),
            prio: Some(100),
            policy: Some(NfChainPolicy::Accept),
            newname: None,
            dev: None,
            handle: None,
        }));
    }

    if !filter_table_exists {
        batch.add(NfListObject::Table(Table {
            family: network.nf_family(),
            name: NFT_FILTER_TABLE.to_string(),
            handle: None,
        }));
    }

    if !filter_chain_exists {
        batch.add(NfListObject::Chain(Chain {
            family: network.nf_family(),
            table: NFT_FILTER_TABLE.to_string(),
            name: NFT_FILTER_FORWARD_CHAIN.to_string(),
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
        table: NFT_FILTER_TABLE.to_string(),
        chain: NFT_FILTER_FORWARD_CHAIN.to_string(),
        expr: vec![
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
        ],
        handle: None,
        index: None,
        comment: None,
    }));

    // masquerade from iface, created only once
    if !masquerade_rule_exists {
        batch.add(NfListObject::Rule(Rule {
            family: network.nf_family(),
            table: NFT_NAT_TABLE.to_string(),
            chain: NFT_NAT_POSTROUTING_CHAIN.to_string(),
            expr: masquerade_expr,
            handle: None,
            index: None,
            comment: None,
        }));
    }

    apply_ruleset(&batch.to_nftables(), None, None).await.unwrap();
    Ok(())
}

async fn delete(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    let tap_idx = get_link_index(network.tap_name.clone(), &netlink_handle).await?;
    netlink_handle
        .link()
        .del(tap_idx)
        .execute()
        .await
        .map_err(FirecrackerNetworkError::NetlinkOperationError)?;

    // run_iptables(
    //     &network.iptables_path,
    //     format!("-t nat -D POSTROUTING -o {} -j MASQUERADE", network.iface_name),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     "-D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!("-D FORWARD -i {} -o {} -j ACCEPT", network.tap_name, network.iface_name),
    // )
    // .await
    Ok(())
}

async fn check(network: &FirecrackerNetwork, netlink_handle: rtnetlink::Handle) -> Result<(), FirecrackerNetworkError> {
    get_link_index(network.tap_name.clone(), &netlink_handle).await?;

    // run_iptables(
    //     &network.iptables_path,
    //     format!("-t nat -C POSTROUTING -o {} -j MASQUERADE", network.iface_name),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     "-C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!("-C FORWARD -i {} -o {} -j ACCEPT", network.tap_name, network.iface_name),
    // )
    // .await
    Ok(())
}
