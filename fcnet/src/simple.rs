use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression},
    helper::apply_ruleset,
    schema::{Chain, NfListObject, Rule, Table},
    stmt::{Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfHook},
};
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

    let mut batch = Batch::new();
    // chains and tables
    batch.add(NfListObject::Table(Table {
        family: network.nf_family(),
        name: NFT_NAT_TABLE.to_string(),
        handle: Some(1),
    }));
    batch.add(NfListObject::Chain(Chain {
        family: network.nf_family(),
        table: NFT_NAT_TABLE.to_string(),
        name: NFT_NAT_POSTROUTING_CHAIN.to_string(),
        handle: Some(2),
        _type: Some(NfChainType::NAT),
        hook: Some(NfHook::Postrouting),
        prio: Some(100),
        policy: Some(NfChainPolicy::Accept),
        newname: None,
        dev: None,
    }));
    batch.add(NfListObject::Table(Table {
        family: network.nf_family(),
        name: NFT_FILTER_TABLE.to_string(),
        handle: Some(3),
    }));
    batch.add(NfListObject::Chain(Chain {
        family: network.nf_family(),
        table: NFT_FILTER_TABLE.to_string(),
        name: NFT_FILTER_FORWARD_CHAIN.to_string(),
        handle: Some(4),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Forward),
        prio: Some(0),
        policy: Some(NfChainPolicy::Accept),
        newname: None,
        dev: None,
    }));
    // rules
    batch.add(NfListObject::Rule(Rule {
        family: network.nf_family(),
        table: NFT_NAT_TABLE.to_string(),
        chain: NFT_NAT_POSTROUTING_CHAIN.to_string(),
        handle: Some(5),
        expr: vec![
            Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Oifname })),
                right: Expression::String(network.iface_name.clone()),
                op: Operator::EQ,
            }),
            Statement::Masquerade(None),
        ],
        index: None,
        comment: None,
    }));
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
        handle: Some(7),
        index: None,
        comment: None,
    }));

    tokio::task::spawn_blocking(move || apply_ruleset(&batch.to_nftables(), None, None))
        .await
        .unwrap()
        .unwrap();

    // run_iptables(
    //     &network.iptables_path,
    //     format!("-t nat -A POSTROUTING -o {} -j MASQUERADE", network.iface_name),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT".to_string(),
    // )
    // .await?;
    // run_iptables(
    //     &network.iptables_path,
    //     format!("-A FORWARD -i {} -o {} -j ACCEPT", network.tap_name, network.iface_name),
    // )
    // .await
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
