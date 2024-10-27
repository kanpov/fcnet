use std::net::IpAddr;

use fcnet::{FirecrackerIpStack, FirecrackerNetwork};
use futures_util::TryStreamExt;
use nftables::{
    batch::Batch,
    schema::{Chain, NfListObject, NfObject, Nftables, Table},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

use crate::{Error, ObjectType, NFT_FILTER_CHAIN, NFT_POSTROUTING_CHAIN, NFT_TABLE};

pub async fn get_link_index(link: String, netlink_handle: &rtnetlink::Handle) -> Result<u32, Error> {
    Ok(netlink_handle
        .link()
        .get()
        .match_name(link)
        .execute()
        .try_next()
        .await
        .map_err(Error::NetlinkOperationError)?
        .ok_or(Error::ObjectNotFound(ObjectType::IpLink))?
        .header
        .index)
}

pub fn add_base_chains_if_needed(
    network: &FirecrackerNetwork,
    current_ruleset: &Nftables,
    batch: &mut Batch,
) -> Result<(), Error> {
    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut filter_chain_exists = false;

    for object in &current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match object.as_ref() {
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
                _ => continue,
            },
            _ => continue,
        }
    }

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

    Ok(())
}

pub fn check_base_chains(network: &FirecrackerNetwork, current_ruleset: &Nftables) -> Result<(), Error> {
    let mut table_exists = false;
    let mut postrouting_chain_exists = false;
    let mut filter_chain_exists = false;

    for object in &current_ruleset.objects {
        match object {
            NfObject::ListObject(object) => match object.as_ref() {
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
                _ => continue,
            },
            _ => continue,
        }
    }

    if !table_exists {
        return Err(Error::ObjectNotFound(ObjectType::NfTable));
    }

    if !postrouting_chain_exists {
        return Err(Error::ObjectNotFound(ObjectType::NfPostroutingChain));
    }

    if !filter_chain_exists {
        return Err(Error::ObjectNotFound(ObjectType::NfFilterChain));
    }

    Ok(())
}

#[inline]
pub fn nat_proto_from_addr(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(_) => "ip".to_string(),
        IpAddr::V6(_) => "ip6".to_string(),
    }
}

pub trait FirecrackerNetworkExt {
    fn nf_family(&self) -> NfFamily;
    fn nf_program(&self) -> Option<&str>;
}

impl FirecrackerNetworkExt for FirecrackerNetwork {
    #[inline]
    fn nf_family(&self) -> NfFamily {
        match self.ip_stack {
            FirecrackerIpStack::V4 => NfFamily::IP,
            FirecrackerIpStack::V6 => NfFamily::IP6,
            FirecrackerIpStack::Dual => NfFamily::INet,
        }
    }

    #[inline]
    fn nf_program(&self) -> Option<&str> {
        self.nft_path.as_ref().map(|p| p.as_str())
    }
}
