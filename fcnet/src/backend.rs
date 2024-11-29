#[cfg(feature = "smol-backend")]
use async_executor::{Executor, LocalExecutor};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_proto::Connection;
use std::future::Future;
#[cfg(feature = "smol-backend")]
use std::sync::{Arc, OnceLock};

pub trait Backend: Send + Sync + 'static {
    type NetlinkSocket: netlink_sys::AsyncSocket + Send;
    type NftablesProcess: nftables_async::process::Process;

    fn spawn_connection(connection: Connection<RouteNetlinkMessage, Self::NetlinkSocket>);

    fn block_on_current_thread<O, F: Future<Output = O>>(future: F) -> O;
}

#[cfg(feature = "tokio-backend")]
pub struct TokioBackend;

#[cfg(feature = "tokio-backend")]
impl Backend for TokioBackend {
    type NetlinkSocket = netlink_proto::sys::TokioSocket;
    type NftablesProcess = nftables_async::process::TokioProcess;

    fn spawn_connection(connection: Connection<RouteNetlinkMessage, Self::NetlinkSocket>) {
        tokio::task::spawn(connection);
    }

    fn block_on_current_thread<O, F: Future<Output = O>>(future: F) -> O {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Could not build current-thread Tokio runtime. This panic should be isolated to another thread")
            .block_on(future)
    }
}

#[cfg(feature = "smol-backend")]
static SMOL_EXECUTOR: OnceLock<Arc<Executor>> = OnceLock::new();

#[cfg(feature = "smol-backend")]
pub struct SmolBackend;

#[cfg(feature = "smol-backend")]
impl SmolBackend {
    pub fn initialize(executor: impl Into<Arc<Executor<'static>>>) {
        SMOL_EXECUTOR
            .set(executor.into())
            .expect("Smol executor was already initialized");
    }
}

#[cfg(feature = "smol-backend")]
impl Backend for SmolBackend {
    type NetlinkSocket = netlink_proto::sys::SmolSocket;
    type NftablesProcess = nftables_async::process::AsyncProcess;

    fn spawn_connection(connection: Connection<RouteNetlinkMessage, Self::NetlinkSocket>) {
        SMOL_EXECUTOR
            .get()
            .expect("Smol executor wasn't initialized")
            .spawn(connection)
            .detach();
    }

    fn block_on_current_thread<O, F: Future<Output = O>>(future: F) -> O {
        async_io::block_on(LocalExecutor::new().run(future))
    }
}
