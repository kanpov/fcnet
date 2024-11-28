use std::future::Future;

use netlink_packet_route::RouteNetlinkMessage;
use netlink_proto::Connection;

pub trait Backend: Send + Sync + 'static {
    type NetlinkSocket: netlink_sys::AsyncSocket + Send;

    fn spawn_connection(connection: Connection<RouteNetlinkMessage, Self::NetlinkSocket>);

    fn block_on_current_thread<O, F: Future<Output = O>>(future: F) -> O;
}

#[cfg(feature = "tokio-backend")]
pub struct TokioBackend;

#[cfg(feature = "tokio-backend")]
impl Backend for TokioBackend {
    type NetlinkSocket = netlink_proto::sys::TokioSocket;

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
