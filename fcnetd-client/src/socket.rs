use std::{future::Future, path::Path};

#[cfg(feature = "smol-socket")]
use futures_lite::{AsyncBufReadExt as SmolAsyncBufReadExt, AsyncWriteExt as SmolAsyncWriteExt, StreamExt};
#[cfg(feature = "tokio-socket")]
use tokio::io::{AsyncBufReadExt as TokioAsyncBufReadExt, AsyncWriteExt as TokioAsyncWriteExt};

/// The [Socket] trait is a basic abstraction over an underlying asynchronous Unix socket connection used
/// by this crate to connect to fcnetd. This allows for different async I/O implementations to be used
/// interchangeably by implementing this trait.
pub trait Socket: Send + Sync + Sized + Unpin {
    fn connect(socket_path: &Path) -> impl Future<Output = Result<Self, std::io::Error>> + Send;

    fn write_line(&mut self, line: String) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn read_line(&mut self) -> impl Future<Output = Result<Option<String>, std::io::Error>> + Send;
}

/// A [Socket] that uses a [UnixStream](tokio::net::UnixStream) from the [tokio] crate internally.
#[cfg(feature = "tokio-socket")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-socket")))]
pub struct TokioSocket(tokio::net::UnixStream);

#[cfg(feature = "tokio-socket")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio-socket")))]
impl Socket for TokioSocket {
    async fn connect(socket_path: &Path) -> Result<Self, std::io::Error> {
        tokio::net::UnixStream::connect(socket_path).await.map(Self)
    }

    async fn write_line(&mut self, line: String) -> Result<(), std::io::Error> {
        self.0.write_all(format!("{line}\n").as_bytes()).await
    }

    async fn read_line(&mut self) -> Result<Option<String>, std::io::Error> {
        let mut lines = tokio::io::BufReader::new(&mut self.0).lines();
        lines.next_line().await
    }
}

/// A [Socket] that uses a [UnixStream](async_net::unix::UnixStream) from the [async_net] crate internally.
#[cfg(feature = "smol-socket")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol-socket")))]
pub struct SmolSocket(async_net::unix::UnixStream);

#[cfg(feature = "smol-socket")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol-socket")))]
impl Socket for SmolSocket {
    async fn connect(socket_path: &Path) -> Result<Self, std::io::Error> {
        async_net::unix::UnixStream::connect(socket_path).await.map(Self)
    }

    async fn write_line(&mut self, line: String) -> Result<(), std::io::Error> {
        self.0.write_all(format!("{line}\n").as_bytes()).await
    }

    async fn read_line(&mut self) -> Result<Option<String>, std::io::Error> {
        let mut lines = futures_lite::io::BufReader::new(&mut self.0).lines();
        lines.next().await.transpose()
    }
}
