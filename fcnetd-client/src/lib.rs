use std::path::Path;
#[cfg(feature = "deadpool")]
use std::path::PathBuf;

use fcnet_types::{FirecrackerNetwork, FirecrackerNetworkOperation};
use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

const OK_RESPONSE: &str = "OK";

#[derive(Debug, thiserror::Error)]
pub enum FcnetdError {
    #[error("Writing the request to the connection failed: {0}")]
    RequestWriteError(std::io::Error),
    #[error("Serializing the request to JSON failed: {0}")]
    RequestSerializeError(serde_json::Error),
    #[error("Reading the response from the connection failed: {0}")]
    ResponseReadError(std::io::Error),
    #[error("The connection was closed before a response could be received")]
    ConnectionClosed,
    #[error("The daemon returned a failure of the requested operation: {0}")]
    OperationFailed(String),
}

#[derive(Debug)]
pub struct FcnetdConnection {
    stream: UnixStream,
}

#[derive(Serialize)]
struct Request<'net> {
    operation: FirecrackerNetworkOperation,
    network: &'net FirecrackerNetwork,
}

#[derive(Debug)]
#[cfg(feature = "connection-pool")]
pub struct FcnetdConnectionPool {
    path: PathBuf,
    password: Option<String>,
}

#[cfg(feature = "connection-pool")]
impl FcnetdConnectionPool {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            password: None,
        }
    }

    pub fn new_with_password(path: impl Into<PathBuf>, password: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            password: Some(password.into()),
        }
    }
}

#[cfg(feature = "deadpool")]
impl deadpool::managed::Manager for FcnetdConnectionPool {
    type Type = FcnetdConnection;

    type Error = std::io::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        match self.password {
            Some(ref password) => FcnetdConnection::connect_with_password(&self.path, password).await,
            None => FcnetdConnection::connect(&self.path).await,
        }
    }

    async fn recycle(
        &self,
        _obj: &mut Self::Type,
        _metrics: &deadpool::managed::Metrics,
    ) -> deadpool::managed::RecycleResult<Self::Error> {
        deadpool::managed::RecycleResult::Ok(())
    }
}

impl FcnetdConnection {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self { stream })
    }

    pub async fn connect_with_password(path: impl AsRef<Path>, password: impl Into<String>) -> Result<Self, std::io::Error> {
        let password = password.into();
        let mut stream = UnixStream::connect(path).await?;
        stream.write_all(format!("{password}\n").as_bytes()).await?;
        Ok(Self { stream })
    }

    pub async fn run(&mut self, network: &FirecrackerNetwork, operation: FirecrackerNetworkOperation) -> Result<(), FcnetdError> {
        let request = Request { operation, network };
        let request_json = serde_json::to_string(&request).map_err(FcnetdError::RequestSerializeError)?;
        self.stream
            .write_all(format!("{request_json}\n").as_bytes())
            .await
            .map_err(FcnetdError::RequestWriteError)?;

        let mut response_reader = BufReader::new(&mut self.stream).lines();
        let response = match response_reader.next_line().await {
            Ok(Some(response)) => response,
            Ok(None) => return Err(FcnetdError::ConnectionClosed),
            Err(err) => return Err(FcnetdError::ResponseReadError(err)),
        };

        if response != OK_RESPONSE {
            return Err(FcnetdError::OperationFailed(response));
        }

        Ok(())
    }
}
