#[cfg(feature = "deadpool")]
use std::path::PathBuf;
use std::{marker::PhantomData, path::Path};

use fcnet_types::{FirecrackerNetwork, FirecrackerNetworkOperation};
use serde::Serialize;
use socket::Socket;

const OK_RESPONSE: &str = "OK";

pub mod socket;

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
pub struct FcnetdConnection<S: Socket>(S);

#[derive(Serialize)]
struct Request<'net> {
    operation: FirecrackerNetworkOperation,
    network: &'net FirecrackerNetwork,
}

#[derive(Debug)]
#[cfg(feature = "connection-pool")]
pub struct FcnetdConnectionPool<S: Socket> {
    path: PathBuf,
    password: Option<String>,
    phantom: PhantomData<S>,
}

#[cfg(feature = "connection-pool")]
impl<S: Socket> FcnetdConnectionPool<S> {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            password: None,
            phantom: PhantomData,
        }
    }

    pub fn new_with_password(path: impl Into<PathBuf>, password: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            password: Some(password.into()),
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "deadpool")]
impl<S: Socket> deadpool::managed::Manager for FcnetdConnectionPool<S> {
    type Type = FcnetdConnection<S>;

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

impl<S: Socket> FcnetdConnection<S> {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let socket = S::connect(path.as_ref()).await?;
        Ok(Self(socket))
    }

    pub async fn connect_with_password(path: impl AsRef<Path>, password: impl Into<String>) -> Result<Self, std::io::Error> {
        let password = password.into();
        let mut socket = S::connect(path.as_ref()).await?;
        socket.write_line(password).await?;
        Ok(Self(socket))
    }

    pub async fn run(&mut self, network: &FirecrackerNetwork, operation: FirecrackerNetworkOperation) -> Result<(), FcnetdError> {
        let request = Request { operation, network };
        let request_json = serde_json::to_string(&request).map_err(FcnetdError::RequestSerializeError)?;
        self.0
            .write_line(request_json)
            .await
            .map_err(FcnetdError::RequestWriteError)?;

        let response = match self.0.read_line().await {
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
