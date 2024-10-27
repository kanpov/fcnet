use std::{path::Path, str::FromStr};

use fcnet_types::{FirecrackerIpStack, FirecrackerNetwork, FirecrackerNetworkOperation, FirecrackerNetworkType};
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

pub struct FcnetdConnection {
    stream: UnixStream,
}

#[derive(Serialize)]
struct Request<'net> {
    operation: FirecrackerNetworkOperation,
    network: &'net FirecrackerNetwork,
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

#[tokio::test]
async fn t() {
    let mut conn = FcnetdConnection::connect("/tmp/fcnetd.sock").await.unwrap();
    let network = FirecrackerNetwork {
        nft_path: None,
        ip_stack: FirecrackerIpStack::V4,
        iface_name: "wlp7s0".to_string(),
        tap_name: "tap0".to_string(),
        tap_ip: cidr::IpInet::from_str("172.16.0.1/24").unwrap(),
        guest_ip: cidr::IpInet::from_str("172.16.0.2/24").unwrap(),
        network_type: FirecrackerNetworkType::Simple,
    };
    conn.run(&network, FirecrackerNetworkOperation::Add).await.unwrap();
    conn.run(&network, FirecrackerNetworkOperation::Check).await.unwrap();
    // conn.run(&network, FirecrackerNetworkOperation::Delete).await.unwrap();
}
