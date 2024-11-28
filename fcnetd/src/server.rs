use std::{path::PathBuf, sync::Arc};

use fcnet::backend::TokioBackend;
use fcnet_types::{FirecrackerNetwork, FirecrackerNetworkOperation};
use nix::unistd::{Gid, Uid};
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

use crate::Cli;

#[derive(Deserialize, Debug)]
struct Request {
    operation: FirecrackerNetworkOperation,
    network: FirecrackerNetwork,
}

#[tracing::instrument(skip(cli))]
pub async fn start(cli: Cli) {
    let listener = setup_socket(&cli);
    tracing::info!("Starting to serve over the socket: {}", cli.socket_path);

    let cli = Arc::new(cli);
    let mut connection_id = 0;

    loop {
        let stream = match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::info!(connection_id, "Received a connection to the socket from: {addr:?}");
                stream
            }
            Err(err) => {
                tracing::error!(?err, "Could not receive a connection on the socket");
                continue;
            }
        };

        tokio::task::spawn(serve_connection(cli.clone(), stream, connection_id));
        connection_id += 1;
    }
}

#[tracing::instrument(skip(cli, stream))]
async fn serve_connection(cli: Arc<Cli>, mut stream: UnixStream, connection_id: u64) {
    if let Some(ref password) = cli.password {
        let mut line_reader = BufReader::new(&mut stream).lines();
        let provided_password = match line_reader.next_line().await {
            Ok(Some(password)) => password,
            Ok(None) => {
                tracing::warn!("Connection was closed without input of the password");
                return;
            }
            Err(err) => {
                tracing::error!(?err, "Could not read line from connection stream");
                return;
            }
        };

        if provided_password != *password {
            tracing::warn!(
                provided_password,
                "Connection was rejected due to incorrect password being provided"
            );
            return;
        }

        tracing::info!("Connection was accepted with authentication");
    } else {
        tracing::info!("Connection was accepted with authentication disabled")
    }

    loop {
        let mut line_reader = BufReader::new(&mut stream).lines();
        let request_json = match line_reader.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                tracing::info!("Connection was closed");
                return;
            }
            Err(err) => {
                tracing::error!(?err, "Could not read line from connection stream");
                continue;
            }
        };
        drop(line_reader);

        let Ok(request) = serde_json::from_str::<Request>(&request_json) else {
            tracing::warn!(request_json, "Received a malformed request on the connection");
            continue;
        };

        match fcnet::run::<TokioBackend>(&request.network, request.operation).await {
            Ok(_) => {
                tracing::info!(operation = ?request.operation, "Network operation succeeded");
                if let Err(err) = stream.write_all(b"OK\n").await {
                    tracing::error!(?err, "Could not write OK response to the connection");
                }
            }
            Err(err) => {
                tracing::warn!(?err, operation = ?request.operation, "Network operation failed");
                if let Err(err) = stream.write_all(format!("{err}\n").as_bytes()).await {
                    tracing::error!(?err, "Could not write error response to the connection");
                }
            }
        }
    }
}

#[tracing::instrument(skip(cli))]
fn setup_socket(cli: &Cli) -> UnixListener {
    if std::fs::exists(&cli.socket_path).expect("Could not check if socket exists") {
        std::fs::remove_file(&cli.socket_path).expect("Could not remove socket");
        tracing::debug!("Removed pre-existing socket");
    }

    let listener = UnixListener::bind(&cli.socket_path).expect("Could not bind to the socket");
    tracing::debug!("Listening on the socket: {}", cli.socket_path);

    if cli.uid.is_some() || cli.gid.is_some() {
        nix::unistd::chown(
            &PathBuf::from(&cli.socket_path),
            cli.uid.map(Uid::from_raw),
            cli.gid.map(Gid::from_raw),
        )
        .expect("Could not chown the socket to the provided UID and GID");

        tracing::debug!(uid = cli.uid, gid = cli.gid, "Chowned socket via libc");
    } else {
        tracing::warn!("Socket connectivity will not be possible outside of root processes! No UID or GID provided");
    }

    listener
}
