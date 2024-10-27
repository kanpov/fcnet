use std::{path::PathBuf, sync::Arc};

use fcnet_types::{FirecrackerNetwork, FirecrackerNetworkOperation};
use nix::unistd::{Gid, Uid};
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
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
    tracing::info!("Starting to serve over the socket: {}", cli.address);

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
    let mut line_reader = BufReader::new(&mut stream).lines();

    if let Some(ref password) = cli.password {
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
        let request_json = match line_reader.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => {
                tracing::info!("Connection was gracefully closed");
                return;
            }
            Err(err) => {
                tracing::error!(?err, "Could not read line from connection stream");
                continue;
            }
        };

        let Ok(request) = serde_json::from_str::<Request>(&request_json) else {
            tracing::warn!(request_json, "Received a malformed request on the connection");
            continue;
        };

        dbg!(request);
    }
}

#[tracing::instrument(skip(cli))]
fn setup_socket(cli: &Cli) -> UnixListener {
    let listener = UnixListener::bind(&cli.address).expect("Could not bind to the socket");
    tracing::debug!("Listening on the socket: {}", cli.address);

    if cli.uid.is_some() || cli.gid.is_some() {
        nix::unistd::chown(
            &PathBuf::from(&cli.address),
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
