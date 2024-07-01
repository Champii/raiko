use crate::{interfaces::HostError, server::api::create_router, ProverState};
use anyhow::Context;
use sp1_driver::{WorkerEnvelope, WorkerProtocol};
use std::{net::SocketAddr, str::FromStr};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};
use tracing::{error, info, warn};

pub mod api;

async fn handle_worker_socket(mut socket: TcpStream) {
    let data = sp1_driver::read_data(&mut socket).await.unwrap();

    let envelope: WorkerEnvelope = bincode::deserialize(&data).unwrap();

    // FIXME: Put the magic number in the CliOpts
    if envelope.magic != 0xdeadbeef {
        error!("Invalid magic number");

        return;
    }

    match envelope.data {
        WorkerProtocol::Ping => {
            socket.write_u64(data.len() as u64).await.unwrap();
            socket.write_all(&data).await.unwrap();
        }
        WorkerProtocol::PartialProofRequest(data) => {
            process_partial_proof_request(socket, data).await;
        }
    }
}

async fn process_partial_proof_request(mut socket: TcpStream, data: Vec<u8>) {
    let result = sp1_driver::Sp1DistributedProver::run_as_worker(&data).await;

    match result {
        Ok(data) => {
            socket.write_u64(data.len() as u64).await.unwrap();
            socket.write_all(&data).await.unwrap();
        }
        Err(e) => {
            error!("Error while processing worker request: {:?}", e);
        }
    }
}

pub async fn listen_worker(state: ProverState) {
    info!(
        "Listening as a SP1 worker on: {}",
        state.opts.worker_address
    );

    let listener = TcpListener::bind(state.opts.worker_address).await.unwrap();

    loop {
        let (socket, addr) = listener.accept().await.unwrap();

        if let Some(orchestrator_address) = &state.opts.orchestrator_address {
            if addr.ip().to_string() != *orchestrator_address {
                warn!("Unauthorized orchestrator connection from: {}", addr);

                continue;
            }
        }

        info!(
            "Receiving SP1 worker task connected from orchestrator: {}",
            addr
        );

        // We purposely don't spawn the task here, as we want to block to limit the number
        // of concurrent connections to one.
        handle_worker_socket(socket).await;
    }
}

/// Starts the proverd server.
pub async fn serve(state: ProverState) -> anyhow::Result<()> {
    if state.opts.orchestrator_address.is_some() {
        info!("Worker mode enabled");

        tokio::spawn(listen_worker(state.clone()));
    }

    let addr = SocketAddr::from_str(&state.opts.address)
        .map_err(|_| HostError::InvalidAddress(state.opts.address.clone()))?;
    let listener = TcpListener::bind(addr).await?;

    info!("Listening on: {}", listener.local_addr()?);

    let router = create_router(
        state.opts.concurrency_limit,
        state.opts.jwt_secret.as_deref(),
    )
    .with_state(state);
    axum::serve(listener, router)
        .await
        .context("Server couldn't serve")?;

    Ok(())
}
