use crate::ProverState;
use raiko_lib::prover::{ProverError, WorkerError};
use sp1_driver::{
    ExecutionRecord, PublicValues, WorkerProtocol, WorkerRequest, WorkerResponse, WorkerSocket,
};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

pub async fn serve(state: ProverState) {
    if state.opts.orchestrator_address.is_some() {
        tokio::spawn(listen_worker(state));
    }
}

async fn listen_worker(state: ProverState) {
    info!(
        "Listening as a SP1 worker on: {}",
        state.opts.worker_address
    );

    let listener = TcpListener::bind(state.opts.worker_address).await.unwrap();

    loop {
        let Ok((socket, addr)) = listener.accept().await else {
            error!("Error while accepting connection from orchestrator: Closing socket");

            return;
        };

        if let Some(orchestrator_address) = &state.opts.orchestrator_address {
            if addr.ip().to_string() != *orchestrator_address {
                warn!("Unauthorized orchestrator connection from: {}", addr);

                continue;
            }
        }

        // We purposely don't spawn the task here, as we want to block to limit the number
        // of concurrent connections to one.
        if let Err(e) = handle_worker_socket(WorkerSocket::from_stream(socket)).await {
            error!("Error while handling worker socket: {:?}", e);
        }
    }
}

async fn handle_worker_socket(mut socket: WorkerSocket) -> Result<(), ProverError> {
    handle_ping(&mut socket).await?;

    let (shards, public_values, shard_batch_size) = handle_commit(&mut socket).await?;

    handle_prove(&mut socket, shards, public_values, shard_batch_size).await?;

    Ok(())
}

async fn handle_ping(socket: &mut WorkerSocket) -> Result<(), WorkerError> {
    let request = socket.receive().await?;

    match request {
        WorkerProtocol::Ping => socket.send(WorkerProtocol::Pong).await,
        _ => Err(WorkerError::InvalidResponse),
    }
}

async fn handle_commit(
    socket: &mut WorkerSocket,
) -> Result<(Vec<ExecutionRecord>, PublicValues<u32, u32>, usize), WorkerError> {
    let request = socket.receive().await?;

    match request {
        WorkerProtocol::Request(WorkerRequest::Commit(
            checkpoint,
            public_values,
            shard_batch_size,
        )) => {
            let (shards, commitment) = sp1_driver::sp1_specifics::commit(
                checkpoint,
                public_values.clone(),
                shard_batch_size,
            )?;

            socket
                .send(WorkerProtocol::Response(WorkerResponse::Commit(commitment)))
                .await?;

            Ok((shards, public_values, shard_batch_size))
        }
        _ => Err(WorkerError::InvalidRequest),
    }
}

async fn handle_prove(
    socket: &mut WorkerSocket,
    shards: Vec<ExecutionRecord>,
    public_values: PublicValues<u32, u32>,
    shard_batch_size: usize,
) -> Result<(), WorkerError> {
    let request = socket.receive().await?;

    match request {
        WorkerProtocol::Request(WorkerRequest::Prove(challenger)) => {
            let proof = sp1_driver::sp1_specifics::prove(shards, public_values, challenger)?;

            socket
                .send(WorkerProtocol::Response(WorkerResponse::Prove(proof)))
                .await?;

            Ok(())
        }
        _ => Err(WorkerError::InvalidRequest),
    }
}