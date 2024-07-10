use crate::ProverState;
use raiko_lib::prover::{ProverError, WorkerError};
use sp1_driver::{
    sp1_specifics::{Challenger, Checkpoint, PublicValues},
    WorkerProtocol, WorkerRequest, WorkerResponse, WorkerSocket,
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
    while let Ok(protocol) = socket.receive().await {
        match protocol {
            WorkerProtocol::Request(request) => match request {
                WorkerRequest::Ping => handle_ping(&mut socket).await?,
                WorkerRequest::Commit {
                    checkpoint,
                    nb_checkpoints,
                    public_values,
                    shard_batch_size,
                    shard_size,
                } => {
                    handle_commit(
                        &mut socket,
                        checkpoint,
                        nb_checkpoints,
                        public_values,
                        shard_batch_size,
                        shard_size,
                    )
                    .await?
                }
                WorkerRequest::Prove {
                    checkpoint,
                    nb_checkpoints,
                    public_values,
                    shard_batch_size,
                    shard_size,
                    challenger,
                } => {
                    handle_prove(
                        &mut socket,
                        checkpoint,
                        nb_checkpoints,
                        public_values,
                        shard_batch_size,
                        shard_size,
                        challenger,
                    )
                    .await?
                }
            },
            _ => Err(WorkerError::InvalidRequest)?,
        }
    }

    Ok(())
}

async fn handle_ping(socket: &mut WorkerSocket) -> Result<(), WorkerError> {
    socket
        .send(WorkerProtocol::Response(WorkerResponse::Pong))
        .await
}

async fn handle_commit(
    socket: &mut WorkerSocket,
    checkpoint: Checkpoint,
    nb_checkpoints: usize,
    public_values: PublicValues<u32, u32>,
    shard_batch_size: usize,
    shard_size: usize,
) -> Result<(), WorkerError> {
    let (commitments, shards_public_values) = sp1_driver::sp1_specifics::commit(
        checkpoint,
        nb_checkpoints,
        public_values,
        shard_batch_size,
        shard_size,
    )?;

    socket
        .send(WorkerProtocol::Response(WorkerResponse::Commitment {
            commitments,
            shards_public_values,
        }))
        .await
}

async fn handle_prove(
    socket: &mut WorkerSocket,
    checkpoint: Checkpoint,
    nb_checkpoints: usize,
    public_values: PublicValues<u32, u32>,
    shard_batch_size: usize,
    shard_size: usize,
    challenger: Challenger,
) -> Result<(), WorkerError> {
    let proof = sp1_driver::sp1_specifics::prove(
        checkpoint,
        nb_checkpoints,
        public_values,
        shard_batch_size,
        shard_size,
        challenger,
    )?;

    socket
        .send(WorkerProtocol::Response(WorkerResponse::Proof(proof)))
        .await
}
