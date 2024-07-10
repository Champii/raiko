use crate::ProverState;
use raiko_lib::prover::{ProverError, WorkerError};
use sp1_driver::{
    sp1_specifics::Challenger, RequestData, WorkerProtocol, WorkerRequest, WorkerResponse,
    WorkerSocket,
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
                WorkerRequest::Commit(request_data) => {
                    handle_commit(&mut socket, request_data).await?
                }
                WorkerRequest::Prove {
                    request_data,
                    challenger,
                } => handle_prove(&mut socket, request_data, challenger).await?,
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
    request_data: RequestData,
) -> Result<(), WorkerError> {
    let (commitments, shards_public_values) = sp1_driver::sp1_specifics::commit(
        request_data.checkpoint,
        request_data.nb_checkpoints,
        request_data.public_values,
        request_data.shard_batch_size,
        request_data.shard_size,
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
    request_data: RequestData,
    challenger: Challenger,
) -> Result<(), WorkerError> {
    let proof = sp1_driver::sp1_specifics::prove(
        request_data.checkpoint,
        request_data.nb_checkpoints,
        request_data.public_values,
        request_data.shard_batch_size,
        request_data.shard_size,
        challenger,
    )?;

    socket
        .send(WorkerProtocol::Response(WorkerResponse::Proof(proof)))
        .await
}
