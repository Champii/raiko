use crate::ProverState;
use raiko_lib::prover::{ProverError, WorkerError};
use sp1_driver::{WorkerProtocol, WorkerRequest, WorkerResponse, WorkerSocket};
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

    handle_commit(&mut socket).await?;

    handle_prove(&mut socket).await?;

    Ok(())
}

async fn handle_ping(socket: &mut WorkerSocket) -> Result<(), WorkerError> {
    let request = socket.receive().await?;

    match request {
        WorkerProtocol::Request(WorkerRequest::Ping) => {
            socket
                .send(WorkerProtocol::Response(WorkerResponse::Pong))
                .await
        }
        _ => Err(WorkerError::InvalidResponse),
    }
}

async fn handle_commit(socket: &mut WorkerSocket) -> Result<(), WorkerError> {
    let request = socket.receive().await?;

    match request {
        WorkerProtocol::Request(WorkerRequest::Commit(
            checkpoint,
            nb_checkpoints,
            public_values,
            shard_batch_size,
        )) => {
            let (commitment, shards_public_values) = sp1_driver::sp1_specifics::commit(
                checkpoint,
                nb_checkpoints,
                public_values,
                shard_batch_size,
            )?;

            socket
                .send(WorkerProtocol::Response(WorkerResponse::Commit(
                    commitment,
                    shards_public_values,
                )))
                .await?;

            Ok(())
        }
        _ => Err(WorkerError::InvalidRequest),
    }
}

async fn handle_prove(socket: &mut WorkerSocket) -> Result<(), WorkerError> {
    let request = socket.receive().await?;

    match request {
        WorkerProtocol::Request(WorkerRequest::Prove(
            checkpoint,
            nb_checkpoints,
            public_values,
            shard_batch_size,
            challenger,
        )) => {
            let proof = sp1_driver::sp1_specifics::prove(
                checkpoint,
                nb_checkpoints,
                public_values,
                shard_batch_size,
                challenger,
            )?;

            socket
                .send(WorkerProtocol::Response(WorkerResponse::Prove(proof)))
                .await?;

            Ok(())
        }
        _ => Err(WorkerError::InvalidRequest),
    }
}
