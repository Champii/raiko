use crate::ProverState;
use sp1_driver::{PartialProofRequest, WorkerProtocol, WorkerSocket};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

async fn handle_worker_socket(mut socket: WorkerSocket) {
    let protocol = socket.receive().await.unwrap();

    info!("Received request: {}", protocol);

    match protocol {
        WorkerProtocol::Ping => {
            socket.send(WorkerProtocol::Ping).await.unwrap();
        }
        WorkerProtocol::PartialProofRequest(data) => {
            process_partial_proof_request(socket, data).await;
        }
        _ => {
            error!("Invalid request: {:?}", protocol);
        }
    }
}

async fn process_partial_proof_request(mut socket: WorkerSocket, data: PartialProofRequest) {
    let result = sp1_driver::Sp1DistributedProver::run_as_worker(data).await;

    match result {
        Ok(data) => {
            socket
                .send(WorkerProtocol::PartialProofResponse(data))
                .await
                .unwrap();
        }
        Err(e) => {
            error!("Error while processing worker request: {:?}", e);
        }
    }
}

async fn listen_worker(state: ProverState) {
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

        info!("Receiving connection from orchestrator: {}", addr);

        // We purposely don't spawn the task here, as we want to block to limit the number
        // of concurrent connections to one.
        handle_worker_socket(WorkerSocket::new(socket)).await;
    }
}

pub async fn serve(state: ProverState) {
    if state.opts.orchestrator_address.is_some() {
        tokio::spawn(listen_worker(state));
    }
}
