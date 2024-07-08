use async_channel::{Receiver, Sender};
use raiko_lib::prover::WorkerError;

use crate::{WorkerRequest, WorkerResponse, WorkerSocket};

pub struct WorkerClient {
    /// The id of the worker
    id: usize,
    /// The url of the worker
    url: String,
    /// The underlying socket
    socket: WorkerSocket,
    /// The request channel
    request_rx: Receiver<(usize, WorkerRequest)>,
    /// The answer channel
    answer_tx: Sender<(usize, Result<WorkerResponse, WorkerError>)>,
}

impl WorkerClient {
    pub async fn new(
        id: usize,
        url: String,
        request_rx: Receiver<(usize, WorkerRequest)>,
        answer_tx: Sender<(usize, Result<WorkerResponse, WorkerError>)>,
    ) -> Result<Self, WorkerError> {
        let socket = WorkerSocket::connect(&url).await?;

        Ok(WorkerClient {
            id,
            url,
            socket,
            request_rx,
            answer_tx,
        })
    }

    pub async fn ping(&mut self) -> Result<(), WorkerError> {
        self.socket.ping().await
    }

    pub async fn run(&mut self) {
        while let Ok((i, request)) = self.request_rx.recv().await {
            let result = self.send_work_tcp(request).await;

            /* if let Err(e) = result {
                log::error!(
                    "Error while processing work on worker {}: {}. {}\n{}",
                    self.id,
                    self.url,
                    e,
                    request,
                );

                return;
            } */

            self.answer_tx.send((i, result)).await.unwrap();
        }

        log::debug!("Worker {} finished", self.id);
    }

    async fn send_work_tcp(
        &mut self,
        request: WorkerRequest,
    ) -> Result<WorkerResponse, WorkerError> {
        log::info!(
            "Sending checkpoint {} to worker {} at {}",
            self.id,
            self.id,
            self.url
        );

        self.socket.request(request).await
    }
}
