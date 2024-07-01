use async_channel::{Receiver, Sender};
use raiko_lib::prover::WorkerError;
use sp1_core::{runtime::ExecutionState, stark::ShardProof, utils::BabyBearPoseidon2};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
    net::TcpStream,
};

use crate::distributed::partial_proof_request::PartialProofRequest;

pub struct WorkerClient {
    /// The id of the worker
    id: usize,
    /// The url of the worker
    url: String,
    /// A queue to receive the checkpoint to compute the partial proof
    queue: Receiver<(usize, ExecutionState)>,
    /// A channel to send back the id of the checkpoint along with the json strings encoding the computed partial proofs
    answer: Sender<(
        usize,
        Result<Vec<ShardProof<BabyBearPoseidon2>>, WorkerError>,
    )>,
    /// The partial proof request containing the checkpoint data and the challenger
    partial_proof_request: PartialProofRequest,
}

impl WorkerClient {
    pub fn new(
        id: usize,
        url: String,
        queue: Receiver<(usize, ExecutionState)>,
        answer: Sender<(
            usize,
            Result<Vec<ShardProof<BabyBearPoseidon2>>, WorkerError>,
        )>,
        partial_proof_request: PartialProofRequest,
    ) -> Self {
        WorkerClient {
            id,
            url,
            queue,
            answer,
            partial_proof_request,
        }
    }

    pub async fn run(&self) {
        while let Ok((i, checkpoint)) = self.queue.recv().await {
            let partial_proof_result = self.send_work_tcp(i, checkpoint).await;

            if let Err(e) = partial_proof_result {
                log::error!(
                    "Error while sending checkpoint to worker {}: {}. {}",
                    self.id,
                    self.url,
                    e,
                );

                self.answer.send((i, Err(e))).await.unwrap();

                return;
            }

            self.answer.send((i, partial_proof_result)).await.unwrap();
        }

        log::debug!("Worker {} finished", self.id);
    }

    async fn send_work_tcp(
        &self,
        i: usize,
        checkpoint: ExecutionState,
    ) -> Result<Vec<ShardProof<BabyBearPoseidon2>>, WorkerError> {
        let mut stream = TcpStream::connect(&self.url).await?;

        log::info!(
            "Sending checkpoint {} to worker {} at {}",
            i,
            self.id,
            self.url
        );

        let mut request = self.partial_proof_request.clone();

        request.checkpoint_id = i;
        request.checkpoint_data = checkpoint;

        let data = bincode::serialize(&request)?;

        stream.write_u64(data.len() as u64).await?;
        stream.flush().await?;

        stream.write_all(&data).await?;
        stream.flush().await?;

        let response = read_data(&mut stream).await?;

        let partial_proofs = bincode::deserialize(&response)?;

        Ok(partial_proofs)
    }
}

// FIXME: This shouldnt be here
pub async fn read_data(socket: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    // TODO: limit the size of the data
    let size = socket.read_u64().await? as usize;

    let mut data = Vec::new();

    let mut buf_data = BufWriter::new(&mut data);
    let mut buf = [0; 1024];
    let mut total_read = 0;

    loop {
        match socket.read(&mut buf).await {
            // socket closed
            Ok(n) if n == 0 => return Ok(data),
            Ok(n) => {
                buf_data.write_all(&buf[..n]).await?;

                total_read += n;

                if total_read == size {
                    buf_data.flush().await?;

                    return Ok(data);
                }

                // TODO: handle the case where the data is bigger than expected
            }
            Err(e) => {
                log::error!("failed to read from socket; err = {:?}", e);

                return Err(e);
            }
        };
    }
}
