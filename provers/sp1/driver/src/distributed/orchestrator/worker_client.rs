use async_channel::{Receiver, Sender};
use sp1_core::{runtime::ExecutionState, stark::ShardProof, utils::BabyBearPoseidon2};

use crate::distributed::partial_proof_request::PartialProofRequestData;

pub struct WorkerClient {
    /// The id of the worker
    id: usize,
    /// The url of the worker
    url: String,
    /// A queue to receive the checkpoint to compute the partial proof
    queue: Receiver<(usize, ExecutionState)>,
    /// A channel to send back the id of the checkpoint along with the json strings encoding the computed partial proofs
    answer: Sender<(usize, Vec<ShardProof<BabyBearPoseidon2>>)>,
    partial_proof_request: PartialProofRequestData,
    http_client: reqwest::Client,
}

impl WorkerClient {
    pub fn new(
        id: usize,
        url: String,
        queue: Receiver<(usize, ExecutionState)>,
        answer: Sender<(usize, Vec<ShardProof<BabyBearPoseidon2>>)>,
        partial_proof_request: PartialProofRequestData,
        http_client: reqwest::Client,
    ) -> Self {
        WorkerClient {
            id,
            url,
            queue,
            answer,
            partial_proof_request,
            http_client,
        }
    }

    pub async fn run(&self) {
        while let Ok((i, checkpoint)) = self.queue.recv().await {
            let partial_proof_result = self.send_work(i, checkpoint).await;

            match partial_proof_result {
                Ok(partial_proof) => self.answer.send((i, partial_proof)).await.unwrap(),
                Err(e) => {
                    log::error!(
                        "Error while sending checkpoint to worker {}: {}. {}",
                        self.id,
                        self.url,
                        e,
                    );
                    break;
                }
            }
        }
    }

    async fn send_work(
        &self,
        i: usize,
        checkpoint: ExecutionState,
    ) -> Result<Vec<ShardProof<BabyBearPoseidon2>>, reqwest::Error> {
        log::info!("Sending checkpoint to worker {}: {}", self.id, self.url);

        let mut request = self.partial_proof_request.clone();

        request.checkpoint_id = i;
        request.checkpoint_data = checkpoint;

        let data = bincode::serialize(&request).unwrap();

        let now = std::time::Instant::now();
        let part = reqwest::multipart::Part::bytes(data).file_name("checkpoint");
        let form = reqwest::multipart::Form::new()
            .text("resourceName", "checkpoint")
            .part("FileData", part);

        let response_result = self
            .http_client
            .post(&self.url)
            .multipart(form)
            .send()
            .await;

        match response_result {
            Ok(response) => {
                println!("Got answer from worker {}", self.id);
                let value = response.bytes().await.unwrap();
                println!("Got value");
                /* let sp1_response: Sp1Response =
                serde_json::from_str(&value["data"].to_string()).unwrap(); */

                let partial_proofs = bincode::deserialize(&value).unwrap();

                log::info!(
                    "Received proof for checkpoint  from worker {}: {} in {}s",
                    self.id,
                    self.url,
                    now.elapsed().as_secs()
                );

                Ok(partial_proofs)
            }
            Err(e) => Err(e),
        }
    }
}
