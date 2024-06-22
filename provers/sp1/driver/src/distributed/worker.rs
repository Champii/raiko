use async_channel::{Receiver, Sender};
use raiko_lib::PartialProofRequestData;
use serde_json::Value;

use crate::Sp1Response;

pub struct Worker {
    /// The id of the worker
    id: usize,
    /// The url of the worker
    url: String,
    /// A queue to receive the checkpoint to compute the partial proof
    queue: Receiver<(usize, Vec<u8>)>,
    /// A channel to send back the id of the checkpoint along with the json strings encoding the computed partial proofs
    answer: Sender<(usize, String)>,
    public_values: Vec<u8>,
    serialized_challenger: Vec<u8>,
    shard_batch_size: usize,
}

impl Worker {
    pub fn new(
        id: usize,
        url: String,
        queue: Receiver<(usize, Vec<u8>)>,
        answer: Sender<(usize, String)>,
        public_values: Vec<u8>,
        serialized_challenger: Vec<u8>,
        shard_batch_size: usize,
    ) -> Self {
        Worker {
            id,
            url,
            queue,
            answer,
            public_values,
            serialized_challenger,
            shard_batch_size,
        }
    }

    pub async fn run(&self) {
        while let Ok((i, checkpoint)) = self.queue.recv().await {
            let partial_proof_result = self.send_work(i, checkpoint).await;

            match partial_proof_result {
                Ok(partial_proof) => self.answer.send((i, partial_proof)).await.unwrap(),
                Err(_e) => {
                    break;
                }
            }
        }
    }

    async fn send_work(&self, i: usize, checkpoint: Vec<u8>) -> Result<String, reqwest::Error> {
        log::info!(
            "Sending checkpoint to worker {}: {}",
            // checkpoint,
            self.id,
            self.url
        );

        let req = PartialProofRequestData {
            checkpoint_id: i,
            checkpoint_data: checkpoint,
            serialized_challenger: self.serialized_challenger.clone(),
            public_values: self.public_values.clone(),
            shard_batch_size: self.shard_batch_size,
        };

        let data = bincode::serialize(&req).unwrap();

        let now = std::time::Instant::now();
        let part = reqwest::multipart::Part::bytes(data).file_name("checkpoint");
        let form = reqwest::multipart::Form::new()
            .text("resourceName", "checkpoint")
            .part("FileData", part);

        let response_result = reqwest::Client::new()
            .post(&self.url)
            .multipart(form)
            .send()
            .await;

        match response_result {
            Ok(response) => {
                let value: Value = response.json().await.unwrap();
                let sp1_response: Sp1Response =
                    serde_json::from_str(&value["data"].to_string()).unwrap();

                log::info!(
                    "Received proof for checkpoint  from worker {}: {} in {}s",
                    // checkpoint,
                    self.id,
                    self.url,
                    now.elapsed().as_secs()
                );

                Ok(sp1_response.proof)
            }
            Err(e) => Err(e),
        }
    }
}
