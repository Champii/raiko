use async_channel::{Receiver, Sender};
use raiko_lib::prover::ProverConfig;
use raiko_lib::PartialProofRequestData;
use serde_json::Value;

use crate::Sp1Response;

pub struct Worker {
    /// The id of the worker
    id: usize,
    /// The url of the worker
    url: String,
    /// The config to send to the worker
    config: ProverConfig,
    /// A queue to receive the checkpoint to compute the partial proof
    queue: Receiver<(usize, Vec<u8>)>,
    /// A channel to send back the id of the checkpoint along with the json strings encoding the computed partial proofs
    answer: Sender<(usize, String)>,
    /// if an error occured, send the checkpoint back in the queue for another worker to pick it up
    queue_push_back: Sender<(usize, Vec<u8>)>,
    public_values: Vec<u8>,
    serialized_challenger: Vec<u8>,
}

impl Worker {
    pub fn new(
        id: usize,
        url: String,
        config: ProverConfig,
        queue: Receiver<(usize, Vec<u8>)>,
        answer: Sender<(usize, String)>,
        queue_push_back: Sender<(usize, Vec<u8>)>,
        public_values: Vec<u8>,
        serialized_challenger: Vec<u8>,
    ) -> Self {
        Worker {
            id,
            url,
            config,
            queue,
            answer,
            queue_push_back,
            public_values,
            serialized_challenger,
        }
    }

    pub async fn run(&self) {
        while let Ok((i, checkpoint)) = self.queue.recv().await {
            // Compute the partial proof
            let partial_proof_result = self.send_work(i, checkpoint).await;

            match partial_proof_result {
                Ok(partial_proof) => self.answer.send((i, partial_proof)).await.unwrap(),
                Err(_e) => {
                    /* self.queue_push_back
                    .send((i, checkpoint, serialized_challenger))
                    .await
                    .unwrap(); */

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

        let mut config = self.config.clone();

        log::info!(
            "CHECKPOINT+CHALLENGER SIZE: {}",
            checkpoint.len() + self.serialized_challenger.len()
        );

        let req = PartialProofRequestData {
            request: config.to_string(),
            checkpoint_id: i,
            checkpoint_data: checkpoint,
            serialized_challenger: self.serialized_challenger.clone(),
            public_values: self.public_values.clone(),
        };

        log::info!("Serializing...");
        let data = bincode::serialize(&req).unwrap();
        log::info!("DATA SIZE: {}", data.len());

        let now = std::time::Instant::now();
        log::info!("Preparing the data");
        let part = reqwest::multipart::Part::bytes(data).file_name("checkpoint");
        log::info!("Sending the form");
        let form = reqwest::multipart::Form::new()
            .text("resourceName", "checkpoint")
            .part("FileData", part);

        log::info!("Sending the request");
        let response_result = reqwest::Client::new()
            .post(&self.url)
            .multipart(form)
            .send()
            .await;

        log::info!("waiting for the response");
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