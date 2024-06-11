use async_channel::{Receiver, Sender};
use raiko_lib::prover::ProverConfig;
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
    queue: Receiver<usize>,
    /// A channel to send back the id of the checkpoint along with the json strings encoding the computed partial proofs
    answer: Sender<(usize, String)>,
    /// if an error occured, send the checkpoint back in the queue for another worker to pick it up
    queue_push_back: Sender<usize>,
}

impl Worker {
    pub fn new(
        id: usize,
        url: String,
        config: ProverConfig,
        queue: Receiver<usize>,
        answer: Sender<(usize, String)>,
        queue_push_back: Sender<usize>,
    ) -> Self {
        Worker {
            id,
            url,
            config,
            queue,
            answer,
            queue_push_back,
        }
    }

    pub async fn run(&self) {
        while let Ok(checkpoint) = self.queue.recv().await {
            // Compute the partial proof
            let partial_proof_result = self.send_work(checkpoint).await;

            match partial_proof_result {
                Ok(partial_proof) => self.answer.send((checkpoint, partial_proof)).await.unwrap(),
                Err(_e) => {
                    self.queue_push_back.send(checkpoint).await.unwrap();

                    break;
                }
            }
        }
    }

    async fn send_work(&self, checkpoint: usize) -> Result<String, reqwest::Error> {
        log::info!(
            "Sending checkpoint {} to worker {}: {}",
            checkpoint,
            self.id,
            self.url
        );

        let mut config = self.config.clone();

        let mut_config = config.as_object_mut().unwrap();
        mut_config
            .get_mut("sp1")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("checkpoint".to_string(), checkpoint.into());

        let now = std::time::Instant::now();

        let response_result = reqwest::Client::new()
            .post(&self.url)
            .json(&config)
            .send()
            .await;

        match response_result {
            Ok(response) => {
                let value: Value = response.json().await.unwrap();
                let sp1_response: Sp1Response =
                    serde_json::from_str(&value["data"].to_string()).unwrap();

                log::info!(
                    "Received proof for checkpoint {} from worker {}: {} in {}s",
                    checkpoint,
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
