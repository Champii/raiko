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
    queue: Receiver<(usize, Vec<u8>, Vec<u8>)>,
    /// A channel to send back the id of the checkpoint along with the json strings encoding the computed partial proofs
    answer: Sender<(usize, String)>,
    /// if an error occured, send the checkpoint back in the queue for another worker to pick it up
    queue_push_back: Sender<(usize, Vec<u8>, Vec<u8>)>,
}

impl Worker {
    pub fn new(
        id: usize,
        url: String,
        config: ProverConfig,
        queue: Receiver<(usize, Vec<u8>, Vec<u8>)>,
        answer: Sender<(usize, String)>,
        queue_push_back: Sender<(usize, Vec<u8>, Vec<u8>)>,
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
        while let Ok((i, checkpoint, serialized_challenger)) = self.queue.recv().await {
            // Compute the partial proof
            let partial_proof_result = self.send_work(i, checkpoint, serialized_challenger).await;

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

    async fn send_work(
        &self,
        i: usize,
        checkpoint: Vec<u8>,
        serialized_challenger: Vec<u8>,
    ) -> Result<String, reqwest::Error> {
        log::info!(
            "Sending checkpoint to worker {}: {}",
            // checkpoint,
            self.id,
            self.url
        );

        let mut config = self.config.clone();

        /* let mut_config = config.as_object_mut().unwrap();
        mut_config
            .get_mut("sp1")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("i".to_string(), i.into());
        mut_config
            .get_mut("sp1")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("checkpoint_data".to_string(), checkpoint.into());

        mut_config
            .get_mut("sp1")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "serialized_challenger".to_string(),
                serialized_challenger.into(),
            ); */

        println!(
            "CHECKPOINT+CHALLENGER SIZE: {}",
            checkpoint.len() + serialized_challenger.len()
        );
        let req = PartialProofRequestData {
            request: config.to_string(),
            checkpoint_id: i,
            checkpoint_data: checkpoint,
            serialized_challenger,
        };

        println!("Serializing...");
        let data = bincode::serialize(&req).unwrap();

        println!("DATA SIZE: {}", data.len());

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
                println!("RESPONSE: {:#?}", response);
                let txt = response.text().await.unwrap();
                println!("BODY: {:#?}", txt);
                // let value: Value = response.json().await.unwrap();
                let value: Value = serde_json::from_str(&txt).unwrap();
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
