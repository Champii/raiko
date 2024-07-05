use std::fmt::{Display, Formatter};

use async_channel::{Receiver, Sender};
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_symmetric::Hash;
use raiko_lib::prover::WorkerError;
use serde::{Deserialize, Serialize};
use sp1_core::{
    air::PublicValues,
    runtime::ExecutionState,
    stark::ShardProof,
    utils::{
        baby_bear_poseidon2::{Perm, Val},
        BabyBearPoseidon2,
    },
};

use super::WorkerClient;

pub type Checkpoint = ExecutionState;
pub type Commitments = Vec<Hash<Val, Val, 8>>;
pub type PartialProof = Vec<ShardProof<BabyBearPoseidon2>>;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    Commit(Checkpoint, PublicValues<u32, u32>, usize),
    Prove(Challenger),
}

impl Display for WorkerRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerRequest::Commit(_, _, _) => {
                write!(f, "Commit")
            }
            WorkerRequest::Prove(_) => write!(f, "Prove"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    Commit(Commitments),
    Prove(PartialProof),
}

impl Display for WorkerResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerResponse::Commit(_) => write!(f, "Commit"),
            WorkerResponse::Prove(_) => write!(f, "Prove"),
        }
    }
}

pub struct WorkerPool {
    nb_workers: usize,
    request_tx: Sender<(usize, WorkerRequest)>,
    answer_rx: Receiver<(usize, Result<WorkerResponse, WorkerError>)>,
}

impl WorkerPool {
    pub async fn new() -> Result<Self, WorkerError> {
        let (request_tx, request_rx) = async_channel::unbounded();
        let (answer_tx, answer_rx) = async_channel::unbounded();

        let nb_workers = Self::spawn_workers(request_rx, answer_tx).await?;

        Ok(Self {
            nb_workers,
            request_tx,
            answer_rx,
        })
    }

    pub async fn commit(
        &self,
        checkpoints: Vec<Checkpoint>,
        public_values: PublicValues<u32, u32>,
        shard_batch_size: usize,
    ) -> Result<Commitments, WorkerError> {
        let requests = checkpoints
            .into_iter()
            .map(|checkpoint| {
                WorkerRequest::Commit(checkpoint, public_values.clone(), shard_batch_size)
            })
            .collect();

        let commitments_response = self.distribute_work(requests).await?;

        let mut commitments = Vec::new();

        for response in commitments_response {
            if let WorkerResponse::Commit(commitment) = response {
                commitments.extend(commitment);
            } else {
                return Err(WorkerError::InvalidResponse);
            }
        }

        Ok(commitments)
    }

    pub async fn prove(&self, challenger: Challenger) -> Result<PartialProof, WorkerError> {
        let requests = (0..self.nb_workers)
            .map(|_| WorkerRequest::Prove(challenger.clone()))
            .collect();

        let proofs_response = self.distribute_work(requests).await?;

        let mut proofs = Vec::new();

        for response in proofs_response {
            if let WorkerResponse::Prove(partial_proof) = response {
                proofs.extend(partial_proof);
            } else {
                return Err(WorkerError::InvalidResponse);
            }
        }

        Ok(proofs)
    }

    async fn distribute_work(
        &self,
        requests: Vec<WorkerRequest>,
    ) -> Result<Vec<WorkerResponse>, WorkerError> {
        for (i, request) in requests.iter().enumerate() {
            self.request_tx.send((i, request.clone())).await.unwrap();
        }

        let mut results = Vec::new();

        // Get the partial proofs from the workers
        loop {
            let (checkpoint_id, result) = self.answer_rx.recv().await.unwrap();

            match result {
                Ok(response) => {
                    results.push((checkpoint_id as usize, response));
                }
                Err(_e) => {
                    return Err(WorkerError::AllWorkersFailed);
                }
            }

            if results.len() == self.nb_workers {
                break;
            }
        }

        results.sort_by_key(|(checkpoint_id, _)| *checkpoint_id);

        let results = results.into_iter().map(|(_, proof)| proof).collect();

        Ok(results)
    }

    async fn spawn_workers(
        request_rx: Receiver<(usize, WorkerRequest)>,
        answer_tx: Sender<(usize, Result<WorkerResponse, WorkerError>)>,
    ) -> Result<usize, WorkerError> {
        let ip_list_string = std::fs::read_to_string("distributed.json")
            .expect("Sp1 Distributed: Need a `distributed.json` file with a list of IP:PORT");

        let ip_list: Vec<String> = serde_json::from_str(&ip_list_string).expect(
            "Sp1 Distributed: Invalid JSON for `distributed.json`. need an array of IP:PORT",
        );

        let mut nb_workers = 0;

        // try to connect to each worker to make sure they are reachable
        for (i, ip) in ip_list.into_iter().enumerate() {
            let Ok(mut worker) =
                WorkerClient::new(i, ip.clone(), request_rx.clone(), answer_tx.clone()).await
            else {
                log::warn!("Sp1 Distributed: Worker at {} is not reachable. Removing from the list for this task", ip);

                continue;
            };

            if let Err(_) = worker.ping().await {
                log::warn!("Sp1 Distributed: Worker at {} is not sending good response to Ping. Removing from the list for this task", ip);

                continue;
            }

            tokio::spawn(async move {
                worker.run().await;
            });

            nb_workers += 1;
        }

        if nb_workers == 0 {
            log::error!("Sp1 Distributed: No reachable workers found. Aborting...");

            return Err(WorkerError::AllWorkersFailed);
        }

        Ok(nb_workers)
    }

    pub fn len(&self) -> usize {
        self.nb_workers
    }
}
