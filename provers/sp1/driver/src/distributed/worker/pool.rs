use std::{
    fmt::{Display, Formatter},
    sync::Arc,
};

use raiko_lib::prover::WorkerError;
use serde::{Deserialize, Serialize};
use sp1_core::air::PublicValues;
use tokio::sync::RwLock;

use crate::{
    sp1_specifics::{Challenger, Checkpoint, Commitments, PartialProof, ShardsPublicValues},
    WorkerSocket,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    Commit(Checkpoint, usize, PublicValues<u32, u32>, usize),
    Prove(Checkpoint, usize, PublicValues<u32, u32>, usize, Challenger),
}

impl Display for WorkerRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerRequest::Commit(_, _, _, _) => {
                write!(f, "Commit")
            }
            WorkerRequest::Prove(_, _, _, _, _) => write!(f, "Prove"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    Commit(Vec<Commitments>, Vec<Vec<ShardsPublicValues>>),
    Prove(PartialProof),
}

impl Display for WorkerResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerResponse::Commit(_, _) => write!(f, "Commit"),
            WorkerResponse::Prove(_) => write!(f, "Prove"),
        }
    }
}

pub struct WorkerPool {
    workers: Vec<Arc<RwLock<WorkerSocket>>>,
}

impl WorkerPool {
    pub async fn new() -> Result<Self, WorkerError> {
        let workers = Self::spawn_workers().await?;

        Ok(Self { workers })
    }

    pub async fn commit(
        &mut self,
        checkpoints: Vec<(Checkpoint, usize)>,
        public_values: PublicValues<u32, u32>,
        shard_batch_size: usize,
    ) -> Result<(Vec<Commitments>, Vec<Vec<ShardsPublicValues>>), WorkerError> {
        let requests = checkpoints
            .into_iter()
            .map(|(checkpoint, nb_checkpoints)| {
                WorkerRequest::Commit(
                    checkpoint,
                    nb_checkpoints,
                    public_values.clone(),
                    shard_batch_size,
                )
            })
            .collect();

        let commitments_response = self.distribute_work(requests).await?;

        let mut commitments = Vec::new();
        let mut shards_public_values = Vec::new();

        for response in commitments_response {
            if let WorkerResponse::Commit(commitment, got_shards_public_values) = response {
                commitments.extend(commitment);
                shards_public_values.extend(got_shards_public_values);
            } else {
                return Err(WorkerError::InvalidResponse);
            }
        }

        Ok((commitments, shards_public_values))
    }

    pub async fn prove(
        &mut self,
        checkpoints: Vec<(Checkpoint, usize)>,
        public_values: PublicValues<u32, u32>,
        shard_batch_size: usize,
        challenger: Challenger,
    ) -> Result<PartialProof, WorkerError> {
        let requests = checkpoints
            .into_iter()
            .map(|(checkpoint, nb_checkpoints)| {
                WorkerRequest::Prove(
                    checkpoint,
                    nb_checkpoints,
                    public_values,
                    shard_batch_size,
                    challenger.clone(),
                )
            })
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
        &mut self,
        requests: Vec<WorkerRequest>,
    ) -> Result<Vec<WorkerResponse>, WorkerError> {
        use tokio::task::JoinSet;

        let mut set = JoinSet::new();

        for (i, (request, worker)) in requests.into_iter().zip(self.workers.iter()).enumerate() {
            let worker = Arc::clone(worker);

            log::info!("Sp1 Distributed: Sending request to worker {}", i);

            set.spawn(async move { worker.write().await.request(request).await });
        }

        let mut results = Vec::new();

        while let Some(res) = set.join_next().await {
            let out = res.map_err(|_e| WorkerError::AllWorkersFailed)?;

            match out {
                Ok(response) => {
                    log::info!(
                        "Sp1 Distributed: Got response from worker {}",
                        results.len()
                    );

                    results.push(response);
                }
                Err(_e) => {
                    return Err(WorkerError::AllWorkersFailed);
                }
            }
        }

        Ok(results)
    }

    async fn spawn_workers() -> Result<Vec<Arc<RwLock<WorkerSocket>>>, WorkerError> {
        let ip_list_string = std::fs::read_to_string("distributed.json")
            .expect("Sp1 Distributed: Need a `distributed.json` file with a list of IP:PORT");

        let ip_list: Vec<String> = serde_json::from_str(&ip_list_string).expect(
            "Sp1 Distributed: Invalid JSON for `distributed.json`. need an array of IP:PORT",
        );

        let mut workers = Vec::new();

        // try to connect to each worker to make sure they are reachable
        for ip in ip_list.into_iter() {
            let Ok(mut worker) = WorkerSocket::connect(&ip).await else {
                log::warn!("Sp1 Distributed: Worker at {} is not reachable. Removing from the list for this task", ip);

                continue;
            };

            if let Err(_e) = worker.ping().await {
                log::warn!("Sp1 Distributed: Worker at {} is not reachable. Removing from the list for this task", ip);

                continue;
            }

            workers.push(Arc::new(RwLock::new(worker)));
        }

        if workers.len() == 0 {
            log::error!("Sp1 Distributed: No reachable workers found. Aborting...");

            return Err(WorkerError::AllWorkersFailed);
        }

        Ok(workers)
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }
}
