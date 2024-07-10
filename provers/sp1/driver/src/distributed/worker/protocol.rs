use std::fmt::{Display, Formatter};

use raiko_lib::prover::WorkerError;
use serde::{Deserialize, Serialize};
use sp1_core::air::PublicValues;

use crate::sp1_specifics::{
    Challenger, Checkpoint, Commitments, PartialProofs, ShardsPublicValues,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerEnvelope {
    version: u64,
    data: WorkerProtocol,
}

impl WorkerEnvelope {
    pub fn data(self) -> Result<WorkerProtocol, WorkerError> {
        if self.version != include!("../../../worker.version") {
            return Err(WorkerError::InvalidVersion);
        }

        Ok(self.data)
    }
}

impl From<WorkerProtocol> for WorkerEnvelope {
    fn from(data: WorkerProtocol) -> Self {
        WorkerEnvelope {
            version: include!("../../../worker.version"),
            data,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerProtocol {
    Request(WorkerRequest),
    Response(WorkerResponse),
}

impl From<WorkerRequest> for WorkerProtocol {
    fn from(req: WorkerRequest) -> Self {
        WorkerProtocol::Request(req)
    }
}

impl From<WorkerResponse> for WorkerProtocol {
    fn from(res: WorkerResponse) -> Self {
        WorkerProtocol::Response(res)
    }
}

impl Display for WorkerProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerProtocol::Request(req) => write!(f, "Request({})", req),
            WorkerProtocol::Response(res) => write!(f, "Response({})", res),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    Ping,
    Commit {
        checkpoint: Checkpoint,
        nb_checkpoints: usize,
        public_values: PublicValues<u32, u32>,
        shard_batch_size: usize,
        shard_size: usize,
    },
    Prove {
        checkpoint: Checkpoint,
        nb_checkpoints: usize,
        public_values: PublicValues<u32, u32>,
        shard_batch_size: usize,
        shard_size: usize,
        challenger: Challenger,
    },
}

impl Display for WorkerRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerRequest::Ping => write!(f, "Ping"),
            WorkerRequest::Commit { .. } => {
                write!(f, "Commit")
            }
            WorkerRequest::Prove { .. } => write!(f, "Prove"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    Pong,
    Commitment {
        commitments: Commitments,
        shards_public_values: Vec<ShardsPublicValues>,
    },
    Proof(PartialProofs),
}

impl Display for WorkerResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerResponse::Pong => write!(f, "Pong"),
            WorkerResponse::Commitment { .. } => write!(f, "Commit"),
            WorkerResponse::Proof(_) => write!(f, "Prove"),
        }
    }
}
