use raiko_lib::prover::WorkerError;
use serde::{Deserialize, Serialize};

use crate::WorkerProtocol;

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
