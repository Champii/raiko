mod prover;
pub mod sp1_specifics;
mod worker;

pub use prover::Sp1DistributedProver;
pub use worker::{
    RequestData, WorkerEnvelope, WorkerPool, WorkerProtocol, WorkerRequest, WorkerResponse,
    WorkerSocket,
};
