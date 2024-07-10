#![cfg(feature = "enable")]

use serde::{Deserialize, Serialize};

mod distributed;
mod local;

pub use distributed::{
    sp1_specifics, RequestData, Sp1DistributedProver, WorkerEnvelope, WorkerPool, WorkerProtocol,
    WorkerRequest, WorkerResponse, WorkerSocket,
};

pub use local::Sp1Prover;

pub const ELF: &[u8] = include_bytes!("../../guest/elf/sp1-guest");

#[derive(Clone, Serialize, Deserialize)]
pub struct Sp1Response {
    pub proof: String,
}
