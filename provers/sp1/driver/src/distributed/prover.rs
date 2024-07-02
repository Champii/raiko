use std::{
    env,
    fmt::{Display, Formatter},
};

use raiko_lib::{
    input::{GuestInput, GuestOutput},
    prover::{to_proof, Proof, Prover, ProverConfig, ProverResult, WorkerError},
};
use serde::{Deserialize, Serialize};
use sp1_core::{runtime::Program, stark::ShardProof, utils::BabyBearPoseidon2};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1Stdin};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};

use crate::{
    distributed::{
        partial_proof_request::PartialProofRequest,
        sp1_specifics::{commit, prove_partial},
    },
    Sp1Response, ELF,
};

pub struct Sp1DistributedProver;

impl Prover for Sp1DistributedProver {
    async fn run(
        input: GuestInput,
        _output: &GuestOutput,
        _config: &ProverConfig,
    ) -> ProverResult<Proof> {
        log::info!("Running SP1 Distributed orchestrator");

        let now = std::time::Instant::now();

        // Write the input.
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        // Generate the proof for the given program.
        let client = ProverClient::new();
        let (_pk, vk) = client.setup(ELF);

        let proof = Self::run_as_orchestrator(stdin).await?;

        // Verify proof.
        client
            .verify(&proof, &vk)
            .expect("Sp1: verification failed");

        log::info!(
            "Proof generation and verification took: {:?}s",
            now.elapsed().as_secs()
        );

        // Save the proof.
        let proof_dir = env::current_dir().expect("Sp1: dir error");

        proof
            .save(
                proof_dir
                    .as_path()
                    .join("proof-with-io.json")
                    .to_str()
                    .unwrap(),
            )
            .expect("Sp1: saving proof failed");

        to_proof(Ok(Sp1Response {
            proof: serde_json::to_string(&proof).unwrap(),
        }))
    }
}

impl Sp1DistributedProver {
    pub async fn run_as_orchestrator(
        stdin: SP1Stdin,
    ) -> ProverResult<SP1ProofWithPublicValues<Vec<ShardProof<BabyBearPoseidon2>>>> {
        let program = Program::from(ELF);

        let worker_ip_list = Self::read_and_validate_worker_ip_list().await?;

        let (checkpoints, public_values_stream, partial_proof_request) =
            commit(program, &stdin, worker_ip_list.len()).unwrap();

        let proofs = super::orchestrator::distribute_work(
            worker_ip_list,
            checkpoints,
            partial_proof_request,
        )
        .await?;

        Ok(SP1ProofWithPublicValues {
            proof: proofs,
            stdin,
            public_values: public_values_stream,
            sp1_version: sp1_core::SP1_CIRCUIT_VERSION.to_string(),
        })
    }

    pub async fn run_as_worker(
        partial_proof_request: PartialProofRequest,
    ) -> ProverResult<Vec<ShardProof<BabyBearPoseidon2>>> {
        log::debug!(
            "Running SP1 Distributed worker: Prove shard nb {}",
            partial_proof_request.checkpoint_id
        );

        let partial_proof = prove_partial(&partial_proof_request);

        Ok(partial_proof)
    }

    async fn read_and_validate_worker_ip_list() -> Result<Vec<String>, WorkerError> {
        let ip_list_string = std::fs::read_to_string("distributed.json")
            .expect("Sp1 Distributed: Need a `distributed.json` file with a list of IP:PORT");

        let ip_list: Vec<String> = serde_json::from_str(&ip_list_string).expect(
            "Sp1 Distributed: Invalid JSON for `distributed.json`. need an array of IP:PORT",
        );

        let mut reachable_ip_list = Vec::new();

        // try to connect to each worker to make sure they are reachable
        for ip in &ip_list {
            let Ok(mut socket) = WorkerSocket::connect(ip).await else {
                log::warn!("Sp1 Distributed: Worker at {} is not reachable. Removing from the list for this task", ip);

                continue;
            };

            if let Err(_) = socket.send(WorkerProtocol::Ping).await {
                log::warn!("Sp1 Distributed: Worker at {} is not reachable. Removing from the list for this task", ip);

                continue;
            }

            let Ok(response) = socket.receive().await else {
                log::warn!("Sp1 Distributed: Worker at {} is not a valid SP1 worker. Removing from the list for this task", ip);

                continue;
            };

            if let WorkerProtocol::Ping = response {
                reachable_ip_list.push(ip.clone());
            } else {
                log::warn!("Sp1 Distributed: Worker at {} is not a valid SP1 worker. Removing from the list for this task", ip);
            }
        }

        if reachable_ip_list.is_empty() {
            log::error!("Sp1 Distributed: No reachable workers found. Aborting...");

            return Err(WorkerError::AllWorkersFailed);
        }

        Ok(reachable_ip_list)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerEnvelope {
    pub magic: u64,
    pub data: WorkerProtocol,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerProtocol {
    Ping,
    PartialProofRequest(PartialProofRequest),
    PartialProofResponse(Vec<ShardProof<BabyBearPoseidon2>>),
}

impl Display for WorkerProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerProtocol::Ping => write!(f, "Ping"),
            WorkerProtocol::PartialProofRequest(_) => write!(f, "PartialProofRequest"),
            WorkerProtocol::PartialProofResponse(_) => write!(f, "PartialProofResponse"),
        }
    }
}

impl From<WorkerProtocol> for WorkerEnvelope {
    fn from(data: WorkerProtocol) -> Self {
        WorkerEnvelope {
            magic: 0xdeadbeef,
            data,
        }
    }
}

pub struct WorkerSocket {
    pub socket: tokio::net::TcpStream,
}

impl WorkerSocket {
    pub async fn connect(url: &str) -> Result<Self, WorkerError> {
        let stream = tokio::net::TcpStream::connect(url).await?;

        Ok(WorkerSocket { socket: stream })
    }

    pub fn new(socket: tokio::net::TcpStream) -> Self {
        WorkerSocket { socket }
    }

    pub async fn send(&mut self, packet: WorkerProtocol) -> Result<(), WorkerError> {
        let envelope: WorkerEnvelope = packet.into();

        let data = bincode::serialize(&envelope)?;

        self.socket.write_u64(data.len() as u64).await?;
        self.socket.write_all(&data).await?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<WorkerProtocol, WorkerError> {
        let data = self.read_data().await?;

        let envelope: WorkerEnvelope = bincode::deserialize(&data)?;

        if envelope.magic != 0xdeadbeef {
            return Err(WorkerError::InvalidMagicNumber);
        }

        Ok(envelope.data)
    }

    // TODO: Add a timeout
    pub async fn read_data(&mut self) -> Result<Vec<u8>, std::io::Error> {
        // TODO: limit the size of the data
        let size = self.socket.read_u64().await? as usize;

        let mut data = Vec::new();

        let mut buf_data = BufWriter::new(&mut data);
        let mut buf = [0; 1024];
        let mut total_read = 0;

        loop {
            match self.socket.read(&mut buf).await {
                // socket closed
                Ok(n) if n == 0 => return Ok(data),
                Ok(n) => {
                    buf_data.write_all(&buf[..n]).await?;

                    total_read += n;

                    if total_read == size {
                        buf_data.flush().await?;

                        return Ok(data);
                    }

                    // TODO: handle the case where the data is bigger than expected
                }
                Err(e) => {
                    log::error!("failed to read from socket; err = {:?}", e);

                    return Err(e);
                }
            };
        }
    }
}
