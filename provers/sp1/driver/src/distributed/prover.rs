use std::env;

use raiko_lib::{
    input::{GuestInput, GuestOutput},
    prover::{to_proof, Proof, Prover, ProverConfig, ProverError, ProverResult, WorkerError},
};
use sp1_core::{
    air::PublicValues,
    runtime::{ExecutionRecord, ExecutionState, Program},
    stark::ShardProof,
    utils::BabyBearPoseidon2,
};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin};

use crate::{Sp1Response, WorkerPool, WorkerSocket, ELF};

use super::{
    sp1_specifics::{self, compute_checkpoints, observe_commitments},
    Challenger, Checkpoint, Commitments, PartialProof,
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

        let proof = Sp1DistributedOrchestrator::prove(stdin).await?;

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

pub struct Sp1DistributedOrchestrator;

impl Sp1DistributedOrchestrator {
    pub async fn prove(stdin: SP1Stdin) -> ProverResult<SP1ProofWithPublicValues<PartialProof>> {
        // compute checkpoints
        // send checkpoints to workers for commit
        // get commit data
        // observe challenger
        // send challenger to workers for partial proof
        // get partial proofs

        let worker_pool = WorkerPool::new().await?;

        let (checkpoints, public_values_stream, public_values, shard_batch_size) =
            compute_checkpoints(&stdin, worker_pool.len()).map_err(|e| {
                ProverError::GuestError(format!("Error while computing checkpoints: {}", e))
            })?;

        let commitments = worker_pool
            .commit(checkpoints, public_values, shard_batch_size)
            .await?;

        let challenger = observe_commitments(commitments, public_values);

        let partial_proofs = worker_pool.prove(challenger).await?;

        /////////

        /* let (checkpoints, public_values_stream, partial_proof_request) =
            commit(program, &stdin, worker_ip_list.len())
                .map_err(|e| ProverError::GuestError(e.to_string()))?;

        let proofs = super::orchestrator::distribute_work(
            worker_ip_list,
            checkpoints,
            partial_proof_request,
        )
        .await?; */

        Ok(SP1ProofWithPublicValues {
            proof: partial_proofs,
            stdin,
            public_values: SP1PublicValues::from(&public_values_stream),
            sp1_version: sp1_core::SP1_CIRCUIT_VERSION.to_string(),
        })
    }

    /* pub async fn run_as_worker(request: WorkerRequest) -> ProverResult<WorkerResponse> {
        log::debug!(
            "Running SP1 Distributed worker: shard nb {}",
            partial_proof_request.checkpoint_id
        );

        match request {
            WorkerRequest::Commit(i, checkpoint, public_values) => {
                let commitment = commit(&checkpoint, &public_values);

                Ok(WorkerResponse::Commit(i, commitment))
            }
            WorkerRequest::Prove(i, challenger) => {
                let partial_proof = prove_partial(&challenger);

                Ok(WorkerResponse::Prove(i, partial_proof))
            }
        }

        let partial_proof = prove_partial(&partial_proof_request);

        Ok(partial_proof)
    } */
}

pub struct Sp1DistributedWorker;

impl Sp1DistributedWorker {
    pub fn commit(
        checkpoint: Checkpoint,
        public_values: PublicValues<u32, u32>,
        shard_batch_size: usize,
    ) -> Result<(Vec<ExecutionRecord>, Commitments), WorkerError> {
        sp1_specifics::commit(checkpoint, public_values, shard_batch_size)
    }

    pub fn prove(
        shards: Vec<ExecutionRecord>,
        public_values: PublicValues<u32, u32>,
        challenger: Challenger,
    ) -> Result<PartialProof, WorkerError> {
        sp1_specifics::prove(shards, public_values, challenger)
    }
}
