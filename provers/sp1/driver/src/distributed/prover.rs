use std::env;

use raiko_lib::{
    input::{GuestInput, GuestOutput},
    prover::{to_proof, Proof, Prover, ProverConfig, ProverError, ProverResult},
};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin};

use crate::{Sp1Response, WorkerPool, ELF};

use super::sp1_specifics::{compute_checkpoints, observe_commitments, PartialProof};

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
        let mut worker_pool = WorkerPool::new().await?;

        let (checkpoints, public_values_stream, public_values, shard_batch_size) =
            compute_checkpoints(&stdin, worker_pool.len()).map_err(|e| {
                ProverError::GuestError(format!("Error while computing checkpoints: {}", e))
            })?;

        let (commitments, shards_public_values) = worker_pool
            .commit(checkpoints, public_values, shard_batch_size)
            .await?;

        let challenger = observe_commitments(commitments, shards_public_values);

        let partial_proofs = worker_pool.prove(challenger).await?;

        Ok(SP1ProofWithPublicValues {
            proof: partial_proofs,
            stdin,
            public_values: SP1PublicValues::from(&public_values_stream),
            sp1_version: sp1_core::SP1_CIRCUIT_VERSION.to_string(),
        })
    }
}
