use std::env;

use raiko_lib::{
    input::{GuestInput, GuestOutput},
    prover::{to_proof, Proof, Prover, ProverConfig, ProverResult},
    PartialProofRequestData,
};
use sp1_core::{runtime::Program, utils::SP1CoreOpts};
use sp1_sdk::{CoreSC, ProverClient, SP1Stdin};

use crate::{
    distributed::sp1_specifics::{prove_partial_old, short_circuit_proof},
    Sp1Response, ELF,
};

pub struct Sp1DistributedProver;

impl Prover for Sp1DistributedProver {
    async fn run(
        input: GuestInput,
        output: &GuestOutput,
        config: &ProverConfig,
    ) -> ProverResult<Proof> {
        println!("Running SP1 Distributed prover");

        /* if config.get("sp1").map(|sp1| sp1.get("checkpoint")).is_some() {
            return Self::run_as_worker(input, output, &config).await;
        } */

        return Self::run_as_orchestrator(input, output, &config).await;
    }
}

impl Sp1DistributedProver {
    pub async fn run_as_orchestrator(
        input: GuestInput,
        _output: &GuestOutput,
        _config: &ProverConfig,
    ) -> ProverResult<Proof> {
        let now = std::time::Instant::now();

        log::info!("Running SP1 Distributed orchestrator");

        // Write the input.
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        let ip_list = std::fs::read_to_string("distributed.json").unwrap();
        let ip_list: Vec<String> = serde_json::from_str(&ip_list).unwrap();

        // Generate the proof for the given program.
        let client = ProverClient::new();
        let (pk, vk) = client.setup(ELF);

        let program = Program::from(&pk.elf);

        let proving_config = CoreSC::default();
        let mut opts = SP1CoreOpts::default();
        opts.shard_batch_size = 1;

        let (checkpoints, challenger, public_values_stream, public_values, shard_batch_size) =
            prove_partial_old(
                program.clone(),
                &stdin,
                proving_config.clone(),
                opts.clone(),
                ip_list.len(),
            )
            .unwrap();

        log::info!("Number of checkpoints: {}", checkpoints.len());

        let proofs = super::orchestrator::distribute_work(
            ip_list,
            checkpoints,
            public_values,
            challenger,
            shard_batch_size,
        )
        .await;

        let proof = sp1_sdk::SP1ProofWithPublicValues {
            proof: proofs,
            stdin: stdin.clone(),
            public_values: public_values_stream,
            // sp1_version: sp1_core::SP1_CIRCUIT_VERSION.to_string(),
        };

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

    pub async fn run_as_worker(data: &PartialProofRequestData) -> ProverResult<Proof> {
        println!("Running SP1 Distributed worker {}", data.checkpoint_id);
        let config = CoreSC::default();
        let mut opts = SP1CoreOpts::default();
        opts.shard_batch_size = data.shard_batch_size;

        let partial_proof = short_circuit_proof(
            Program::from(ELF),
            config,
            opts.clone(),
            bincode::deserialize(&data.checkpoint_data).unwrap(),
            bincode::deserialize(&data.serialized_challenger).unwrap(),
            bincode::deserialize(&data.public_values).unwrap(),
        );

        to_proof(Ok(Sp1Response {
            proof: serde_json::to_string(&partial_proof).unwrap(),
        }))
    }
}
