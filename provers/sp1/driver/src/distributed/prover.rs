use std::{env, io::Read};

use super::worker::Worker;
use raiko_lib::{
    input::{GuestInput, GuestOutput},
    prover::{to_proof, Proof, Prover, ProverConfig, ProverResult},
    PartialProofRequestData,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp1_core::{runtime::Program, utils::SP1CoreOpts};
use sp1_sdk::{CoreSC, ProverClient, SP1Stdin};

use crate::{
    sp1_specifics::{compute_trace_and_challenger, nb_checkpoints, prove_partial},
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
        config: &ProverConfig,
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

        /* // Execute the program to get the public values and the number of checkpoints
        let (_nb_checkpoint, opts, _public_values) =
            nb_checkpoints(ELF, &stdin, ip_list.len()).expect("Sp1: execution failed"); */

        let proving_config = CoreSC::default();
        let mut opts = SP1CoreOpts::default();
        opts.shard_batch_size = 1;

        let (mut checkpoints, serialized_challenger, public_values_stream, public_values) =
            compute_trace_and_challenger(program, &stdin, proving_config, opts).unwrap();

        let mut config = config.clone();

        // Fixing the network and proof type to be forwarded to the workers
        let mut_config = config.as_object_mut().unwrap();
        mut_config.insert("network".to_string(), "taiko_a7".into());
        mut_config.insert("proof_type".to_string(), "sp1_distributed".into());
        mut_config.insert(
            "sp1".to_string(),
            serde_json::json!({
                "shard_batch_size": opts.shard_batch_size,
            }),
        );

        log::info!("Number of checkpoints: {}", checkpoints.len());

        let (queue_tx, queue_rx) = async_channel::unbounded();
        let (answer_tx, answer_rx) = async_channel::unbounded();

        let public_values_serialized = bincode::serialize(&public_values).unwrap();

        // Spawn the workers
        for (i, url) in ip_list.iter().enumerate() {
            let worker = Worker::new(
                i,
                "http://".to_string() + url + "/proof/partial".into(),
                config.clone(),
                queue_rx.clone(),
                answer_tx.clone(),
                queue_tx.clone(),
                public_values_serialized.clone(),
                serialized_challenger.clone(),
            );

            tokio::spawn(async move {
                worker.run().await;
            });
        }

        // Send the checkpoints to the workers
        // for i in 0..nb_checkpoint {
        for (i, checkpoint) in checkpoints.iter_mut().enumerate() {
            log::info!("Serializing checkpoint {}", i);
            // let serialized_checkpoint = bincode::serialize(checkpoint).unwrap();
            let mut serialized_checkpoint = Vec::new();
            checkpoint.read_to_end(&mut serialized_checkpoint).unwrap();
            log::info!("Serialized checkpoint len {}", serialized_checkpoint.len());
            log::info!("Sending checkpoint {}", i);
            queue_tx.send((i, serialized_checkpoint)).await.unwrap();
        }

        let mut proofs = Vec::new();

        // Get the partial proofs from the workers
        loop {
            let (checkpoint_id, partial_proof_json) = answer_rx.recv().await.unwrap();

            let partial_proof =
                serde_json::from_str::<Vec<_>>(partial_proof_json.as_str()).unwrap();

            std::fs::write(
                format!("partial_proof_{}.json", checkpoint_id),
                partial_proof_json,
            )
            .unwrap();

            proofs.push((checkpoint_id, partial_proof));

            if proofs.len() == checkpoints.len() {
                break;
            }
        }

        proofs.sort_by_key(|(checkpoint_id, _)| *checkpoint_id);

        let proofs = proofs
            .into_iter()
            .map(|(_, proof)| proof)
            .flatten()
            .collect();

        let proof = sp1_sdk::SP1ProofWithPublicValues {
            proof: proofs,
            stdin: stdin.clone(),
            public_values: public_values_stream,
            sp1_version: sp1_core::SP1_CIRCUIT_VERSION.to_string(),
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

    pub async fn run_as_worker(
        input: GuestInput,
        config: &ProverConfig,
        data: &PartialProofRequestData,
    ) -> ProverResult<Proof> {
        let sp1_config = data.request.clone();

        // let sp1_config: ProofRequest = serde_json::from_value(config.clone()).unwrap();

        /* let sp1_config = config.get("sp1").unwrap().as_object().unwrap();

        let checkpoint = sp1_config.get("i").unwrap().as_u64().unwrap() as usize;
        let shard_batch_size = sp1_config
            .get("shard_batch_size")
            .unwrap()
            .as_u64()
            .unwrap() as usize;
        let checkpoint_data =
            serde_json::from_str(&sp1_config.get("checkpoint_data").unwrap().as_str().unwrap())
                .unwrap();
        let serialized_challenger = serde_json::from_str(
            sp1_config
                .get("serialized_challenger")
                .unwrap()
                .as_str()
                .unwrap(),
        )
        .unwrap(); */

        println!("Running SP1 Distributed worker {}", data.checkpoint_id);

        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        // Generate the proof for the given program.
        let client = ProverClient::new();
        let (pk, _vk) = client.setup(ELF);

        let config = CoreSC::default();
        let program = Program::from(&pk.elf);
        let mut opts = SP1CoreOpts::default();
        opts.shard_batch_size = 1;

        let checkpoint_data = bincode::deserialize(&data.checkpoint_data).unwrap();

        let partial_proof = prove_partial(
            program,
            &stdin,
            config,
            opts,
            checkpoint_data,
            data.serialized_challenger.clone(),
            data.checkpoint_id,
            bincode::deserialize(&data.public_values).unwrap(),
        )
        .expect("Sp1: proving failed");

        to_proof(Ok(Sp1Response {
            proof: serde_json::to_string(&partial_proof).unwrap(),
        }))
    }
}
