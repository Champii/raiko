#![cfg(feature = "enable")]

use serde::{Deserialize, Serialize};

mod distributed;
mod local;

pub use distributed::Sp1DistributedProver;
pub use local::Sp1Prover;

const ELF: &[u8] = include_bytes!("../../guest/elf/sp1-guest");

#[derive(Clone, Serialize, Deserialize)]
pub struct Sp1Response {
    pub proof: String,
}

#[cfg(test)]
mod test {
    use super::*;
    const TEST_ELF: &[u8] = include_bytes!("../../guest/elf/test-sp1-guest");

    #[test]
    fn run_unittest_elf() {
        // TODO(Cecilia): imple GuestInput::mock() for unit test
        let client = ProverClient::new();
        let stdin = SP1Stdin::new();
        let (pk, vk) = client.setup(TEST_ELF);
        let proof = client.prove(&pk, stdin).expect("Sp1: proving failed");
        client
            .verify(&proof, &vk)
            .expect("Sp1: verification failed");
    }
}

mod sp1_specifics {
    use std::fs::File;
    use std::io::Seek;
    use std::io::Write;
    use std::time::Instant;

    use p3_challenger::CanObserve;
    use p3_field::PrimeField32;
    use serde::{de::DeserializeOwned, Serialize};
    use sp1_core::runtime::ExecutionRecord;
    use sp1_core::{
        runtime::{ExecutionError, Program, Runtime, ShardingConfig},
        stark::{
            Com, LocalProver, MachineRecord, OpeningProof, PcsProverData, RiscvAir, ShardMainData,
            ShardProof, StarkGenericConfig,
        },
        utils::{SP1CoreOpts, SP1CoreProverError},
    };
    use sp1_sdk::{SP1PublicValues, SP1Stdin};

    fn trace_checkpoint(program: Program, file: &File, opts: SP1CoreOpts) -> ExecutionRecord {
        let mut reader = std::io::BufReader::new(file);
        let state = bincode::deserialize_from(&mut reader).expect("failed to deserialize state");
        let mut runtime = Runtime::recover(program.clone(), state, opts);
        let (events, _) =
            tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());
        events
    }

    fn reset_seek(file: &mut File) {
        file.seek(std::io::SeekFrom::Start(0))
            .expect("failed to seek to start of tempfile");
    }

    pub fn nb_checkpoints(
        elf: &[u8],
        stdin: &SP1Stdin,
        nb_workers: usize,
    ) -> Result<(usize, SP1CoreOpts, SP1PublicValues), ExecutionError> {
        // nb_checkpoints, sp1_core_opts, public_values
        let program = Program::from(elf);
        let mut opts = SP1CoreOpts::default();

        opts.shard_size = std::env::var("SHARD_SIZE")
            .unwrap_or(opts.shard_size.to_string())
            .parse::<usize>()
            .unwrap_or(opts.shard_size);

        opts.shard_batch_size = std::env::var("SHARD_BATCH_SIZE")
            .unwrap_or(opts.shard_batch_size.to_string())
            .parse::<usize>()
            .unwrap_or(opts.shard_batch_size);

        let mut runtime = Runtime::new(program, opts);
        runtime.write_vecs(&stdin.buffer);
        for (proof, vkey) in stdin.proofs.iter() {
            runtime.write_proof(proof.clone(), vkey.clone());
        }
        runtime.run()?;

        let nb_shards =
            (runtime.record.cpu_events.len() as f64 / opts.shard_size as f64).ceil() as usize;

        opts.shard_batch_size = (nb_shards as f64 / nb_workers as f64).ceil() as usize;

        let nb_checkpoints = (nb_shards as f64 / opts.shard_batch_size as f64).ceil() as usize;

        println!("nb_shards: {}", nb_shards);
        println!("shard_batch_size: {}", opts.shard_batch_size);
        println!("nb_checkpoints: {}", nb_checkpoints);

        Ok((
            nb_checkpoints,
            opts,
            SP1PublicValues::from(&runtime.state.public_values_stream),
        ))
    }

    pub fn prove_partial<SC: StarkGenericConfig + Send + Sync>(
        program: Program,
        stdin: &SP1Stdin,
        config: SC,
        opts: SP1CoreOpts,
        checkpoint_id: usize,
    ) -> Result<Vec<ShardProof<SC>>, SP1CoreProverError>
    where
        SC::Challenger: Clone,
        OpeningProof<SC>: Send + Sync,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        <SC as StarkGenericConfig>::Val: PrimeField32,
    {
        let proving_start = Instant::now();

        // Execute the program.
        let mut runtime = Runtime::new(program.clone(), opts);
        runtime.write_vecs(&stdin.buffer);
        for proof in stdin.proofs.iter() {
            runtime.write_proof(proof.0.clone(), proof.1.clone());
        }

        // Setup the machine.
        let machine = RiscvAir::machine(config);
        let (pk, vk) = machine.setup(runtime.program.as_ref());

        // If we don't need to batch, we can just run the program normally and prove it.
        /* if opts.shard_batch_size == 0 {
            // Execute the runtime and collect all the events..
            runtime.run().map_err(SP1CoreProverError::ExecutionError)?;

            // If debugging is enabled, we will also debug the constraints.
            #[cfg(feature = "debug")]
            {
                let mut challenger = machine.config().challenger();
                machine.debug_constraints(&pk, runtime.record.clone(), &mut challenger);
            }

            // Generate the proof and return the proof and public values.
            let public_values = std::mem::take(&mut runtime.state.public_values_stream);
            let proof = prove_simple(machine.config().clone(), runtime)?;
            return Ok(proof);
        } */

        // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
        let mut checkpoints = Vec::new();
        let (_public_values_stream, public_values) = loop {
            // Execute the runtime until we reach a checkpoint.
            let (checkpoint, done) = runtime
                .execute_state()
                .map_err(SP1CoreProverError::ExecutionError)?;

            // Save the checkpoint to a temp file.
            let mut tempfile = tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
            let mut writer = std::io::BufWriter::new(&mut tempfile);
            bincode::serialize_into(&mut writer, &checkpoint)
                .map_err(SP1CoreProverError::SerializationError)?;
            writer.flush().map_err(SP1CoreProverError::IoError)?;
            drop(writer);
            tempfile
                .seek(std::io::SeekFrom::Start(0))
                .map_err(SP1CoreProverError::IoError)?;
            checkpoints.push(tempfile);

            // If we've reached the final checkpoint, break out of the loop.
            if done {
                break (
                    std::mem::take(&mut runtime.state.public_values_stream),
                    runtime.record.public_values,
                );
            }
        };
        println!("CHECKPOINTS: {}", checkpoints.len());

        // For each checkpoint, generate events, shard them, commit shards, and observe in challenger.
        let sharding_config = ShardingConfig::default();
        let mut shard_main_datas = Vec::new();
        let mut challenger = machine.config().challenger();
        vk.observe_into(&mut challenger);

        let mut checkpoint_shards_vec = Vec::new();

        for checkpoint_file in checkpoints.iter_mut() {
            let mut record = trace_checkpoint(program.clone(), checkpoint_file, opts);
            record.public_values = public_values;
            reset_seek(&mut *checkpoint_file);

            // Shard the record into shards.
            let checkpoint_shards =
                tracing::info_span!("shard").in_scope(|| machine.shard(record, &sharding_config));

            // Commit to each shard.
            let (commitments, commit_data) = tracing::info_span!("commit")
                .in_scope(|| LocalProver::commit_shards(&machine, &checkpoint_shards, opts));
            shard_main_datas.push(commit_data);

            // Observe the commitments.
            for (commitment, shard) in commitments.into_iter().zip(checkpoint_shards.iter()) {
                challenger.observe(commitment);
                challenger
                    .observe_slice(&shard.public_values::<SC::Val>()[0..machine.num_pv_elts()]);
            }
            checkpoint_shards_vec.push(checkpoint_shards);
        }

        // For each checkpoint, generate events and shard again, then prove the shards.
        let mut shard_proofs = Vec::<ShardProof<SC>>::new();
        // let mut checkpoint_file = checkpoints.into_iter().nth(checkpoint_id).unwrap();

        /* let checkpoint_shards = {
            let mut events = trace_checkpoint(program.clone(), &checkpoint_file, opts);
            events.public_values = public_values;
            reset_seek(&mut checkpoint_file);
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config))
        }; */

        log::info!("Starting proof shard");
        let mut checkpoint_proofs = checkpoint_shards_vec
            .into_iter()
            .nth(checkpoint_id)
            .unwrap()
            .into_iter()
            .map(|shard| {
                let config = machine.config();
                log::info!("Commit main");
                let shard_data =
                    LocalProver::commit_main(config, &machine, &shard, shard.index() as usize);

                let chip_ordering = shard_data.chip_ordering.clone();
                let ordered_chips = machine
                    .shard_chips_ordered(&chip_ordering)
                    .collect::<Vec<_>>()
                    .to_vec();

                log::info!("Actually prove shard");
                LocalProver::prove_shard(
                    config,
                    &pk,
                    &ordered_chips,
                    shard_data,
                    &mut challenger.clone(),
                )
            })
            .collect::<Vec<_>>();

        shard_proofs.append(&mut checkpoint_proofs);

        // let proof = MachineProof::<SC> { shard_proofs };

        // Print the summary.
        let proving_time = proving_start.elapsed().as_secs_f64();
        tracing::info!(
            "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
            runtime.state.global_clk,
            proving_time,
            (runtime.state.global_clk as f64 / proving_time as f64),
            bincode::serialize(&shard_proofs).unwrap().len(),
        );

        Ok(shard_proofs)
    }
}
