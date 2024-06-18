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

    use p3_baby_bear::BabyBear;
    use p3_baby_bear::DiffusionMatrixBabyBear;
    use p3_challenger::CanObserve;
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeField32;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use serde::ser::SerializeStruct;
    use serde::ser::SerializeTuple;
    use serde::Serializer;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use serde_remote::deserialize_duplex_challenger;
    use serde_remote::serialize_duplex_challenger;
    use sp1_core::air::PublicValues;
    use sp1_core::runtime::ExecutionRecord;
    use sp1_core::runtime::ExecutionState;
    use sp1_core::utils::baby_bear_poseidon2::Perm;
    use sp1_core::utils::baby_bear_poseidon2::Val;
    use sp1_core::utils::BabyBearPoseidon2;
    use sp1_core::{
        runtime::{ExecutionError, Program, Runtime, ShardingConfig},
        stark::{
            Com, LocalProver, MachineRecord, OpeningProof, PcsProverData, RiscvAir, ShardMainData,
            ShardProof, StarkGenericConfig,
        },
        utils::{SP1CoreOpts, SP1CoreProverError},
    };
    use sp1_sdk::{SP1PublicValues, SP1Stdin};

    use crate::ELF;

    mod serde_remote {
        use super::{Perm, Val};
        use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
        use p3_challenger::DuplexChallenger;
        use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
        use p3_symmetric::{CryptographicPermutation, Hash};
        use serde::{ser::SerializeTuple, Serializer};
        pub use serde::{Deserialize, Serialize};

        #[derive(Copy, Clone, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
        #[repr(transparent)] // `PackedBabyBearNeon` relies on this!
        pub struct BabyBearRemote {
            // This is `pub(crate)` just for tests. If you're accessing `value` outside of those, you're
            // likely doing something fishy.
            pub value: u32,
        }

        fn babybear_to_babybearremote(babybear: BabyBear) -> BabyBearRemote {
            unsafe { std::mem::transmute(babybear) }
        }

        fn babybearremote_to_babybear(babybear_remote: BabyBearRemote) -> BabyBear {
            unsafe { std::mem::transmute(babybear_remote) }
        }

        #[derive(Default, Clone, Serialize, Deserialize)]
        pub struct Poseidon2ExternalMatrixGeneralRemote;

        #[derive(Debug, Clone, Default, Serialize, Deserialize)]
        pub struct DiffusionMatrixBabyBearRemote;

        #[derive(Clone, Serialize, Deserialize)]
        pub struct Poseidon2Remote {
            pub rounds_f: usize,
            /* #[serde(serialize_with = "serialize_external_constants")]
            #[serde(deserialize_with = "deserialize_external_constants")] */
            pub external_constants: Vec<[BabyBearRemote; 16]>,
            pub external_linear_layer: Poseidon2ExternalMatrixGeneralRemote,
            pub rounds_p: usize,
            pub internal_constants: Vec<BabyBearRemote>,
            pub internal_linear_layer: DiffusionMatrixBabyBearRemote,
        }

        fn poseidon2_to_poseidon2remote(
            poseidon2: Poseidon2<
                BabyBear,
                Poseidon2ExternalMatrixGeneral,
                DiffusionMatrixBabyBear,
                16,
                7,
            >,
        ) -> Poseidon2Remote {
            // transmute
            unsafe { std::mem::transmute(poseidon2) }
        }

        fn poseidon2remote_to_poseidon2(
            poseidon2_remote: Poseidon2Remote,
        ) -> Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>
        {
            // transmute
            unsafe { std::mem::transmute(poseidon2_remote) }
        }

        #[derive(Clone, Serialize, Deserialize)]
        pub struct DuplexChallengerRemote {
            pub sponge_state: [BabyBearRemote; 16],
            pub input_buffer: Vec<BabyBearRemote>,
            pub output_buffer: Vec<BabyBearRemote>,
            pub permutation: Poseidon2Remote,
        }

        fn duplexchallenge_to_duplexchallengerremote(
            duplex_challenger: DuplexChallenger<
                BabyBear,
                Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
                16,
                8,
            >,
        ) -> DuplexChallengerRemote {
            // transmute
            unsafe { std::mem::transmute(duplex_challenger) }
        }

        fn duplexchallengerremote_to_duplexchallenger(
            duplex_challenger_remote: DuplexChallengerRemote,
        ) -> DuplexChallenger<
            BabyBear,
            Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
            16,
            8,
        > {
            // transmute
            unsafe { std::mem::transmute(duplex_challenger_remote) }
        }

        pub fn serialize_duplex_challenger(
            duplex_challenger: &DuplexChallenger<Val, Perm, 16, 8>,
        ) -> Vec<u8> {
            let transmuted = duplexchallenge_to_duplexchallengerremote(duplex_challenger.clone());
            bincode::serialize(&transmuted).unwrap()
        }

        pub fn deserialize_duplex_challenger(
            serialized: Vec<u8>,
        ) -> DuplexChallenger<Val, Perm, 16, 8> {
            let transmuted: DuplexChallengerRemote = bincode::deserialize(&serialized).unwrap();
            duplexchallengerremote_to_duplexchallenger(transmuted)
        }

        /* fn serialize_sponge_state<const WIDTH: usize, S, T>(
            t: &[T; WIDTH],
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: Serialize,
        {
            let mut ser_tuple = serializer.serialize_seq(Some(WIDTH))?;
            for elem in t {
                ser_tuple.serialize_element(elem)?;
            }
            ser_tuple.end()
        }

        fn deserialize_sponge_state<'de, T, const WIDTH: usize, D>(
            deserializer: D,
        ) -> Result<[T; WIDTH], D::Error>
        where
            D: serde::Deserializer<'de>,
            T: Deserialize<'de>,
        {
            deserializer.deserialize_seq(SpongeStateVisitor::<T, WIDTH>)
        }

        fn serialize_external_constants<const WIDTH: usize, S, T>(
            t: &Vec<[T; WIDTH]>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: Serialize,
        {
            let serialized_inner = t.iter().map(|x| serialize_sponge_state(x, serializer));

            t.serialize(serializer)
        }

        fn deserialize_external_constants<'de, T, const WIDTH: usize, D>(
            deserializer: D,
        ) -> Result<Vec<[T; WIDTH]>, D::Error>
        where
            D: serde::Deserializer<'de>,
            T: Deserialize<'de>,
        {
            let deserialized_inner = Vec::<[T; WIDTH]>::deserialize(deserializer)?;
            Ok(deserialized_inner)
        } */
    }

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

    pub fn compute_trace_and_challenger(
        program: Program,
        stdin: &SP1Stdin,
        config: BabyBearPoseidon2,
        opts: SP1CoreOpts,
    ) -> Result<(Vec<File>, Vec<u8>, SP1PublicValues, PublicValues<u32, u32>), SP1CoreProverError>
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

        // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
        let mut checkpoints = Vec::new();
        let (public_values_stream, public_values) = loop {
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
            println!("CHECKPOINT SIZE: {}", tempfile.metadata().unwrap().len());

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
        let machine_config = machine.config();
        let mut challenger: DuplexChallenger<Val, Perm, 16, 8> =
            DuplexChallenger::new(machine_config.perm.clone());
        // let mut challenger = machine.config().challenger();
        // vk.observe_into(&mut challenger);
        log::info!(
            "Public value size: {}",
            bincode::serialize(&public_values).unwrap().len()
        );

        let mut checkpoint_shards_vec = Vec::new();

        for checkpoint_file in checkpoints.iter_mut() {
            let mut record = trace_checkpoint(program.clone(), checkpoint_file, opts);
            record.public_values = public_values;
            reset_seek(&mut *checkpoint_file);

            log::info!(
                "Record size: {}",
                bincode::serialize(&record).unwrap().len()
            );

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
                challenger.observe_slice(&shard.public_values::<Val>()[0..machine.num_pv_elts()]);
            }
            checkpoint_shards_vec.push(checkpoint_shards);
        }

        let serialized_challenger = serialize_duplex_challenger(&challenger);

        println!("CHALLENGER SIZE: {}", serialized_challenger.len());

        let public_values_stream = SP1PublicValues::from(&public_values_stream);
        Ok((
            checkpoints,
            serialized_challenger,
            public_values_stream,
            public_values,
        ))
    }

    pub fn prove_partial(
        program: Program,
        stdin: &SP1Stdin,
        config: BabyBearPoseidon2,
        opts: SP1CoreOpts,
        checkpoint: ExecutionState,
        serialized_challenger: Vec<u8>,
        checkpoint_id: usize,
        public_values: sp1_core::air::PublicValues<u32, u32>,
    ) -> Result<Vec<ShardProof<BabyBearPoseidon2>>, SP1CoreProverError>
/* where
        SC::Challenger: Clone,
        OpeningProof<SC>: Send + Sync,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        <SC as StarkGenericConfig>::Val: PrimeField32, */ {
        let proving_start = Instant::now();

        /* // Execute the program.
        let mut runtime = Runtime::new(program.clone(), opts);
        runtime.write_vecs(&stdin.buffer);
        for proof in stdin.proofs.iter() {
            runtime.write_proof(proof.0.clone(), proof.1.clone());
        } */

        // Setup the machine.
        let machine = RiscvAir::machine(config);
        let (pk, vk) = machine.setup(&program);

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

        /* // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
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
            println!("CHECKPOINT SIZE: {}", tempfile.metadata().unwrap().len());

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
        let machine_config = machine.config();
        let mut challenger: DuplexChallenger<Val, Perm, 16, 8> =
            DuplexChallenger::new(machine_config.perm.clone());
        // let mut challenger = machine.config().challenger();
        // vk.observe_into(&mut challenger);

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
                challenger.observe_slice(&shard.public_values::<Val>()[0..machine.num_pv_elts()]);
            }
            checkpoint_shards_vec.push(checkpoint_shards);
        } */

        // For each checkpoint, generate events and shard again, then prove the shards.
        let mut shard_proofs = Vec::<ShardProof<BabyBearPoseidon2>>::new();
        // let mut checkpoint_file = checkpoints.into_iter().nth(checkpoint_id).unwrap();

        /* let checkpoint_shards = {
            let mut events = trace_checkpoint(program.clone(), &checkpoint_file, opts);
            events.public_values = public_values;
            reset_seek(&mut checkpoint_file);
            tracing::debug_span!("shard").in_scope(|| machine.shard(events, &sharding_config))
        }; */

        let mut challenger = deserialize_duplex_challenger(serialized_challenger);

        let mut events = {
            let mut runtime = Runtime::recover(program.clone(), checkpoint, opts);
            let (events, _) = tracing::debug_span!("runtime.trace")
                .in_scope(|| runtime.execute_record().unwrap());
            events
        };

        // TODO
        events.public_values = public_values;

        let sharding_config = ShardingConfig::default();
        let checkpoint = machine.shard(events, &sharding_config);

        log::info!("Starting proof shard");
        let mut checkpoint_proofs = checkpoint
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
        /* tracing::info!(
            "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
            runtime.state.global_clk,
            proving_time,
            (runtime.state.global_clk as f64 / proving_time as f64),
            bincode::serialize(&shard_proofs).unwrap().len(),
        ); */

        Ok(shard_proofs)
    }
}
