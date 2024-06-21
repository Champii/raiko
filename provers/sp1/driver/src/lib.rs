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
    use sp1_core::air::MachineAir;
    /* use serde_remote::as_u8_eq;
    use serde_remote::cast_from_u8;
    use serde_remote::cast_to_u8;
    use serde_remote::deserialize_duplex_challenger;
    use serde_remote::serialize_duplex_challenger; */
    use sp1_core::air::PublicValues;
    use sp1_core::runtime::ExecutionRecord;
    use sp1_core::runtime::ExecutionState;
    use sp1_core::stark::StarkMachine;
    use sp1_core::stark::StarkProvingKey;
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
    use sp1_sdk::CoreSC;
    use sp1_sdk::{SP1PublicValues, SP1Stdin};

    use crate::ELF;

    /* mod serde_remote {
        use std::io::Read;

        use super::{Perm, Val};
        use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
        use p3_challenger::DuplexChallenger;
        use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
        use p3_symmetric::{CryptographicPermutation, Hash};
        use serde::{ser::SerializeTuple, Serializer};
        pub use serde::{Deserialize, Serialize};

        #[derive(Copy, Debug, Clone, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
        #[repr(transparent)]
        pub struct BabyBearRemote {
            pub value: u32,
        }

        /* fn babybear_to_babybearremote(babybear: BabyBear) -> BabyBearRemote {
            unsafe { std::mem::transmute(babybear) }
        }

        fn babybearremote_to_babybear(babybear_remote: BabyBearRemote) -> BabyBear {
            unsafe { std::mem::transmute(babybear_remote) }
        } */

        #[derive(Default, Clone, Debug, Serialize, Deserialize)]
        pub struct Poseidon2ExternalMatrixGeneralRemote;

        #[derive(Debug, Clone, Default, Serialize, Deserialize)]
        pub struct DiffusionMatrixBabyBearRemote;

        #[derive(Clone, Debug, Serialize, Deserialize)]
        pub struct Poseidon2Remote {
            pub rounds_f: usize,
            pub external_constants: Vec<[BabyBearRemote; 16]>,
            pub external_linear_layer: Poseidon2ExternalMatrixGeneralRemote,
            pub rounds_p: usize,
            pub internal_constants: Vec<BabyBearRemote>,
            pub internal_linear_layer: DiffusionMatrixBabyBearRemote,
        }

        /* fn poseidon2_to_poseidon2remote(
            poseidon2: Poseidon2<
                BabyBear,
                Poseidon2ExternalMatrixGeneral,
                DiffusionMatrixBabyBear,
                16,
                7,
            >,
        ) -> Poseidon2Remote {
            unsafe { std::mem::transmute(poseidon2) }
        }

        fn poseidon2remote_to_poseidon2(
            poseidon2_remote: Poseidon2Remote,
        ) -> Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>
        {
            unsafe { std::mem::transmute(poseidon2_remote) }
        } */

        #[derive(Clone, Debug, Serialize, Deserialize)]
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
            unsafe { std::mem::transmute_copy(&duplex_challenger) }
        }

        fn duplexchallengerremote_to_duplexchallenger(
            duplex_challenger_remote: DuplexChallengerRemote,
        ) -> DuplexChallenger<
            BabyBear,
            Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
            16,
            8,
        > {
            unsafe { std::mem::transmute_copy(&duplex_challenger_remote) }
        }

        /* unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
            println!("SIZEOF: {}", ::core::mem::size_of::<T>());

            let slice = ::core::slice::from_raw_parts(
                (p as *const T) as *const u8,
                ::core::mem::size_of::<T>(),
            );
            /* assert_eq!(slice.len(), ::core::mem::size_of::<T>());

            let slice2 = (*(p as *const T as *const &[u8])).to_vec();
            assert_eq!(slice, slice2.as_slice()); */
            slice
        }



        unsafe fn u8_slice_as_any<T: Sized + Clone>(slice: &[u8]) -> T {
            /* assert_eq!(slice.len(), ::core::mem::size_of::<T>());
            unsafe { &*(slice.as_ptr() as *const T) }.clone() */
            /* let (head, body, tail) = slice.align_to::<T>();
            body[0].clone() */
            // unsafe { std::ptr::read(slice.as_ptr() as *const T) }
            unsafe { std::mem::transmute(slice) }
            // unsafe { std::mem::transmute(slice) }
            // (*(slice.as_ptr() as *const T)).clone()
            /* let num_bytes = ::std::mem::size_of::<T>();
            let mut s = ::std::mem::uninitialized();
            let buffer = std::slice::from_raw_parts_mut(&mut s as *mut T as *mut u8, num_bytes);
            let mut data = slice.to_vec();
            let mut slice = data.as_slice();
            match slice.read_exact(buffer) {
                Ok(()) => s,
                Err(e) => {
                    ::std::mem::forget(s);
                    panic!("Failed to read_exact: {}", e);
                }
            } */
        } */

        pub unsafe fn as_u8_eq<T: Sized>(a: &T, b: &T) -> bool {
            let a_slice = ::core::slice::from_raw_parts(
                (a as *const T) as *const u8,
                ::core::mem::size_of::<T>(),
            );
            let b_slice = ::core::slice::from_raw_parts(
                (b as *const T) as *const u8,
                ::core::mem::size_of::<T>(),
            );
            assert_eq!(a_slice.len(), b_slice.len());
            a_slice == b_slice
        }

        pub fn serialize_duplex_challenger(
            duplex_challenger: &DuplexChallenger<Val, Perm, 16, 8>,
        ) -> Vec<u8> {
            // println!("CHALLENGER {:#?}", duplex_challenger);
            /* let orig = unsafe { any_as_u8_slice(duplex_challenger) };
            let new = unsafe { u8_slice_as_any::<DuplexChallenger<Val, Perm, 16, 8>>(orig) }; */
            /* println!("EQUAL: \n{:?}\n{:?}", orig, unsafe {
                any_as_u8_slice(&new)
            }); */
            // assert_eq!(orig, unsafe { any_as_u8_slice(&new) });

            let transmuted = duplexchallenge_to_duplexchallengerremote(duplex_challenger.clone());
            // let new = unsafe { any_as_u8_slice(&transmuted) };
            /* println!("ORIG: {:#?}", orig);
            println!("NEW: {:#?}", new); */
            bincode::serialize(&transmuted).unwrap()
            // orig.to_vec()
        }

        pub fn deserialize_duplex_challenger(
            serialized: Vec<u8>,
        ) -> DuplexChallenger<Val, Perm, 16, 8> {
            let transmuted: DuplexChallengerRemote = bincode::deserialize(&serialized).unwrap();
            duplexchallengerremote_to_duplexchallenger(transmuted)
            // unsafe { u8_slice_as_any(&serialized) }
        }

        pub unsafe fn cast_to_u8<T: Clone>(t: &T) -> &[u8] {
            let ptr: *const T = t;
            let ptr: *const u8 = ptr as *const u8;
            let len = std::mem::size_of::<T>();
            std::slice::from_raw_parts(ptr, len)
        }

        pub unsafe fn cast_from_u8<T: Clone>(bytes: &[u8]) -> T {
            /* // assert correct endianness somehow
            assert_eq!(bytes.len(), std::mem::size_of::<T>());
            let ptr: *const u8 = bytes.as_ptr();
            assert_eq!(ptr.align_offset(std::mem::align_of::<T>()), 0); */

            // ptr.cast::<T>().as_ref().unwrap().clone()
            std::ptr::read_unaligned(bytes.as_ptr().cast())
        }
    } */

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

    /* pub fn nb_checkpoints(
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
    } */

    pub fn compute_trace_and_challenger(
        program: Program,
        stdin: &SP1Stdin,
        config: BabyBearPoseidon2,
        opts: SP1CoreOpts,
    ) -> Result<
        (
            Vec<ExecutionState>,
            Vec<u8>,
            Vec<u8>,
            SP1PublicValues,
            PublicValues<u32, u32>,
            StarkMachine<CoreSC, RiscvAir<BabyBear>>,
            <BabyBearPoseidon2 as StarkGenericConfig>::Challenger,
            StarkProvingKey<BabyBearPoseidon2>,
        ),
        SP1CoreProverError,
    > {
        let proving_start = Instant::now();

        // Execute the program.
        let mut runtime = Runtime::new(program.clone(), opts);
        runtime.write_vecs(&stdin.buffer);
        for proof in stdin.proofs.iter() {
            runtime.write_proof(proof.0.clone(), proof.1.clone());
        }

        // Setup the machine.
        let machine = RiscvAir::machine(config);

        let machine_config = machine.config();

        let (pk, vk) = machine.setup(runtime.program.as_ref());

        let sharding_config = ShardingConfig::default();
        let machine_config = machine.config();
        let mut checkpoints = Vec::new();
        let mut challenger = machine_config.challenger();
        vk.observe_into(&mut challenger);
        let mut records = Vec::new();
        let (public_values_stream, public_values) = loop {
            let state = runtime.state.clone();

            // Execute the runtime until we reach a checkpoint.

            let (record, done) = runtime
                .execute_record()
                .map_err(SP1CoreProverError::ExecutionError)?;

            println!("Checkpoint: {:?}", record.public_values);

            checkpoints.push(state);
            records.push(record);

            // If we've reached the final checkpoint, break out of the loop.
            if done {
                break (
                    std::mem::take(&mut runtime.state.public_values_stream),
                    runtime.record.public_values,
                );
            }
        };

        for mut record in records {
            record.public_values = public_values;
            let checkpoint_shards =
                tracing::info_span!("shard").in_scope(|| machine.shard(record, &sharding_config));

            // Commit to each shard.
            let (commitments, commit_data) = tracing::info_span!("commit")
                .in_scope(|| LocalProver::commit_shards(&machine, &checkpoint_shards, opts));

            // Observe the commitments.
            for (commitment, shard) in commitments.into_iter().zip(checkpoint_shards.iter()) {
                challenger.observe(commitment);
                challenger.observe_slice(&shard.public_values::<Val>()[0..machine.num_pv_elts()]);
            }
        }

        let serialized_challenger = bincode::serialize(&challenger).unwrap();
        let deserialized_challenger: <BabyBearPoseidon2 as StarkGenericConfig>::Challenger =
            bincode::deserialize(&serialized_challenger).unwrap();

        let serialized_pk = bincode::serialize(&pk).unwrap();

        // assert_eq!(format!("{:?}", challenger), format!("{:?}", deserialized_challenger)

        println!("CHALLENGER SIZE: {}", serialized_challenger.len());

        let public_values_stream = SP1PublicValues::from(&public_values_stream);
        Ok((
            checkpoints,
            serialized_challenger,
            serialized_pk,
            public_values_stream,
            public_values,
            machine,
            challenger,
            pk,
        ))
    }

    pub fn prove_partial(
        program: Program,
        // stdin: &SP1Stdin,
        config: BabyBearPoseidon2,
        opts: SP1CoreOpts,
        checkpoint: ExecutionState,
        serialized_challenger: Vec<u8>,
        serialized_pk: Vec<u8>,
        checkpoint_id: usize,
        public_values: sp1_core::air::PublicValues<u32, u32>,
    ) -> Result<Vec<ShardProof<BabyBearPoseidon2>>, SP1CoreProverError> {
        let proving_start = Instant::now();

        // Setup the machine.
        let machine = RiscvAir::machine(config);
        // let (pk, vk) = machine.setup(&program);

        let pk = bincode::deserialize(&serialized_pk).unwrap();

        // For each checkpoint, generate events and shard again, then prove the shards.
        let mut shard_proofs = Vec::<ShardProof<BabyBearPoseidon2>>::new();

        let mut challenger: <BabyBearPoseidon2 as StarkGenericConfig>::Challenger =
            bincode::deserialize(&serialized_challenger).unwrap();

        let mut events = {
            let mut runtime = Runtime::recover(program.clone(), checkpoint, opts);
            let (events, _) = tracing::debug_span!("runtime.trace")
                .in_scope(|| runtime.execute_record().unwrap());
            events
        };

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

        let proving_time = proving_start.elapsed().as_secs_f64();

        tracing::info!(
            "Proving checkpoint {} took {}s",
            checkpoint_id,
            proving_time
        );

        Ok(shard_proofs)
    }
    pub fn prove_partial_local(
        program: Program,
        stdin: &SP1Stdin,
        config: BabyBearPoseidon2,
        opts: SP1CoreOpts,
        checkpoint: ExecutionState,
        mut challenger: <BabyBearPoseidon2 as StarkGenericConfig>::Challenger,
        checkpoint_id: usize,
        public_values: sp1_core::air::PublicValues<u32, u32>,
    ) -> Result<Vec<ShardProof<BabyBearPoseidon2>>, SP1CoreProverError> {
        let proving_start = Instant::now();

        // Setup the machine.
        let machine = RiscvAir::machine(config);
        let (pk, vk) = machine.setup(&program);

        // For each checkpoint, generate events and shard again, then prove the shards.
        let mut shard_proofs = Vec::<ShardProof<BabyBearPoseidon2>>::new();

        /* let mut challenger: <BabyBearPoseidon2 as StarkGenericConfig>::Challenger =
        bincode::deserialize(&serialized_challenger).unwrap(); */

        let mut events = {
            let mut runtime = Runtime::recover(program.clone(), checkpoint, opts);
            let (events, _) = tracing::debug_span!("runtime.trace")
                .in_scope(|| runtime.execute_record().unwrap());
            events
        };

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

        let proving_time = proving_start.elapsed().as_secs_f64();

        tracing::info!(
            "Proving checkpoint {} took {}s",
            checkpoint_id,
            proving_time
        );

        Ok(shard_proofs)
    }

    pub fn prove_partial_old<SC: StarkGenericConfig + Send + Sync>(
        program: Program,
        stdin: &SP1Stdin,
        config: SC,
        opts: SP1CoreOpts,
        // checkpoint_id: usize,
    ) -> Result<(Vec<ShardProof<SC>>, SP1PublicValues), SP1CoreProverError>
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
        let machine = RiscvAir::machine(config.clone());
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
        let mut checkpoints_states = Vec::new();
        let (public_values_stream, public_values) = loop {
            // Execute the runtime until we reach a checkpoint.
            let (checkpoint, done) = runtime
                .execute_state()
                .map_err(SP1CoreProverError::ExecutionError)?;
            checkpoints_states.push(checkpoint.clone());

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

        /* log::info!("Starting proof shard");
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

        shard_proofs.append(&mut checkpoint_proofs); */

        let shard_proofs = short_circuit_proof(
            program,
            stdin,
            config,
            opts,
            checkpoints_states,
            challenger,
            pk,
            public_values,
            // &machine,
        );

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

        Ok((shard_proofs, SP1PublicValues::from(&public_values_stream)))
    }

    pub fn short_circuit_proof<SC: StarkGenericConfig + Sync + Send>(
        program: Program,
        stdin: &SP1Stdin,
        config: SC,
        opts: SP1CoreOpts,
        checkpoint_shards_vec: Vec<ExecutionState>,
        mut challenger: <SC as StarkGenericConfig>::Challenger,
        pk: sp1_core::stark::StarkProvingKey<SC>,
        public_values: sp1_core::air::PublicValues<u32, u32>,
        // machine: &StarkMachine<SC, A>,
    ) -> Vec<ShardProof<SC>>
    where
        /* SC: StarkGenericConfig,
        SC::Challenger: Clone,
        A: MachineAir<SC::Val>,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        <SC as StarkGenericConfig>::Val: PrimeField32, */
        // A: MachineAir<SC::Val> + for<'a> air::Air<sp1_core::stark::ProverConstraintFolder<'a, SC>>,
        SC::Challenger: Clone,
        OpeningProof<SC>: Send + Sync,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        <SC as StarkGenericConfig>::Val: PrimeField32,
    {
        let machine = RiscvAir::machine(config.clone());
        let sharding_config = ShardingConfig::default();
        log::info!("Starting proof shard");
        let mut res = vec![];
        let mut checkpoint_proofs = checkpoint_shards_vec.into_iter().for_each(|checkpoint| {
            let mut events = {
                let mut runtime = Runtime::recover(program.clone(), checkpoint, opts);
                let (events, _) = tracing::debug_span!("runtime.trace")
                    .in_scope(|| runtime.execute_record().unwrap());
                events
            };

            events.public_values = public_values;
            let checkpoint_shards =
                tracing::info_span!("shard").in_scope(|| machine.shard(events, &sharding_config));

            let mut proofs = checkpoint_shards
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
            res.append(&mut proofs);
        });
        return res;
    }
}
