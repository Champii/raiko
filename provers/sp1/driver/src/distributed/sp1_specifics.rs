use std::fs::File;
use std::io::Seek;
use std::io::Write;
use std::time::Instant;

use p3_challenger::{CanObserve, DuplexChallenger};

use sp1_core::{
    air::PublicValues,
    runtime::{ExecutionRecord, ExecutionState, Program, Runtime, ShardingConfig},
    stark::{LocalProver, MachineRecord, RiscvAir, ShardProof, StarkGenericConfig},
    utils::{
        baby_bear_poseidon2::{Perm, Val},
        BabyBearPoseidon2, SP1CoreOpts, SP1CoreProverError,
    },
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

pub fn prove_partial_old(
    program: Program,
    stdin: &SP1Stdin,
    config: BabyBearPoseidon2,
    mut opts: SP1CoreOpts,
    nb_workers: usize,
) -> Result<
    (
        Vec<ExecutionState>,
        DuplexChallenger<Val, Perm, 16, 8>,
        SP1PublicValues,
        PublicValues<u32, u32>,
        usize,
    ),
    SP1CoreProverError,
> {
    let proving_start = Instant::now();

    let now = Instant::now();

    log::debug!("Starting prover");

    // Execute the program.
    let mut runtime = Runtime::new(program.clone(), opts);
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }

    log::debug!("Runtime setup took {:?}", now.elapsed());

    let now = Instant::now();

    // Setup the machine.
    let machine = RiscvAir::machine(config.clone());
    let (_pk, vk) = machine.setup(runtime.program.as_ref());

    log::debug!("Machine setup took {:?}", now.elapsed());

    let now = Instant::now();

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let mut checkpoints_files = Vec::new();
    let mut checkpoints_states = Vec::new();

    let (public_values_stream, public_values) = loop {
        let checkpoint_start = Instant::now();

        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        checkpoints_states.push(checkpoint.clone());

        log::debug!("Checkpoint took {:?}", checkpoint_start.elapsed());

        let checkpoint_serialize = Instant::now();

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
        checkpoints_files.push(tempfile);

        log::debug!(
            "Checkpoint serialization took {:?}",
            checkpoint_serialize.elapsed()
        );

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                std::mem::take(&mut runtime.state.public_values_stream),
                runtime.record.public_values,
            );
        }
    };
    println!("CHECKPOINTS: {}", checkpoints_files.len());

    log::debug!("Total checkpointing took {:?}", now.elapsed());

    let now = Instant::now();

    // For each checkpoint, generate events, shard them, commit shards, and observe in challenger.
    let sharding_config = ShardingConfig::default();
    // let mut shard_main_datas = Vec::new();
    let mut challenger = machine.config().challenger();
    vk.observe_into(&mut challenger);

    log::debug!("Challenger setup took {:?}", now.elapsed());

    let shard_batch_size = (checkpoints_files.len() as f64 / nb_workers as f64).ceil() as usize;

    let checkpoints_files = checkpoints_files
        .chunks(shard_batch_size)
        .map(|chunk| &chunk[0])
        .collect::<Vec<_>>();

    let checkpoints_states = checkpoints_states
        .chunks(shard_batch_size)
        .map(|chunk| chunk[0].clone())
        .collect::<Vec<_>>();

    let now = Instant::now();

    opts.shard_batch_size = shard_batch_size;

    for checkpoint_file in checkpoints_files.iter() {
        let trace_checkpoint_time = Instant::now();

        let mut record = trace_checkpoint(program.clone(), checkpoint_file, opts);
        record.public_values = public_values;
        // reset_seek(&mut *checkpoint_file);

        log::debug!(
            "Checkpoint trace took {:?}",
            trace_checkpoint_time.elapsed()
        );

        let sharding_time = Instant::now();

        // Shard the record into shards.
        let checkpoint_shards =
            tracing::info_span!("shard").in_scope(|| machine.shard(record, &sharding_config));

        log::debug!("Checkpoint sharding took {:?}", sharding_time.elapsed());

        let commit_time = Instant::now();

        // Commit to each shard.
        let (commitments, _commit_data) = tracing::info_span!("commit")
            .in_scope(|| LocalProver::commit_shards(&machine, &checkpoint_shards, opts));

        log::debug!("Checkpoint commit took {:?}", commit_time.elapsed());

        let observe_time = Instant::now();

        // Observe the commitments.
        for (commitment, shard) in commitments.into_iter().zip(checkpoint_shards.iter()) {
            challenger.observe(commitment);
            challenger.observe_slice(&shard.public_values::<Val>()[0..machine.num_pv_elts()]);
        }

        log::debug!("Checkpoint observe took {:?}", observe_time.elapsed());
    }

    log::debug!("Checkpoints commitment took {:?}", now.elapsed());

    log::debug!("Total setup took {:?}", proving_start.elapsed());

    Ok((
        checkpoints_states,
        challenger,
        SP1PublicValues::from(&public_values_stream),
        public_values,
        shard_batch_size,
    ))
}

pub fn short_circuit_proof(
    program: Program,
    config: BabyBearPoseidon2,
    opts: SP1CoreOpts,
    checkpoint: ExecutionState,
    challenger: DuplexChallenger<Val, Perm, 16, 8>,
    public_values: sp1_core::air::PublicValues<u32, u32>,
) -> Vec<ShardProof<BabyBearPoseidon2>> {
    let now = Instant::now();

    let machine = RiscvAir::machine(config.clone());
    let (pk, _vk) = machine.setup(&program);
    let sharding_config = ShardingConfig::default();

    log::debug!("Machine setup took {:?}", now.elapsed());

    log::info!("Starting proof shard");
    let mut res = vec![];

    let now = Instant::now();

    let proving_time = Instant::now();

    let mut events = {
        let mut runtime = Runtime::recover(program.clone(), checkpoint, opts);
        let (events, _) =
            tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());
        events
    };

    log::debug!("Runtime recover took {:?}", now.elapsed());

    let now = Instant::now();

    events.public_values = public_values;
    let checkpoint_shards =
        tracing::info_span!("shard").in_scope(|| machine.shard(events, &sharding_config));

    log::debug!("Checkpoint sharding took {:?}", now.elapsed());

    let mut proofs = checkpoint_shards
        .into_iter()
        .map(|shard| {
            let config = machine.config();
            log::info!("Commit main");

            let now = Instant::now();
            let shard_data =
                LocalProver::commit_main(config, &machine, &shard, shard.index() as usize);

            log::debug!("Commit main took {:?}", now.elapsed());

            let now = Instant::now();

            let chip_ordering = shard_data.chip_ordering.clone();
            let ordered_chips = machine
                .shard_chips_ordered(&chip_ordering)
                .collect::<Vec<_>>()
                .to_vec();

            log::debug!("Shard chips ordering took {:?}", now.elapsed());

            let now = Instant::now();

            log::info!("Actually prove shard");
            let proof = LocalProver::prove_shard(
                config,
                &pk,
                &ordered_chips,
                shard_data,
                &mut challenger.clone(),
            );

            log::debug!("Prove shard took {:?}", now.elapsed());

            proof
        })
        .collect::<Vec<_>>();

    res.append(&mut proofs);

    log::debug!("Proving took {:?}", proving_time.elapsed());

    return res;
}
