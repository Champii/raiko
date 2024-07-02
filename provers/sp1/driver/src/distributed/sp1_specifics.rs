use std::{
    fs::File,
    io::{Seek, Write},
    time::Instant,
};

use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger};

use sp1_core::{
    air::PublicValues,
    runtime::{ExecutionRecord, ExecutionState, Program, Runtime, ShardingConfig},
    stark::{LocalProver, MachineRecord, RiscvAir, ShardProof, StarkGenericConfig, StarkMachine},
    utils::{
        baby_bear_poseidon2::{Perm, Val},
        BabyBearPoseidon2, SP1CoreOpts, SP1CoreProverError,
    },
};
use sp1_sdk::CoreSC;
use sp1_sdk::{SP1PublicValues, SP1Stdin};

use crate::ELF;

use super::partial_proof_request::PartialProofRequest;

fn trace_checkpoint(
    program: Program,
    file: &File,
    opts: SP1CoreOpts,
) -> (ExecutionState, ExecutionRecord) {
    let mut reader = std::io::BufReader::new(file);

    let state: ExecutionState =
        bincode::deserialize_from(&mut reader).expect("failed to deserialize state");

    let mut runtime = Runtime::recover(program.clone(), state.clone(), opts);

    let (events, _) =
        tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());

    (state, events)
}

fn compute_checkpoints(
    runtime: &mut Runtime,
) -> Result<(Vec<File>, Vec<u8>, PublicValues<u32, u32>), SP1CoreProverError> {
    let checkpoints_start = Instant::now();

    let mut checkpoints_files = Vec::new();

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let (public_values_stream, public_values) = loop {
        let checkpoint_start = Instant::now();

        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        log::debug!("Checkpoint took {:?}", checkpoint_start.elapsed());

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

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                std::mem::take(&mut runtime.state.public_values_stream),
                runtime.record.public_values,
            );
        }
    };

    log::debug!("Total checkpointing took {:?}", checkpoints_start.elapsed());

    Ok((checkpoints_files, public_values_stream, public_values))
}

fn commit_checkpoints(
    checkpoints_files: Vec<File>,
    program: Program,
    opts: SP1CoreOpts,
    public_values: PublicValues<u32, u32>,
    machine: &StarkMachine<CoreSC, RiscvAir<BabyBear>>,
    challenger: &mut DuplexChallenger<Val, Perm, 16, 8>,
) -> Vec<ExecutionState> {
    let now = Instant::now();

    let sharding_config = ShardingConfig::default();
    let mut checkpoints_states = Vec::new();

    // Only keep the first checkpoint file of each batch.
    let checkpoints_files = checkpoints_files
        .chunks(opts.shard_batch_size)
        .map(|chunk| &chunk[0])
        .collect::<Vec<_>>();

    let nb_checkpoints = checkpoints_files.len();

    // For each checkpoint, generate events, shard them, commit shards, and observe in challenger.
    for (i, checkpoint_file) in checkpoints_files.into_iter().enumerate() {
        log::info!("Committing checkpoint {}/{}", i + 1, nb_checkpoints);

        let trace_checkpoint_time = Instant::now();

        let (state, mut record) = trace_checkpoint(program.clone(), checkpoint_file, opts);
        record.public_values = public_values;

        checkpoints_states.push(state);

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

        // Observe the commitments.
        for (commitment, shard) in commitments.into_iter().zip(checkpoint_shards.iter()) {
            challenger.observe(commitment);
            challenger.observe_slice(&shard.public_values::<Val>()[0..machine.num_pv_elts()]);
        }
    }

    log::debug!("Checkpoints commitment took {:?}", now.elapsed());

    checkpoints_states
}

// Meant to be run by the orchestrator to commit the program and generate the partial proof
// request.
pub fn commit(
    program: Program,
    stdin: &SP1Stdin,
    nb_workers: usize,
) -> Result<(Vec<ExecutionState>, SP1PublicValues, PartialProofRequest), SP1CoreProverError> {
    let proving_start = Instant::now();
    let runtime_setup_start = Instant::now();

    log::debug!("Starting commit");

    let config = CoreSC::default();
    let mut opts = SP1CoreOpts::default();

    // FIXME: Is this the most efficient ?
    opts.shard_batch_size = 1;

    // Execute the program.
    let mut runtime = Runtime::new(program.clone(), opts);
    runtime.write_vecs(&stdin.buffer);

    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }

    log::debug!("Runtime setup took {:?}", runtime_setup_start.elapsed());

    let machine_setup_start = Instant::now();

    // Setup the machine.
    let machine = RiscvAir::machine(config.clone());
    let (_pk, vk) = machine.setup(runtime.program.as_ref());

    log::debug!("Machine setup took {:?}", machine_setup_start.elapsed());

    let (checkpoints_files, public_values_stream, public_values) =
        compute_checkpoints(&mut runtime)?;

    let mut challenger = machine.config().challenger();
    vk.observe_into(&mut challenger);

    opts.shard_batch_size = (checkpoints_files.len() as f64 / nb_workers as f64).ceil() as usize;

    let checkpoints_states = commit_checkpoints(
        checkpoints_files,
        program,
        opts,
        public_values,
        &machine,
        &mut challenger,
    );

    log::debug!("Total setup took {:?}", proving_start.elapsed());

    let partial_proof_request = PartialProofRequest {
        checkpoint_id: 0,
        checkpoint_data: ExecutionState::default(),
        challenger,
        public_values,
        shard_batch_size: opts.shard_batch_size,
    };

    Ok((
        checkpoints_states,
        SP1PublicValues::from(&public_values_stream),
        partial_proof_request,
    ))
}

// Meant to be run by the worker to generate the partial proof.
pub fn prove_partial(request_data: &PartialProofRequest) -> Vec<ShardProof<BabyBearPoseidon2>> {
    let prove_partial_start = Instant::now();

    let program = Program::from(ELF);
    let config = CoreSC::default();
    let mut opts = SP1CoreOpts::default();

    opts.shard_batch_size = request_data.shard_batch_size;

    let machine = RiscvAir::machine(config.clone());
    let (pk, _vk) = machine.setup(&program);

    let sharding_config = ShardingConfig::default();
    let runtime_recover_start = Instant::now();
    let mut shard_proofs = vec![];

    let events = {
        let mut runtime =
            Runtime::recover(program.clone(), request_data.checkpoint_data.clone(), opts);

        let (mut events, _) =
            tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());

        events.public_values = request_data.public_values;

        events
    };

    log::debug!("Runtime recover took {:?}", runtime_recover_start.elapsed());

    let now = Instant::now();

    let checkpoint_shards =
        tracing::info_span!("shard").in_scope(|| machine.shard(events, &sharding_config));

    log::debug!("Checkpoint sharding took {:?}", now.elapsed());

    let nb_shards = checkpoint_shards.len();

    let mut proofs = checkpoint_shards
        .into_iter()
        .enumerate()
        .map(|(i, shard)| {
            log::info!("Proving shard {}/{}", i + 1, nb_shards);

            let config = machine.config();

            let commit_main_start = Instant::now();

            let shard_data =
                LocalProver::commit_main(config, &machine, &shard, shard.index() as usize);

            log::debug!("Commit main took {:?}", commit_main_start.elapsed());

            let chip_ordering = shard_data.chip_ordering.clone();
            let ordered_chips = machine
                .shard_chips_ordered(&chip_ordering)
                .collect::<Vec<_>>()
                .to_vec();

            let prove_shard_start = Instant::now();

            let proof = LocalProver::prove_shard(
                config,
                &pk,
                &ordered_chips,
                shard_data,
                &mut request_data.challenger.clone(),
            );

            log::debug!("Prove shard took {:?}", prove_shard_start.elapsed());

            proof
        })
        .collect::<Vec<_>>();

    shard_proofs.append(&mut proofs);

    log::info!("Proving shards took {:?}", prove_partial_start.elapsed());

    return shard_proofs;
}
