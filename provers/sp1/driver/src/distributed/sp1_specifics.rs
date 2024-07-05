use std::{
    fs::File,
    io::{Seek, Write},
    time::Instant,
};

use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger};

use raiko_lib::prover::WorkerError;
use sp1_core::{
    runtime::{ExecutionState, Program, Runtime, ShardingConfig},
    stark::{LocalProver, MachineRecord, RiscvAir, ShardProof, StarkGenericConfig, StarkMachine},
    utils::{
        baby_bear_poseidon2::{Perm, Val},
        BabyBearPoseidon2, SP1CoreOpts, SP1CoreProverError,
    },
};

pub use sp1_core::air::PublicValues;
pub use sp1_core::runtime::ExecutionRecord;

use sp1_sdk::CoreSC;
use sp1_sdk::{SP1PublicValues, SP1Stdin};

use crate::ELF;

use super::{Challenger, Checkpoint, Commitments, PartialProof};

fn trace_checkpoint(
    program: Program,
    checkpoint: Checkpoint,
    opts: SP1CoreOpts,
) -> ExecutionRecord {
    let mut runtime = Runtime::recover(program, checkpoint, opts);

    let (events, _) =
        tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());

    events
}

pub fn compute_checkpoints(
    stdin: &SP1Stdin,
    nb_workers: usize,
) -> Result<(Vec<ExecutionState>, Vec<u8>, PublicValues<u32, u32>, usize), SP1CoreProverError> {
    let config = CoreSC::default();
    let mut opts = SP1CoreOpts::default();

    // FIXME: Is this the most efficient ?
    opts.shard_batch_size = 1;

    let program = Program::from(ELF);

    // Execute the program.
    let mut runtime = Runtime::new(program.clone(), opts);
    runtime.write_vecs(&stdin.buffer);

    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }

    let checkpoints_start = Instant::now();

    let mut checkpoints_states = Vec::new();

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let (public_values_stream, public_values) = loop {
        let checkpoint_start = Instant::now();

        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        log::debug!("Checkpoint took {:?}", checkpoint_start.elapsed());

        checkpoints_states.push(checkpoint);

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                std::mem::take(&mut runtime.state.public_values_stream),
                runtime.record.public_values,
            );
        }
    };

    log::debug!("Total checkpointing took {:?}", checkpoints_start.elapsed());

    opts.shard_batch_size = (checkpoints_states.len() as f64 / nb_workers as f64).ceil() as usize;

    let checkpoints_states = checkpoints_states
        .chunks(opts.shard_batch_size)
        .map(|chunk| chunk[0].clone())
        .collect::<Vec<_>>();

    Ok((
        checkpoints_states,
        public_values_stream,
        public_values,
        opts.shard_batch_size,
    ))
}

pub fn commit(
    checkpoint: Checkpoint,
    public_values: PublicValues<u32, u32>,
    shard_batch_size: usize,
) -> Result<(Vec<ExecutionRecord>, Commitments), WorkerError> {
    let config = CoreSC::default();
    let sharding_config = ShardingConfig::default();
    let mut opts = SP1CoreOpts::default();

    opts.shard_batch_size = shard_batch_size;

    let program = Program::from(ELF);

    let mut record = trace_checkpoint(program.clone(), checkpoint, opts);
    record.public_values = public_values;

    let machine = RiscvAir::machine(config.clone());
    let (_pk, vk) = machine.setup(&program);

    let checkpoint_shards =
        tracing::info_span!("shard").in_scope(|| machine.shard(record, &sharding_config));
    //
    // Commit to each shard.
    let (commitments, _commit_data) = tracing::info_span!("commit")
        .in_scope(|| LocalProver::commit_shards(&machine, &checkpoint_shards, opts));

    Ok((checkpoint_shards, commitments))
}

pub fn prove(
    shards: Vec<ExecutionRecord>,
    public_values: PublicValues<u32, u32>,
    mut challenger: Challenger,
) -> Result<PartialProof, WorkerError> {
    let config = CoreSC::default();

    let program = Program::from(ELF);

    let machine = RiscvAir::machine(config.clone());
    let (pk, _vk) = machine.setup(&program);

    let nb_shards = shards.len();

    let mut proofs = shards
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
                &mut challenger.clone(),
            );

            log::debug!("Prove shard took {:?}", prove_shard_start.elapsed());

            proof
        })
        .collect::<Vec<_>>();

    Ok(proofs)
}

pub fn observe_commitments(
    commitments: Commitments,
    public_values: PublicValues<u32, u32>,
) -> Challenger {
    let public_values: Vec<Val> = public_values.to_vec();

    let config = CoreSC::default();

    let program = Program::from(ELF);

    // Setup the machine.
    let machine = RiscvAir::machine(config.clone());
    let (_pk, vk) = machine.setup(&program);

    let mut challenger = config.challenger();

    vk.observe_into(&mut challenger);

    for commitment in commitments {
        challenger.observe(commitment);
        challenger.observe_slice(&public_values[0..machine.num_pv_elts()]);
    }

    challenger
}
