use std::time::Instant;

use p3_challenger::{CanObserve, DuplexChallenger};
use p3_symmetric::Hash;

use raiko_lib::prover::WorkerError;
pub use sp1_core::air::PublicValues;
use sp1_core::{
    runtime::{ExecutionRecord, ExecutionState, Program, Runtime, ShardingConfig},
    stark::{LocalProver, MachineRecord, RiscvAir, ShardProof, StarkGenericConfig},
    utils::{
        baby_bear_poseidon2::{Perm, Val},
        BabyBearPoseidon2, SP1CoreOpts, SP1CoreProverError,
    },
};

use sp1_sdk::{CoreSC, SP1Stdin};

use crate::ELF;

pub type Checkpoint = ExecutionState;
pub type Shard = ExecutionRecord;
pub type ShardsPublicValues = Vec<Val>;
pub type Commitments = Vec<Hash<Val, Val, 8>>;
pub type PartialProofs = Vec<ShardProof<BabyBearPoseidon2>>;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

fn trace_checkpoint(
    program: Program,
    checkpoint: Checkpoint,
    opts: SP1CoreOpts,
) -> (Shard, Checkpoint) {
    let mut runtime = Runtime::recover(program, checkpoint, opts);

    let (events, _) =
        tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());

    let state = runtime.state.clone();

    (events, state)
}

// This is the entry point of the orchestrator
// It computes the checkpoints to be sent to the workers
pub fn compute_checkpoints(
    stdin: &SP1Stdin,
    nb_workers: usize,
) -> Result<
    (
        Vec<(Checkpoint, usize)>,
        Vec<u8>,
        PublicValues<u32, u32>,
        SP1CoreOpts,
    ),
    SP1CoreProverError,
> {
    log::info!("Computing checkpoints");
    let opts = SP1CoreOpts::default();

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

    log::info!("Nb checkpoints: {}", checkpoints_states.len());

    let nb_checkpoints_per_workers =
        (checkpoints_states.len() as f64 / nb_workers as f64).ceil() as usize;

    let checkpoints_states = checkpoints_states
        .chunks(nb_checkpoints_per_workers)
        .map(|chunk| (chunk[0].clone(), chunk.len()))
        .collect::<Vec<_>>();

    Ok((
        checkpoints_states,
        public_values_stream,
        public_values,
        opts,
    ))
}

// This is the entry point of the worker
// It commits the checkpoints and returns the commitments and the public values of the shards
pub fn commit(
    mut checkpoint: Checkpoint,
    nb_checkpoints: usize,
    public_values: PublicValues<u32, u32>,
    shard_batch_size: usize,
    shard_size: usize,
) -> Result<(Commitments, Vec<ShardsPublicValues>), WorkerError> {
    let config = CoreSC::default();
    let sharding_config = ShardingConfig::default();

    let mut opts = SP1CoreOpts::default();
    opts.shard_batch_size = shard_batch_size;
    opts.shard_size = shard_size;

    let program = Program::from(ELF);

    let mut commitments_vec = Vec::new();
    let mut shards_public_values_vec = Vec::new();

    let mut processed_checkpoints = 0;

    while processed_checkpoints < nb_checkpoints {
        log::info!(
            "Commiting checkpoint {}/{}",
            processed_checkpoints + 1,
            nb_checkpoints
        );

        let (mut record, new_checkpoint) = trace_checkpoint(program.clone(), checkpoint, opts);
        record.public_values = public_values;

        let machine = RiscvAir::machine(config.clone());

        let checkpoint_shards =
            tracing::info_span!("shard").in_scope(|| machine.shard(record, &sharding_config));

        // Commit to each shard.
        let (commitments, _commit_data) = tracing::info_span!("commit")
            .in_scope(|| LocalProver::commit_shards(&machine, &checkpoint_shards, opts));

        let shards_public_values = checkpoint_shards
            .iter()
            .map(|shard| shard.public_values::<Val>()[0..machine.num_pv_elts()].to_vec())
            .collect::<Vec<_>>();

        commitments_vec.extend(commitments);
        shards_public_values_vec.extend(shards_public_values);

        checkpoint = new_checkpoint;

        processed_checkpoints += 1;
    }

    Ok((commitments_vec, shards_public_values_vec))
}

// When every worker has committed the shards, the orchestrator can observe the commitments
pub fn observe_commitments(
    commitments: Commitments,
    shards_public_values: Vec<ShardsPublicValues>,
) -> Challenger {
    log::info!("Observing commitments");

    let config = CoreSC::default();

    let program = Program::from(ELF);

    // Setup the machine.
    let machine = RiscvAir::machine(config.clone());
    let (_pk, vk) = machine.setup(&program);

    let mut challenger = machine.config().challenger();

    vk.observe_into(&mut challenger);

    for (commitment, shard_public_values) in
        commitments.into_iter().zip(shards_public_values.iter())
    {
        challenger.observe(commitment);
        challenger.observe_slice(&shard_public_values[..]);
    }

    challenger
}

// The workers can now prove the shards thanks to the challenger sent by the orchestrator
pub fn prove(
    mut checkpoint: Checkpoint,
    nb_checkpoints: usize,
    public_values: PublicValues<u32, u32>,
    shard_batch_size: usize,
    shard_size: usize,
    challenger: Challenger,
) -> Result<PartialProofs, WorkerError> {
    let config = CoreSC::default();

    let sharding_config = ShardingConfig::default();

    let mut opts = SP1CoreOpts::default();
    opts.shard_batch_size = shard_batch_size;
    opts.shard_size = shard_size;

    let program = Program::from(ELF);

    let machine = RiscvAir::machine(config.clone());
    let (pk, _vk) = machine.setup(&program);

    let mut processed_checkpoints = 0;

    let mut proofs = Vec::new();

    while processed_checkpoints < nb_checkpoints {
        log::info!(
            "Proving checkpoint {}/{}",
            processed_checkpoints + 1,
            nb_checkpoints
        );

        let (mut record, new_checkpoint) = trace_checkpoint(program.clone(), checkpoint, opts);
        record.public_values = public_values;

        let checkpoint_shards =
            tracing::info_span!("shard").in_scope(|| machine.shard(record, &sharding_config));

        let nb_shards = checkpoint_shards.len();

        let partial_proofs = checkpoint_shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                log::info!("|-> Proving shard {}/{}", i + 1, nb_shards);

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

        proofs.extend(partial_proofs);

        checkpoint = new_checkpoint;
        processed_checkpoints += 1;
    }

    Ok(proofs)
}
