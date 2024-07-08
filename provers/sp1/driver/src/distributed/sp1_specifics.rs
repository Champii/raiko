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
pub type Shards = Vec<Shard>;
pub type Commitments = Vec<Hash<Val, Val, 8>>;
pub type PartialProof = Vec<ShardProof<BabyBearPoseidon2>>;
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

fn trace_checkpoint(program: Program, checkpoint: Checkpoint, opts: SP1CoreOpts) -> Shard {
    let mut runtime = Runtime::recover(program, checkpoint, opts);

    let (events, _) =
        tracing::debug_span!("runtime.trace").in_scope(|| runtime.execute_record().unwrap());

    events
}

pub fn compute_checkpoints(
    stdin: &SP1Stdin,
    nb_workers: usize,
) -> Result<(Vec<Checkpoint>, Vec<u8>, PublicValues<u32, u32>, usize), SP1CoreProverError> {
    log::info!("Computing checkpoints");
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
) -> Result<(Shards, Commitments), WorkerError> {
    log::info!("Commiting checkpoint");

    let config = CoreSC::default();
    let sharding_config = ShardingConfig::default();
    let mut opts = SP1CoreOpts::default();

    opts.shard_batch_size = shard_batch_size;

    let program = Program::from(ELF);

    let mut record = trace_checkpoint(program.clone(), checkpoint, opts);
    record.public_values = public_values;

    let machine = RiscvAir::machine(config.clone());

    let checkpoint_shards =
        tracing::info_span!("shard").in_scope(|| machine.shard(record, &sharding_config));

    // Commit to each shard.
    let (commitments, _commit_data) = tracing::info_span!("commit")
        .in_scope(|| LocalProver::commit_shards(&machine, &checkpoint_shards, opts));

    Ok((checkpoint_shards, commitments))
}

pub fn prove(shards: Shards, challenger: Challenger) -> Result<PartialProof, WorkerError> {
    log::info!("Proving shards");

    let config = CoreSC::default();

    let program = Program::from(ELF);

    let machine = RiscvAir::machine(config.clone());
    let (pk, _vk) = machine.setup(&program);

    let nb_shards = shards.len();

    let proofs = shards
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
    log::info!("Observing commitments");

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
