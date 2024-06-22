mod worker_client;

use p3_challenger::DuplexChallenger;
use sp1_core::{
    air::PublicValues,
    runtime::ExecutionState,
    stark::ShardProof,
    utils::{
        baby_bear_poseidon2::{Perm, Val},
        BabyBearPoseidon2,
    },
};
use worker_client::WorkerClient;

pub async fn distribute_work(
    ip_list: Vec<String>,
    checkpoints: Vec<ExecutionState>,
    public_values: PublicValues<u32, u32>,
    challenger: DuplexChallenger<Val, Perm, 16, 8>,
    shard_batch_size: usize,
) -> Vec<ShardProof<BabyBearPoseidon2>> {
    let (queue_tx, queue_rx) = async_channel::unbounded();
    let (answer_tx, answer_rx) = async_channel::unbounded();

    // Spawn the workers
    for (i, url) in ip_list.iter().enumerate() {
        let worker = WorkerClient::new(
            i,
            "http://".to_string() + url + "/proof/partial".into(),
            queue_rx.clone(),
            answer_tx.clone(),
            bincode::serialize(&public_values).unwrap(),
            bincode::serialize(&challenger).unwrap(),
            shard_batch_size,
        );

        tokio::spawn(async move {
            worker.run().await;
        });
    }

    // Send the checkpoints to the workers
    for (i, checkpoint) in checkpoints.iter().enumerate() {
        queue_tx
            .send((i, bincode::serialize(&checkpoint).unwrap()))
            .await
            .unwrap();
    }

    let mut proofs = Vec::new();

    // Get the partial proofs from the workers
    loop {
        let (checkpoint_id, partial_proof_json) = answer_rx.recv().await.unwrap();

        let partial_proof = serde_json::from_str::<Vec<_>>(partial_proof_json.as_str()).unwrap();

        proofs.push((checkpoint_id as usize, partial_proof));

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

    proofs
}
