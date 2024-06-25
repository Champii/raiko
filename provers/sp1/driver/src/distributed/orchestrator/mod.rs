mod worker_client;

use sp1_core::{runtime::ExecutionState, stark::ShardProof, utils::BabyBearPoseidon2};
use worker_client::WorkerClient;

use super::partial_proof_request::PartialProofRequestData;

pub async fn distribute_work(
    ip_list: Vec<String>,
    checkpoints: Vec<ExecutionState>,
    partial_proof_request: PartialProofRequestData,
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
            partial_proof_request.clone(),
        );

        tokio::spawn(async move {
            worker.run().await;
        });
    }

    let nb_checkpoints = checkpoints.len();

    // Send the checkpoints to the workers
    for (i, checkpoint) in checkpoints.into_iter().enumerate() {
        queue_tx.send((i, checkpoint)).await.unwrap();
    }

    let mut proofs = Vec::new();

    // Get the partial proofs from the workers
    loop {
        let (checkpoint_id, partial_proof) = answer_rx.recv().await.unwrap();

        // let partial_proof = serde_json::from_str::<Vec<_>>(partial_proof_json.as_str()).unwrap();

        proofs.push((checkpoint_id as usize, partial_proof));

        if proofs.len() == nb_checkpoints {
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
