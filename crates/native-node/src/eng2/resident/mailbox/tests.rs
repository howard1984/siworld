use super::*;
use crate::eng2::{
    certificate::{AuthorizationWitness, Certificate, Statement, Vote},
    commitment::{self, Component},
    runtime_export::host::Proposal,
};
fn statement(sequence: u64) -> Statement {
    Statement {
        network: [1; 32],
        checkpoint_height: 72,
        checkpoint_block: [3; 32],
        authorization_height: 96,
        authorization_block: [4; 32],
        roster_sequence: sequence,
        roster_digest: [5; 32],
    }
}
fn vote(sequence: u64) -> Incoming {
    Incoming::Vote {
        statement: statement(sequence),
        vote: Box::new(Vote {
            slot: 0,
            signature: [0; crate::eng2::certificate::SIGNATURE_BYTES],
        }),
    }
}
fn messages() -> Vec<Incoming> {
    // Canonical mailbox fixtures, not valid signatures or admitted checkpoints.
    let witness = AuthorizationWitness {
        descriptors: commitment::COMPONENTS.map(|id| {
            Component::from_local_encoding(id, b"synthetic mailbox fixture", 131072)
                .unwrap()
                .descriptor()
        }),
        governance: b"synthetic public witness".to_vec(),
    };
    vec![
        Incoming::Proposal(Proposal {
            statement: statement(0),
            witness: witness.clone(),
        }),
        vote(0),
        Incoming::Certified {
            certificate: Box::new(Certificate {
                statement: statement(0),
                votes: [
                    Vote {
                        slot: 0,
                        signature: [0; crate::eng2::certificate::SIGNATURE_BYTES],
                    },
                    Vote {
                        slot: 1,
                        signature: [0; crate::eng2::certificate::SIGNATURE_BYTES],
                    },
                ],
            }),
            witness,
        },
    ]
}
fn original(budget: &p2p::Budget, message: &Incoming) -> p2p::Reservation {
    let length = message.encode(131072).unwrap().len();
    budget.reserve(length * 3 + 65536).unwrap()
}
#[test]
fn eight_peers_replaying_three_packets_each_second_do_not_fill_the_inbox() {
    let budget = p2p::Budget::new(8 * 1024 * 1024);
    let before = budget.available().unwrap();
    let mailbox = CheckpointMailbox::new(budget.clone());
    let packets = messages();
    let started = Instant::now();
    for second in 0..120 {
        let now = started + Duration::from_secs(second);
        for _peer in 0..8 {
            for packet in &packets {
                mailbox
                    .enqueue_at(packet.clone(), original(&budget, packet), now)
                    .unwrap();
            }
        }
        assert!(mailbox.incoming.lock().unwrap().queue.len() <= 3);
        let batch = mailbox.drain().unwrap();
        assert_eq!(
            batch.messages.len(),
            if second % RECENT_LIFETIME.as_secs() == 0 {
                3
            } else {
                0
            }
        );
        mailbox.acknowledge_at(&batch, now).unwrap();
        drop(batch);
        assert!(mailbox.incoming.lock().unwrap().queue.is_empty());
        assert!(mailbox.incoming.lock().unwrap().recent.len() <= MAX_RECENT);
    }
    assert!(budget.available().unwrap() < before);
    drop(mailbox);
    assert_eq!(budget.available().unwrap(), before);
}
#[test]
fn reservations_remain_owned_through_consumption_and_success_removes_inflight_replays() {
    let budget = p2p::Budget::new(1024 * 1024);
    let before = budget.available().unwrap();
    let mailbox = CheckpointMailbox::new(budget.clone());
    let message = vote(0);
    let now = Instant::now();
    mailbox
        .enqueue_at(message.clone(), original(&budget, &message), now)
        .unwrap();
    let queued = budget.available().unwrap();
    mailbox
        .enqueue_at(message.clone(), original(&budget, &message), now)
        .unwrap();
    assert_eq!(budget.available().unwrap(), queued);
    let batch = mailbox.drain().unwrap();
    assert_eq!(batch.messages.len(), 1);
    assert_eq!(budget.available().unwrap(), queued);
    mailbox
        .enqueue_at(message.clone(), original(&budget, &message), now)
        .unwrap();
    assert!(budget.available().unwrap() < queued);
    mailbox.acknowledge_at(&batch, now).unwrap();
    assert!(mailbox.incoming.lock().unwrap().queue.is_empty());
    assert_eq!(budget.available().unwrap(), queued);
    drop(batch);
    let cached = budget.available().unwrap();
    assert!(cached > queued && cached < before);
    mailbox
        .enqueue_at(message.clone(), original(&budget, &message), now)
        .unwrap();
    assert_eq!(budget.available().unwrap(), cached);
    drop(mailbox);
    assert_eq!(budget.available().unwrap(), before);
}
#[test]
fn rejected_batches_are_not_remembered_and_new_statements_or_epochs_are_not_suppressed() {
    let budget = p2p::Budget::new(1024 * 1024);
    let mailbox = CheckpointMailbox::new(budget.clone());
    let message = vote(0);
    let now = Instant::now();
    mailbox
        .enqueue_at(message.clone(), original(&budget, &message), now)
        .unwrap();
    let rejected = mailbox.drain().unwrap();
    drop(rejected);
    mailbox
        .enqueue_at(message.clone(), original(&budget, &message), now)
        .unwrap();
    let retry = mailbox.drain().unwrap();
    assert_eq!(retry.messages.len(), 1);
    mailbox.acknowledge_at(&retry, now).unwrap();
    drop(retry);
    let next_epoch = vote(1);
    mailbox
        .enqueue_at(next_epoch.clone(), original(&budget, &next_epoch), now)
        .unwrap();
    let mut next_statement = message.clone();
    if let Incoming::Vote { statement, .. } = &mut next_statement {
        statement.authorization_height += 1;
    }
    mailbox
        .enqueue_at(
            next_statement.clone(),
            original(&budget, &next_statement),
            now,
        )
        .unwrap();
    assert_eq!(mailbox.drain().unwrap().messages.len(), 2);
    mailbox
        .enqueue_at(
            message.clone(),
            original(&budget, &message),
            now + RECENT_LIFETIME - Duration::from_nanos(1),
        )
        .unwrap();
    assert!(mailbox.drain().unwrap().messages.is_empty());
    mailbox
        .enqueue_at(
            message.clone(),
            original(&budget, &message),
            now + RECENT_LIFETIME,
        )
        .unwrap();
    assert_eq!(mailbox.drain().unwrap().messages.len(), 1);
}
#[test]
fn recent_cache_is_bounded_and_real_unique_queue_overload_remains_rejected() {
    let budget = p2p::Budget::new(8 * 1024 * 1024);
    let mailbox = CheckpointMailbox::new(budget.clone());
    let now = Instant::now();
    for sequence in 0..MAX_RECENT as u64 + 1 {
        let message = vote(sequence);
        mailbox
            .enqueue_at(message.clone(), original(&budget, &message), now)
            .unwrap();
        let batch = mailbox.drain().unwrap();
        mailbox.acknowledge_at(&batch, now).unwrap();
    }
    assert_eq!(mailbox.incoming.lock().unwrap().recent.len(), MAX_RECENT);
    let evicted = vote(0);
    mailbox
        .enqueue_at(evicted.clone(), original(&budget, &evicted), now)
        .unwrap();
    assert_eq!(mailbox.drain().unwrap().messages.len(), 1);
    for sequence in 1000..1000 + MAX_QUEUED as u64 {
        let message = vote(sequence);
        mailbox
            .enqueue_at(message.clone(), original(&budget, &message), now)
            .unwrap();
    }
    let excess = vote(2000);
    assert!(
        mailbox
            .enqueue_at(excess.clone(), original(&budget, &excess), now)
            .is_err()
    );
    assert_eq!(mailbox.incoming.lock().unwrap().queue.len(), MAX_QUEUED);
}
