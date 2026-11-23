#![allow(dead_code)]

use sivault_releaser::ledger::{Attempt, Event, Ledger, Possession, Record, SlotIdentity};
use sivault_releaser::message::{Action, Body, Domain, Id, Message, Operation, OwnerMeta};

pub fn id(byte: u8) -> Id {
    Id([byte; 32])
}

pub fn domain() -> Domain {
    Domain {
        suite: 0x1234,
        network: id(1),
        safe: id(2),
        generation: 1,
        slot: id(3),
        incarnation: id(4),
        request: id(5),
        operation: Operation::Normal,
    }
}

pub fn slot() -> SlotIdentity {
    let d = domain();
    SlotIdentity {
        suite: d.suite,
        network: d.network,
        safe: d.safe,
        slot: d.slot,
        ledger: id(6),
    }
}

pub fn record() -> Record {
    Record {
        generation: 1,
        incarnation: id(4),
        manifest: id(7),
        root: id(8),
    }
}

pub fn ledger(allowance: u64) -> Ledger {
    Ledger::enrollment(slot(), allowance, record())
}

pub fn attempt(request: u8) -> Attempt {
    let mut domain = domain();
    domain.request = id(request);
    Attempt {
        domain,
        record_manifest: id(7),
        selected_record: id(9),
        challenge: id(request.wrapping_add(80)),
        init_digest: id(10),
        challenge_digest: id(11),
        client_nonce: id(12),
        server_nonce: id(13),
        reply_key_digest: id(14),
        deadline: 100,
    }
}

pub fn register(a: &Attempt) -> Event {
    Event::RegisterChallenge {
        attempt: a.clone(),
        now: 1,
    }
}
pub fn charge(a: &Attempt) -> Event {
    Event::Charge {
        attempt: a.clone(),
        possession: Possession::Accepted,
        now: 2,
    }
}

pub fn owner(counter: u64, action: Action) -> Message {
    let mut d = domain();
    d.operation = Operation::Owner;
    d.request = id((counter + 100) as u8);
    Message {
        domain: d,
        body: Body::Owner {
            meta: Box::new(OwnerMeta {
                owner_key: id(20),
                counter,
                command: id(counter as u8),
                predecessor: id(21),
                manifest: id(22),
                expiry: 100,
            }),
            action,
        },
    }
}

pub fn command(message: Message) -> Event {
    let Body::Owner { meta, .. } = &message.body else {
        panic!("owner message required");
    };
    Event::Owner {
        digest: id((meta.counter + 150) as u8),
        message: Box::new(message),
        now: 3,
    }
}

pub fn refill(counter: u64, expected: u64, delta: u64) -> Message {
    owner(
        counter,
        Action::Refill {
            ledger: id(6),
            delta,
            expected_total: expected,
            new_total: expected + delta,
        },
    )
}

pub fn prepare(counter: u64) -> Message {
    owner(
        counter,
        Action::Prepare {
            rotation: id(30),
            old_root: id(8),
            next_generation: 2,
            next_manifest: id(22),
            next_root: id(31),
            expected_head: id(32),
            successor_record: id(33),
            successor_incarnation: id(34),
        },
    )
}

pub fn commit(counter: u64) -> Message {
    owner(
        counter,
        Action::Commit {
            rotation: id(30),
            old_root: id(8),
            next_root: id(31),
            receipts: id(35),
            certificate: id(36),
        },
    )
}

pub fn retire(counter: u64) -> Message {
    owner(
        counter,
        Action::Retire {
            rotation: id(30),
            old_root: id(8),
            next_root: id(31),
            certificate: id(36),
        },
    )
}

pub fn delete(counter: u64, fence_counter: u64) -> Message {
    owner(
        counter,
        Action::Delete {
            rotation: id(30),
            retired_record: id(7),
            expected_fence: id((fence_counter + 150) as u8),
            share_ids: vec![id(40), id(41)],
        },
    )
}

pub fn restore(counter: u64) -> Message {
    owner(
        counter,
        Action::RestoreService {
            ledger: id(6),
            expected_head: id(50),
            exact_record: id(7),
            expected_tombstone: id(51),
            target_incarnation: id(52),
            witness: id(53),
        },
    )
}
