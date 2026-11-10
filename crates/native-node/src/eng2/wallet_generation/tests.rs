use super::*;
fn binding() -> Binding {
    Binding::new([1; 32], [2; 32], [3; 32], [4; 32])
}
fn records(from: u64, count: usize, mut parent: Hash) -> Vec<Record> {
    let b = binding();
    (0..count)
        .map(|index| {
            let header = Header {
                network: b.network(),
                height: from + index as u64,
                parent,
                timestamp: 300 + index as u64,
                target: [255; 32],
                execution_commitment: [7; 32],
                body_commitment: [8; 32],
                nonce: 0,
            };
            let raw = header.encode().unwrap();
            parent = header.id().unwrap();
            let receipt = [b"SWE2WLT1".as_slice(), &b.0, &raw, &[0; 17]].concat();
            Record::from_receipt(&b, raw, &receipt).unwrap()
        })
        .collect()
}
#[test]
fn complete_chunk_and_partial_tail_have_exact_bounded_generation_coverage() {
    let b = binding();
    let first = Chunk {
        from: 1,
        records: records(1, 128, b.genesis()),
    };
    let tail = Chunk {
        from: 129,
        records: records(129, 2, first.records.last().unwrap().id),
    };
    let (a, bytes) = Descriptor::from_chunk(&b, &first).unwrap();
    assert_eq!(bytes.len(), MAX_CHUNK_BYTES);
    assert_eq!(a.decode_chunk(&b, &bytes).unwrap(), first);
    let (z, tailbytes) = Descriptor::from_chunk(&b, &tail).unwrap();
    let m = Manifest {
        height: 130,
        tip: tail.records.last().unwrap().id,
        chunks: vec![a, z],
    };
    let encoded = m.encode(&b).unwrap();
    assert_eq!(Manifest::decode(&b, &encoded).unwrap(), m);
    assert_eq!(m.chunks[1].decode_chunk(&b, &tailbytes).unwrap(), tail);
    let mut bad = m.clone();
    bad.chunks[0].count = 127;
    assert!(bad.encode(&b).is_err());
    let mut bad = m.clone();
    bad.chunks[1].from = 130;
    assert!(bad.encode(&b).is_err());
    let mut bad = m;
    bad.height = 129;
    assert!(bad.encode(&b).is_err());
}
#[test]
fn corrupt_foreign_noncanonical_and_oversized_artifacts_are_rejected() {
    let b = binding();
    let c = Chunk {
        from: 1,
        records: records(1, 2, b.genesis()),
    };
    let (d, raw) = Descriptor::from_chunk(&b, &c).unwrap();
    for offset in [0, 8, 136, 137, 145, 147, 337, 369, 373] {
        let mut bad = raw.clone();
        bad[offset] ^= 1;
        assert!(d.decode_chunk(&b, &bad).is_err());
    }
    let mut bad = raw.clone();
    bad.push(0);
    assert!(Chunk::decode(&b, &bad).is_err());
    let mut foreign = b.clone();
    foreign.0[0] ^= 1;
    assert!(Chunk::decode(&foreign, &raw).is_err());
    let mut gap = c.clone();
    gap.records[1].header[46] ^= 1;
    assert!(gap.encode(&b).is_err());
    assert!(
        Chunk {
            from: 2,
            records: c.records.clone()
        }
        .encode(&b)
        .is_err()
    );
    let m = Manifest {
        height: 2,
        tip: c.records[1].id,
        chunks: vec![d],
    };
    let raw = m.encode(&b).unwrap();
    for offset in [0, 8, 136, 137, 177, 179, 187, 189] {
        let mut bad = raw.clone();
        bad[offset] ^= 1;
        assert!(Manifest::decode(&b, &bad).is_err());
    }
    assert!(Manifest::decode(&b, &vec![0; MAX_MANIFEST_BYTES + 1]).is_err());
    assert!(
        Manifest {
            height: 0,
            tip: [0; 32],
            chunks: vec![]
        }
        .encode(&b)
        .is_err()
    );
}
