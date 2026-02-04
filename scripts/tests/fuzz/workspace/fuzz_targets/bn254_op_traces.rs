#![no_main]

use glyph::bn254_ops::{validate_bn254_op_trace_batch, Bn254OpKind, Bn254OpTraceEvent};
use libfuzzer_sys::fuzz_target;

fn parse_u64_le(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    u64::from_le_bytes(buf)
}

fn parse_events(data: &[u8]) -> Vec<Bn254OpTraceEvent> {
    const CHUNK_LEN: usize = 97;
    let mut events = Vec::new();
    for chunk in data.chunks(CHUNK_LEN) {
        if chunk.len() < CHUNK_LEN {
            break;
        }
        let kind = match chunk[0] % 3 {
            0 => Bn254OpKind::Add,
            1 => Bn254OpKind::Sub,
            _ => Bn254OpKind::Mul,
        };
        let mut limbs = [[0u64; 4]; 3];
        for i in 0..12 {
            let start = 1 + i * 8;
            let end = start + 8;
            let value = parse_u64_le(&chunk[start..end]);
            limbs[i / 4][i % 4] = value;
        }
        events.push(Bn254OpTraceEvent {
            kind,
            a: limbs[0],
            b: limbs[1],
            out: limbs[2],
        });
    }
    events
}

fuzz_target!(|data: &[u8]| {
    let events = parse_events(data);
    let _ = validate_bn254_op_trace_batch(&events);
});
