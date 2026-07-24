#![no_main]
//! The whole point of the crate: a reader must return a value (0 when out of
//! range) and NEVER panic, for any byte slice and any offset — including offsets
//! that would overflow `off + width`. This target drives the six multi-byte readers
//! (be/le u16/u32/u64), where the width arithmetic and overflow guard live; each
//! calls its `try_*` twin internally, so those paths are covered transitively. The
//! single-byte `u8`/`try_u8` readers are a plain `slice.get` with no width to
//! overflow. The fuzzer drives arbitrary (slice, offset) pairs; a panic is a failure.

use libfuzzer_sys::fuzz_target;
use safe_read::{be_u16, be_u32, be_u64, le_u16, le_u32, le_u64};

fuzz_target!(|data: &[u8]| {
    // First 8 bytes pick an offset (may be enormous → exercises the overflow
    // guard); the remainder is the slice being read.
    let off = usize::from_le_bytes(
        data.get(..8)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0u8; 8]),
    );
    let body = data.get(8..).unwrap_or(data);

    // The adversarial offset (possibly usize::MAX-adjacent).
    let _ = (
        be_u16(body, off),
        be_u32(body, off),
        be_u64(body, off),
        le_u16(body, off),
        le_u32(body, off),
        le_u64(body, off),
    );

    // Sweep the boundary region (past-the-end offsets included) for good measure.
    for o in 0..body.len().saturating_add(9).min(128) {
        let _ = (be_u16(body, o), be_u64(body, o), le_u32(body, o));
    }
});
