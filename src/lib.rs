#![no_std]
#![forbid(unsafe_code)]

//! Panic-free bounded integer readers over an untrusted byte slice.
//!
//! Every read returns a benign default (0 / `None`) when the requested window is out of
//! range — never a panic. This is the shared front door for every offset/length field
//! parsed from an attacker-controllable forensic image, so each reader crate does not
//! re-derive its own bounds-checked helpers.
//!
//! Two flavours per width:
//! - **`le_u32(data, off) -> u32`** — returns `0` out of range (the common case; the parser
//!   then rejects the structurally-invalid record through its own validation).
//! - **`try_le_u32(data, off) -> Option<u32>`** — returns `None` out of range, for the callers
//!   that must distinguish a genuine `0` field from an absent/truncated one.
//!
//! ```
//! use safe_read::{le_u32, be_u16, u8, try_le_u32};
//! assert_eq!(le_u32(&[0x78, 0x56, 0x34, 0x12], 0), 0x1234_5678);
//! assert_eq!(be_u16(&[0xaa, 0x12, 0x34], 1), 0x1234);
//! assert_eq!(u8(&[0xab], 0), 0xab);
//! // Out of range: 0 for the plain readers, None for the `try_` twins:
//! assert_eq!(le_u32(&[1, 2, 3], 0), 0);
//! assert_eq!(try_le_u32(&[1, 2, 3], 0), None);
//! ```
//!
//! `#![no_std]` — pure slice arithmetic, no allocation.

/// Define a fixed-width integer reader pair. The `try_` twin returns `None` when the window
/// at `off` is not fully in range (too short, offset past EOF, or `off + width` overflowing
/// `usize`); the plain reader unwraps that to `0`. Neither ever panics.
macro_rules! bounded_reader {
    ($name:ident, $try_name:ident, $ty:ty, $width:literal, $from_bytes:ident) => {
        #[doc = concat!("Read a `", stringify!($ty), "` at `off`; `None` if out of range. Never panics. Use when `0` must be distinguished from absent/truncated.")]
        #[must_use]
        pub fn $try_name(data: &[u8], off: usize) -> Option<$ty> {
            let end = off.checked_add($width)?;
            let slice = data.get(off..end)?;
            let mut buf = [0u8; $width];
            buf.copy_from_slice(slice);
            Some(<$ty>::$from_bytes(buf))
        }

        #[doc = concat!("Read a `", stringify!($ty), "` at `off`; `0` if out of range. Never panics.")]
        #[must_use]
        pub fn $name(data: &[u8], off: usize) -> $ty {
            $try_name(data, off).unwrap_or(0)
        }
    };
}

bounded_reader!(be_u16, try_be_u16, u16, 2, from_be_bytes);
bounded_reader!(be_u32, try_be_u32, u32, 4, from_be_bytes);
bounded_reader!(be_u64, try_be_u64, u64, 8, from_be_bytes);
bounded_reader!(le_u16, try_le_u16, u16, 2, from_le_bytes);
bounded_reader!(le_u32, try_le_u32, u32, 4, from_le_bytes);
bounded_reader!(le_u64, try_le_u64, u64, 8, from_le_bytes);

/// Read a single byte at `off`; `None` if `off` is past the end. Never panics.
#[must_use]
pub fn try_u8(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

/// Read a single byte at `off`; `0` if `off` is past the end. Never panics. (Endianness is
/// irrelevant for one byte; provided so callers never index `data[off]` directly.)
#[must_use]
pub fn u8(data: &[u8], off: usize) -> u8 {
    try_u8(data, off).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_endian_reads_in_range() {
        assert_eq!(be_u16(&[0x12, 0x34], 0), 0x1234);
        assert_eq!(be_u32(&[0, 0, 1, 0], 0), 256);
        assert_eq!(
            be_u64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], 0),
            0x0102_0304_0506_0708
        );
    }

    #[test]
    fn little_endian_reads_in_range() {
        assert_eq!(le_u16(&[0x34, 0x12], 0), 0x1234);
        assert_eq!(le_u32(&[0, 1, 0, 0], 0), 256);
        assert_eq!(
            le_u64(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01], 0),
            0x0102_0304_0506_0708
        );
    }

    #[test]
    fn reads_honor_offset() {
        assert_eq!(be_u16(&[0xaa, 0x12, 0x34], 1), 0x1234);
        assert_eq!(le_u32(&[0xff, 0xff, 0, 1, 0, 0], 2), 256);
    }

    #[test]
    fn single_byte_reads() {
        assert_eq!(u8(&[0xab, 0xcd], 0), 0xab);
        assert_eq!(u8(&[0xab, 0xcd], 1), 0xcd);
        assert_eq!(u8(&[0xab], 5), 0); // past end → 0
        assert_eq!(u8(&[], 0), 0);
        assert_eq!(try_u8(&[0xab], 0), Some(0xab));
        assert_eq!(try_u8(&[0xab], 1), None);
    }

    #[test]
    fn try_variants_distinguish_zero_from_absent() {
        assert_eq!(try_le_u32(&[0, 0, 0, 0], 0), Some(0)); // genuine in-range 0
        assert_eq!(try_le_u32(&[0, 0, 0], 0), None); // too short
        assert_eq!(try_be_u16(&[1, 2], 2), None); // offset past window
        assert_eq!(
            try_be_u64(&[1, 2, 3, 4, 5, 6, 7, 8], 0),
            Some(0x0102_0304_0506_0708)
        );
        assert_eq!(try_le_u16(&[], 0), None);
    }

    #[test]
    fn out_of_range_returns_zero_never_panics() {
        assert_eq!(be_u32(&[1, 2, 3], 0), 0);
        assert_eq!(be_u64(&[1, 2, 3, 4, 5, 6, 7], 0), 0);
        assert_eq!(be_u32(&[1, 2, 3, 4], 2), 0);
        assert_eq!(le_u16(&[1, 2], 2), 0);
        assert_eq!(be_u16(&[], 0), 0);
        assert_eq!(le_u32(&[1, 2, 3, 4], 100), 0);
    }

    #[test]
    fn offset_overflow_returns_zero() {
        assert_eq!(be_u32(&[1, 2, 3, 4], usize::MAX), 0);
        assert_eq!(try_be_u32(&[1, 2, 3, 4], usize::MAX), None);
    }
}
