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
//! Each width has a signed reader too (`le_i32`, `try_be_i64`, …), for the fields a format
//! declares signed; and [`try_bytes`] copies out a fixed-width byte window (a GUID, a
//! signature, a digest) under the same bounds rule.
//!
//! ```
//! use safe_read::{le_u32, be_u16, u8, try_le_u32, le_i32, try_bytes};
//! assert_eq!(le_u32(&[0x78, 0x56, 0x34, 0x12], 0), 0x1234_5678);
//! assert_eq!(be_u16(&[0xaa, 0x12, 0x34], 1), 0x1234);
//! assert_eq!(u8(&[0xab], 0), 0xab);
//! // Signed fields come back negative, not as their huge unsigned twin:
//! assert_eq!(le_i32(&[0xff, 0xff, 0xff, 0xff], 0), -1);
//! assert_eq!(try_bytes::<2>(&[0xaa, 0xbb, 0xcc], 1), Some([0xbb, 0xcc]));
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

// Signed twins. Two's-complement reinterpretation is the whole difference: a field the
// format declares signed (a FILETIME delta, a negative record offset, a signed count)
// read through the unsigned reader comes back as its huge positive twin.
bounded_reader!(be_i16, try_be_i16, i16, 2, from_be_bytes);
bounded_reader!(be_i32, try_be_i32, i32, 4, from_be_bytes);
bounded_reader!(be_i64, try_be_i64, i64, 8, from_be_bytes);
bounded_reader!(le_i16, try_le_i16, i16, 2, from_le_bytes);
bounded_reader!(le_i32, try_le_i32, i32, 4, from_le_bytes);
bounded_reader!(le_i64, try_le_i64, i64, 8, from_le_bytes);

/// Copy the `N`-byte window at `off` into an array; `None` if that window is not fully in
/// range (too short, offset past EOF, or `off + N` overflowing `usize`). Never panics.
///
/// The array flavour of the readers above, for the fixed-width windows that are not
/// integers — GUIDs, signatures, digests, fixed-size name fields:
///
/// ```
/// use safe_read::try_bytes;
/// let record = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
/// assert_eq!(try_bytes::<4>(&record, 0), Some([0xde, 0xad, 0xbe, 0xef]));
/// assert_eq!(try_bytes::<4>(&record, 3), None); // runs past the end
/// ```
#[must_use]
pub fn try_bytes<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    let slice = data.get(off..end)?;
    let mut buf = [0u8; N];
    buf.copy_from_slice(slice);
    Some(buf)
}

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

    #[test]
    fn signed_reads_in_range() {
        assert_eq!(le_i16(&[0x34, 0x12], 0), 0x1234);
        assert_eq!(be_i16(&[0x12, 0x34], 0), 0x1234);
        assert_eq!(le_i32(&[0, 1, 0, 0], 0), 256);
        assert_eq!(be_i32(&[0, 0, 1, 0], 0), 256);
        assert_eq!(
            le_i64(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01], 0),
            0x0102_0304_0506_0708
        );
        assert_eq!(
            be_i64(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], 0),
            0x0102_0304_0506_0708
        );
    }

    #[test]
    fn signed_reads_honor_offset() {
        assert_eq!(be_i16(&[0xaa, 0x12, 0x34], 1), 0x1234);
        assert_eq!(le_i32(&[0xff, 0xff, 0, 1, 0, 0], 2), 256);
    }

    /// The whole point of the signed readers: a two's-complement bit pattern must come
    /// back as a negative number, not as its huge unsigned twin.
    #[test]
    fn signed_reads_round_trip_negative_values() {
        assert_eq!(le_i16(&[0xff, 0xff], 0), -1);
        assert_eq!(be_i16(&[0xff, 0xff], 0), -1);
        assert_eq!(le_i32(&[0xff, 0xff, 0xff, 0xff], 0), -1);
        assert_eq!(be_i32(&[0xff, 0xff, 0xff, 0xff], 0), -1);
        assert_eq!(le_i64(&[0xff; 8], 0), -1);
        assert_eq!(be_i64(&[0xff; 8], 0), -1);

        // i16::MIN / i32::MIN / i64::MIN — the sign bit alone.
        assert_eq!(le_i16(&[0x00, 0x80], 0), i16::MIN);
        assert_eq!(be_i16(&[0x80, 0x00], 0), i16::MIN);
        assert_eq!(le_i32(&[0x00, 0x00, 0x00, 0x80], 0), i32::MIN);
        assert_eq!(be_i32(&[0x80, 0x00, 0x00, 0x00], 0), i32::MIN);
        assert_eq!(le_i64(&[0, 0, 0, 0, 0, 0, 0, 0x80], 0), i64::MIN);
        assert_eq!(be_i64(&[0x80, 0, 0, 0, 0, 0, 0, 0], 0), i64::MIN);

        // A FILETIME-style "no such time" sentinel and an ordinary negative delta.
        assert_eq!(
            le_i64(&[0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0),
            -2
        );
        assert_eq!(le_i32(&[0x9c, 0xff, 0xff, 0xff], 0), -100);

        assert_eq!(try_le_i32(&[0xff, 0xff, 0xff, 0xff], 0), Some(-1));
        assert_eq!(try_be_i64(&[0xff; 8], 0), Some(-1));
    }

    #[test]
    fn signed_out_of_range_returns_zero_or_none() {
        assert_eq!(le_i16(&[1], 0), 0);
        assert_eq!(be_i16(&[], 0), 0);
        assert_eq!(le_i32(&[1, 2, 3], 0), 0);
        assert_eq!(be_i32(&[1, 2, 3, 4], 2), 0);
        assert_eq!(le_i64(&[1, 2, 3, 4, 5, 6, 7], 0), 0);
        assert_eq!(be_i64(&[1, 2, 3, 4, 5, 6, 7, 8], 100), 0);

        assert_eq!(try_le_i16(&[1], 0), None);
        assert_eq!(try_be_i16(&[], 0), None);
        assert_eq!(try_le_i32(&[1, 2, 3], 0), None);
        assert_eq!(try_be_i32(&[1, 2, 3, 4], 2), None);
        assert_eq!(try_le_i64(&[1, 2, 3, 4, 5, 6, 7], 0), None);
        assert_eq!(try_be_i64(&[1, 2, 3, 4, 5, 6, 7, 8], 100), None);

        // A genuine in-range 0 is still distinguishable from absent.
        assert_eq!(try_le_i32(&[0, 0, 0, 0], 0), Some(0));
    }

    #[test]
    fn signed_offset_overflow_returns_zero() {
        assert_eq!(le_i16(&[1, 2, 3, 4], usize::MAX), 0);
        assert_eq!(be_i32(&[1, 2, 3, 4], usize::MAX), 0);
        assert_eq!(le_i64(&[1, 2, 3, 4], usize::MAX), 0);
        assert_eq!(try_le_i16(&[1, 2, 3, 4], usize::MAX), None);
        assert_eq!(try_be_i32(&[1, 2, 3, 4], usize::MAX), None);
        assert_eq!(try_le_i64(&[1, 2, 3, 4], usize::MAX), None);
    }

    #[test]
    fn try_bytes_window_in_range() {
        let data = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        assert_eq!(try_bytes::<4>(&data, 0), Some([0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(try_bytes::<2>(&data, 4), Some([0x01, 0x02]));
        assert_eq!(try_bytes::<1>(&data, 5), Some([0x02]));
        assert_eq!(try_bytes::<6>(&data, 0), Some(data));
        // A zero-width window is in range anywhere up to the end.
        assert_eq!(try_bytes::<0>(&data, 6), Some([]));
        assert_eq!(try_bytes::<0>(&[], 0), Some([]));
        // A 16-byte GUID window — the case the fleet re-derives everywhere.
        let guid = [
            0x77, 0x4e, 0xc1, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(try_bytes::<16>(&guid, 0), Some(guid));
    }

    #[test]
    fn try_bytes_out_of_range_returns_none() {
        let data = [1u8, 2, 3, 4];
        assert_eq!(try_bytes::<5>(&data, 0), None); // window longer than slice
        assert_eq!(try_bytes::<4>(&data, 1), None); // window runs past the end
        assert_eq!(try_bytes::<1>(&data, 4), None); // offset at the end
        assert_eq!(try_bytes::<1>(&[], 0), None);
        assert_eq!(try_bytes::<16>(&data, 0), None);
    }

    /// `off + N` must be a `checked_add`: an unchecked one wraps here and would then
    /// index a window that looks in range.
    #[test]
    fn try_bytes_offset_overflow_returns_none() {
        let data = [1u8, 2, 3, 4];
        assert_eq!(try_bytes::<4>(&data, usize::MAX), None);
        assert_eq!(try_bytes::<16>(&data, usize::MAX - 8), None);
        assert_eq!(try_bytes::<2>(&data, usize::MAX - 1), None);
    }
}
