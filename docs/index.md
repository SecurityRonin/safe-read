# safe-read

Panic-free bounded integer readers over untrusted byte slices. Each of
`le_u16`/`le_u32`/`le_u64`, `be_u16`/`be_u32`/`be_u64` and their signed twins
`le_i16`/`le_i32`/`le_i64`, `be_i16`/`be_i32`/`be_i64` reads a fixed-width
integer at a byte offset, returning `0` when the window is out of range — too
short, offset past EOF, or `off + width` overflowing `usize`. `try_bytes::<N>`
copies out a fixed-width byte window (a GUID, a signature, a digest) under the
same rule, returning `None` instead. `#![no_std]`, no dependencies, no `unsafe`.

```rust
use safe_read::{le_u32, le_i32, try_bytes};
assert_eq!(le_u32(&[0x78, 0x56, 0x34, 0x12], 0), 0x1234_5678);
assert_eq!(le_u32(&[1, 2, 3], 0), 0); // out of range → 0, never a panic
assert_eq!(le_i32(&[0xff, 0xff, 0xff, 0xff], 0), -1); // signed fields stay signed
assert_eq!(try_bytes::<2>(&[0xaa, 0xbb, 0xcc], 1), Some([0xbb, 0xcc]));
```

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
