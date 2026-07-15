# safe-read

Panic-free bounded integer readers over untrusted byte slices. Each of
`le_u16`/`le_u32`/`le_u64` and `be_u16`/`be_u32`/`be_u64` reads a fixed-width
integer at a byte offset, returning `0` when the window is out of range — too
short, offset past EOF, or `off + width` overflowing `usize`. `#![no_std]`, no
dependencies, no `unsafe`.

```rust
use safe_read::{le_u32, be_u16};
assert_eq!(le_u32(&[0x78, 0x56, 0x34, 0x12], 0), 0x1234_5678);
assert_eq!(le_u32(&[1, 2, 3], 0), 0); // out of range → 0, never a panic
```

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd
