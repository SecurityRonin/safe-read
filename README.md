# safe-read

[![Crates.io](https://img.shields.io/crates/v/safe-read.svg)](https://crates.io/crates/safe-read)
[![Docs.rs](https://docs.rs/safe-read/badge.svg)](https://docs.rs/safe-read)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Fuzzed, panic-free-by-construction bounded integer readers over untrusted byte slices** — the shared front door for every offset/length field parsed from an attacker-controllable forensic image, so each reader crate stops re-deriving its own bounds-checked helpers.

```rust
use safe_read::{le_u32, be_u16};

// In range → the value; out of range → 0, never a panic.
assert_eq!(le_u32(&[0x78, 0x56, 0x34, 0x12], 0), 0x1234_5678);
assert_eq!(le_u32(&[1, 2, 3], 0), 0);          // too short
assert_eq!(be_u16(&[1, 2, 3, 4], usize::MAX), 0); // offset overflow
```

`be_u16`/`be_u32`/`be_u64` and `le_u16`/`le_u32`/`le_u64` each read a fixed-width integer at a byte offset, returning `0` when the window is out of range — too short, offset past EOF, or `off + width` overflowing `usize`. `#![no_std]`, no dependencies, no `unsafe`.

## Install

```toml
[dependencies]
safe-read = "0.1"
```

---

[Privacy Policy](https://securityronin.github.io/safe-read/privacy/) · [Terms of Service](https://securityronin.github.io/safe-read/terms/) · © 2026 Security Ronin Ltd
