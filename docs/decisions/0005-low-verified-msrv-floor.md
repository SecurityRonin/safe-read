# 5. Low CI-verified MSRV floor (1.75), decoupled from the dev toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet policy separates the **dev toolchain** (what everything is built,
formatted, and linted with) from a published library's **declared MSRV** (a
downstream-facing compatibility promise). `rust-toolchain.toml` pins the dev/CI
toolchain to the current fleet stable (`1.96.0`). But `safe-read` is a published
library that *every* reader depends on: if it raised its MSRV to match the dev
pin, it would force that floor onto the entire fleet and any external consumer.
Conflating the two numbers would silently narrow the crate's audience with each
fleet toolchain bump.

## Decision

Declare a low, CI-verified MSRV independent of the dev pin:

- `Cargo.toml` sets `rust-version = "1.75"`, with the rationale in a comment ("a
  leaf byte-reading crate with no features to gate … so every fleet reader can
  depend on it without raising theirs").
- CI enforces it honestly: the `msrv` job in `ci.yml` runs `cargo test
  --all-features` on `dtolnay/rust-toolchain@1.75.0`, so the floor is a real,
  tested guarantee rather than an aspirational number.
- The dev toolchain stays at the fleet pin (`rust-toolchain.toml` channel
  `1.96.0`); the two numbers are deliberately different.

The crate uses only long-stable APIs (`checked_add`, `slice::get`,
`u32::from_le_bytes`, `copy_from_slice`), so `1.75` costs nothing.

## Consequences

- Every fleet reader and any external consumer can adopt `safe-read` without
  raising their own MSRV — a deliberate compatibility feature.
- The `1.75` floor must be treated as near-breaking: raise it only if the crate
  genuinely needs a newer-Rust feature, never merely to match a toolchain bump.
- The verified-MSRV CI job is a real guarantee and must not be dropped to chase a
  newer language feature casually.
