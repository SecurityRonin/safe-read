# 4. Minimal safe leaf: `no_std`, zero dependencies, `forbid(unsafe)`

Date: 2026-07-24
Status: Accepted

## Context

This crate is meant to be depended on by *every* reader in the fleet, including
crates that themselves must stay `no_std` and dependency-light, and including
parsers of attacker-controlled input where a memory-safety defect would reintroduce
exactly the out-of-bounds class the crate exists to eliminate. A shared leaf that
pulls dependencies, requires `std`, or contains `unsafe` would be both harder to
adopt universally and a worse trust anchor.

## Decision

Keep the crate a minimal safe leaf on three axes, all enforced in source:

- **`#![no_std]`** (`src/lib.rs`) — pure fixed-width slice arithmetic, no
  allocation, so `no_std` readers can depend on it.
- **Zero runtime dependencies** — the `[dependencies]` table in `Cargo.toml` is
  empty, so no third-party license is ever pulled in; the crate's own license is
  Apache-2.0. The `deny.toml` allow-list is `["MIT", "Apache-2.0"]` (the fleet
  default pair) — with no dependencies the `MIT` entry is inert, but it is kept so
  the config matches the rest of the fleet rather than being trimmed to a lone entry.
- **`unsafe_code = "forbid"`** — set both as an inner attribute (`#![forbid(unsafe_code)]`)
  and in `[lints.rust]`. Unlike the mmap-backed container readers (ewf,
  memory-forensic), which the constitution permits to downgrade to
  `deny` + a bounded per-site `#[allow]`, this crate needs no `unsafe` at all: the
  whole implementation is `checked_add` + `slice.get` + `copy_from_slice`. So it
  takes the strongest, non-overridable posture and can honestly wear the
  "unsafe forbidden" guarantee.

## Consequences

- Any fleet crate can add `safe-read` for free — no transitive dependencies, no
  `std` requirement, no new `unsafe` audit surface.
- The `forbid` (not `deny`) posture means no future contributor can locally opt in
  to `unsafe` without an explicit, visible policy change to the crate root.
- Adding a feature that needed `std` or a dependency (e.g. a `serde` output path)
  would be a deliberate departure from this decision, not a casual addition.
