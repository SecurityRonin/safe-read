# 2. One shared audited crate, never a per-crate `bytes.rs`

Date: 2026-07-24
Status: Accepted

## Context

Before this crate existed, each fleet reader (ewf, ntfs, vhdx, qcow2, …)
hand-rolled its own `read_uNN_le` / `bytes.rs` bounds-checked integer helpers.
That is the recurring DRY-plus-robustness failure the fleet constitution calls
out: the hand-rolled copies drift apart, and some variants — a `data.get(off..off+4)`
that computes `off+4` before the `get` — can overflow `usize` in a way a
`checked_add` would have caught. N re-derivations means N chances to get the
overflow guard subtly wrong, and no single place to fuzz or audit.

## Decision

Publish exactly one audited implementation, `safe-read`, and route every
fixed-width integer field read through it. No fleet reader re-derives its own
`read_uNN_le`/`bytes.rs`. `forensic-vfs` re-exports `safe-read` so umbrella crates
get it transitively without adding a direct dependency. This is the constitution's
binding rule ("route through the `safe-read` crate; NEVER hand-roll a per-crate
`bytes.rs`") made concrete as a standalone crate.

## Consequences

- The overflow/bounds logic is written, fuzzed (ADR 0006), and audited **once**;
  fixing or hardening it fixes the whole fleet on a version bump.
- The crate must stay a trivial, dependency-free leaf so that adding it to any
  reader is free (ADR 0004) — a heavy shared helper would not be adopted.
- A reader that still carries its own `bytes.rs` is migration debt to retire, not
  a parallel valid choice.
