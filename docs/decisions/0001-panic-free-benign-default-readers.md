# 1. Panic-free bounded readers return a benign default out of range

Date: 2026-07-24
Status: Accepted

## Context

Every fleet reader crate parses **untrusted, attacker-controllable** byte data:
disk images, memory dumps, log records. Offset and length fields inside those
structures routinely point past the end of the buffer — because the input is
truncated, malformed, or deliberately crafted. The naive `data[off]` /
`&data[off..off+4]` idioms panic on such input, which for a forensic tool is a
denial-of-service on the investigation: a single crafted record aborts the whole
run. The `off + width` computation can itself overflow `usize` when `off` is near
`usize::MAX`, which a bare slice index does not guard against.

## Decision

Every reader is total: it returns a value for *any* `(slice, offset)` pair and
never panics. When the requested window is not fully in range — too short, offset
past EOF, or `off + width` overflowing `usize` — the plain reader returns `0`. The
bounds check is a `checked_add` for the overflow case plus `slice.get(off..end)`
for the range case (`src/lib.rs`, the `bounded_reader!` macro); both are
non-panicking by construction. `0` is the benign default because the parser then
rejects the structurally-invalid record through its own field validation — the
out-of-range read surfaces as an impossible value, not a crash.

## Consequences

- Malformed or truncated evidence degrades to an obviously-invalid field value
  (`0`), never a crash — the calling parser's normal validation catches it.
- Callers must still validate the *values* they read (a `0` length, an offset
  that exceeds the record) — this crate guarantees no crash, not semantic
  correctness (see ADR 0007 for the scope boundary).
- The `off + width` overflow guard means callers never have to pre-check offsets
  against `usize::MAX` before calling.
