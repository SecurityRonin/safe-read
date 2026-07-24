# 6. Fuzzing supplies the empirical proof of the never-panic invariant

Date: 2026-07-24
Status: Accepted

## Context

"Never panics for any input" is a universal claim. The static posture — `forbid(unsafe)`
plus non-panicking primitives (ADR 0004, ADR 0001) — makes a panic unreachable *by
construction*, but the fleet's evidence discipline distinguishes a static guarantee
from *measured* robustness. A bare, self-graded "panic-free" claim is unearned; the
differentiator the fleet badges is **input-fuzzed** — measured evidence against the
real threat (arbitrary attacker bytes and offsets). The `off + width` overflow path
in particular is exactly the kind of edge a hand-written test can forget but a fuzzer
exercises by driving `usize::MAX`-adjacent offsets.

## Decision

Carry a `cargo-fuzz` target (`fuzz/fuzz_targets/readers.rs`) whose invariant is
"the reader returns a value and never panics, for any byte slice and any offset."
The harness drives the six multi-byte readers — `be_u16/be_u32/be_u64` and
`le_u16/le_u32/le_u64` — which are where the width arithmetic and the `off + width`
overflow guard live; each plain reader calls its own `try_*` twin internally, so the
`try_*` paths are exercised transitively. The single-byte `u8`/`try_u8` readers are a
plain `slice.get(off)` with no width arithmetic to overflow, so they are not driven by
this target. The harness derives an adversarial offset from the first 8 input bytes —
deliberately reaching `usize::MAX`-adjacent values to hit the overflow guard — and then
sweeps the boundary region past the end of the slice. CI builds it: the `fuzz-check` job in
`ci.yml` runs `cargo +nightly fuzz check` (nightly-forced, warnings not denied in its
own deps). The README leads with the *measured* "fuzzed" word and keeps "panic-free"
only as the qualified static half, per the fleet robustness-wording rule.

## Consequences

- The never-panic claim is backed by a maintained, CI-built fuzz target, not just an
  assertion — the empirical partner to the static lints.
- The fuzz crate is a standalone workspace excluded from `deny.toml`'s graph and
  `publish = false`, so it never leaks into the published crate or its license set.
- Fuzzing shows present-robustness over the executed corpus; it does not *prove*
  absence of all panics — which is why the static `forbid`/non-panicking construction
  (ADR 0001, 0004) remains the primary guarantee and fuzzing the confirmation.
