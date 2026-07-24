# 3. Two flavours per width: plain `0`-returning and `try_` `None`-returning

Date: 2026-07-24
Status: Accepted

## Context

The `0`-on-out-of-range default (ADR 0001) is right for the common case, where a
parser reads a field and then validates it — an out-of-range read collapses to an
impossible value the parser already rejects. But some callers must distinguish a
**genuine in-range `0`** (a field that is legitimately zero) from an **absent or
truncated** field. Collapsing both to `0` loses that distinction and can mask a
truncation as a valid empty value — a silent-wrong-output risk. Version 0.1.0
shipped only the plain readers; the `try_*` twins and `u8` were added in 0.2.0
(commit `dfb14dd`, `feat: add u8 + try_* (Option-returning) readers`).

## Decision

Generate both flavours from one macro (`bounded_reader!` in `src/lib.rs`):

- `try_le_u32(data, off) -> Option<u32>` — the real check, returning `None` when
  the window is out of range.
- `le_u32(data, off) -> u32` — the same call unwrapped to `0` for the common case.

The plain reader is defined *in terms of* the `try_` twin (`try_name(...).unwrap_or(0)`),
so there is exactly one bounds-checking code path per width and the two flavours
cannot diverge. A single-byte pair (`u8` / `try_u8`) rounds out the set so callers
never index `data[off]` directly even for one byte.

## Consequences

- Callers pick the right tool: `0`-tolerant fields use the plain reader; fields
  where zero-vs-absent matters use the `try_` twin — a structural choice, not a
  side-channel flag.
- The API surface is 2× the width count, but every pair shares one implementation,
  so the maintenance and fuzzing surface does not double.
