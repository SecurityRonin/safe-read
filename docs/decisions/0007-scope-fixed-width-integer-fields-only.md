# 7. Scope boundary: fixed-width integer fields only

Date: 2026-07-24
Status: Accepted

## Context

There is a tempting slippery slope for a "safe reading" crate: once it owns the
bounds-checked integer read, it could also grow length-field validation, offset
range-checking against a record, allocation caps against alloc-bombs, string
decoding, and so on. But those concerns are *format-specific* — what counts as a
valid length depends on the record it lives in — and pulling them into a shared
leaf would either bloat it with format knowledge it cannot have or tempt callers
to believe a `safe-read` call has validated more than it has. That false sense of
completeness is itself a robustness hazard.

## Decision

`safe-read` handles **fixed-width integer field reads only** — the six
`{le,be}_u{16,32,64}` widths plus `u8`, each in a plain and a `try_` flavour.
It deliberately does **not** provide:

- range-checking a length/offset/count value *from the image* against the record
  it indexes;
- capping allocations sized by an untrusted length;
- variable-width, string, or structured decoding.

Those remain the calling reader's job, exactly as the fleet constitution states
("`safe-read` handles fixed-width integer fields only; range-checking every
length/offset/count from the image before use and capping allocations against
alloc bombs remain the reader's job"). The crate's guarantee is precisely "no
panic on any `(slice, offset)`", nothing broader.

## Consequences

- The crate stays a trivial, universally-adoptable leaf (ADR 0002, 0004) with a
  guarantee callers can reason about exactly.
- Callers are on notice that a `safe-read` call is *not* semantic validation: a
  returned `0` or `Some(n)` still needs the parser's own bounds and sanity checks.
- New capability that is genuinely format-agnostic (e.g. another integer width)
  fits; anything format-specific belongs in the reader, not here.
