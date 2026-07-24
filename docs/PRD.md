# safe-read — Purpose & Scope

**What it is.** `safe-read` is the fleet's single audited implementation of
bounds-checked, fixed-width integer reads over an untrusted byte slice. Every
`{le,be}_u{16,32,64}` (plus `u8`) comes in two flavours: a plain reader that
returns `0` when the requested window is out of range, and a `try_` twin that
returns `None` for callers who must tell a genuine in-range `0` from an
absent/truncated field. No read ever panics — out of range means too short, offset
past EOF, or `off + width` overflowing `usize`.

**Who uses it.** Every fleet reader crate that decodes attacker-controllable
forensic data (ewf, ntfs, vhdx, qcow2, memory-forensic, …). It exists so those
crates stop re-deriving their own `bytes.rs` bounds-checked helpers — a shared
front door that is written, fuzzed, and audited once (see
[`docs/decisions/`](docs/decisions/) for the rationale).

**In scope.** Fixed-width integer field reads only, `#![no_std]`, zero
dependencies, `#![forbid(unsafe_code)]`, and a low CI-verified MSRV (1.75) so no
consumer's floor is raised.

**Out of scope (the caller's job).** Range-checking a length/offset/count value
*from the image* against the record it indexes, capping allocations sized by an
untrusted length, and any variable-width/string/structured decoding. A `safe-read`
call guarantees "no panic", not semantic validation — the parser still applies its
own bounds and sanity checks.
