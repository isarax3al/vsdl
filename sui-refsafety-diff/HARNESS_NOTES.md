# Building & running the differential harness

## Placement
Add `diff_refsafety.rs` as a fuzz target in a crate that depends on `move-bytecode-verifier`,
`move-bytecode-verifier-meter`, `move-binary-format`, and `move-vm-config`. The existing
`external-crates/move/crates/*-fuzz*` crates already carry these deps; add the target to that
crate's `Cargo.toml`:

```toml
[[bin]]
name = "diff_refsafety"
path = "fuzz_targets/diff_refsafety.rs"
test = false
doc = false
```

## Verified symbol paths (commit 8d47098)
| symbol | path | visibility |
|---|---|---|
| `verify_module_unmetered` | `move_bytecode_verifier::verify_module_unmetered` | `pub` |
| graph checker | `move_bytecode_verifier::reference_safety::verify` | `pub` |
| regex checker | `move_bytecode_verifier::regex_reference_safety::verify` | `pub` |
| `FunctionContext::new` | `move_bytecode_verifier::absint::FunctionContext::new` | `pub` |
| `DummyMeter` | `move_bytecode_verifier_meter::dummy::DummyMeter` | `pub` |

No test-only or `pub(crate)` symbol is invented; the harness compiles against the public API.

## Run
```bash
cd external-crates/move/crates/<the-fuzz-crate>
cargo +nightly fuzz run diff_refsafety -- -jobs=$(nproc)
```
Hits (candidate-P divergences) panic and drop the offending module to `/tmp/refgap_*.mvb`.

## Guiding the generator (optional but strongly recommended)
Random `CompiledModule`s almost never pass `check_bounds`, so a naive `arbitrary` derive wastes
nearly all executions. Bias generation toward patterns most likely to separate a *path*-based
analysis from a *graph*-based one:

- `MutBorrowLoc → MutBorrowField(f) → MutBorrowField(g)` — multi-level field paths.
- `MutBorrowLoc(x)` twice on the same local, then both passed to a `Call` with two `&mut` params.
- `UnpackVariantMutRef` followed by `MutBorrowField` — enum-through paths (newest, least covered).
- `if/else` branches producing different borrows that merge at a join point (path-precision loss).
- Sequences that produce a `.*` (dot-star) in the path representation.

Only emit modules that already pass `check_bounds`; otherwise both checkers reject and the run is noise.

## Triage — do NOT skip
A hit is a *latent* divergence, **not** a confirmed vulnerability. See `FINDINGS.md`: in the default
config the graph checker is authoritative and rejected the module, so nothing executes. Before
treating any hit as security-relevant, work it through the seven-step chain (Template ج):
1. Confirm regex-accepts ∧ graph-rejects on the saved `.mvb`.
2. Prove the graph rejection is **safety-relevant** (aliasing / dangling / use-after-move), not a
   conservative false-positive over a genuinely safe program. This is the filter that kills almost
   every hit.
3. Publishability by an unprivileged user.
4. Runtime reachability — and note the switch is checked at signing/publish only.
5. Concrete runtime impact (double `&mut`, linear-value drop, or type confusion → critical;
   panic-only → MEDIUM, be honest).
6. `paranoid_type_checks` + adapter: does runtime catch it first? Trace `eval` before claiming impact.
7. Weakest link — if any step breaks, the candidate is dead. Say so.

And the governing caveat: even a real soundness gap here is only live once
`switch_to_regex_reference_safety` is flipped to `true` (`code_unit_verifier.rs:191`).
