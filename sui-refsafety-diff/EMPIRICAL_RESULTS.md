# Empirical results — differential reference-safety run

**Target:** Sui Move bytecode verifier, `reference_safety` (graph) vs `regex_reference_safety`.
**Source commit:** `8d47098` (MystenLabs/sui `main`).
**Toolchain:** stable rustc 1.94.1, release build. No nightly/libfuzzer required — the driver is a
stable-Rust structured generator (`guided_driver.rs`).

## What was actually built and run

`guided_driver.rs` builds a fixed, valid module scaffold — struct `S { f0:u64, f1:u64 }`, enum
`E { V0{e0}, V1{e1,e2} }`, a helper `g(&mut S,&mut S)`, and 8 typed locals (S, &mut S, &S, u64,
&mut u64, E, &mut E, &E) — then fuzzes the body of one function from a curated, borrow-relevant
opcode alphabet (borrows, field borrows, variant unpack refs, pack/unpack, ReadRef/WriteRef,
FreezeRef, calls, branches).

Each generated function is filtered through the **exact production per-function pipeline order**
before the two reference checkers are compared:

```
control-flow (via FunctionContext::new)
  -> StackUsageVerifier::verify   (must pass)
  -> type_safety::verify          (must pass)
  -> locals_safety::verify        (must pass)
  -> reference_safety::verify      \ compared
  -> regex_reference_safety::verify /
```

To gate correctly, three internal passes were exposed `pub` in a **local clone only** (research
patch, never upstreamed): `type_safety`, `locals_safety`, `stack_usage_verifier`. Without this gate
the reference verifiers face inputs the real pipeline rejects earlier, producing spurious
panics/errors (observed and eliminated — see below).

## Outcome

Across tens of millions of iterations / millions of gated function-comparisons:

| metric | result |
|---|---|
| `CANDIDATE_P` (regex accepts ∧ graph rejects) | **0** |
| `guarded_dir` (graph accepts ∧ regex rejects) | **0** |
| any behavioral divergence between the two checkers | **0** |

The two implementations agreed on every gated input. **No vulnerability found.**

### Strongest single signal (struct-borrow alphabet, property genuinely stressed)

In runs over the struct-borrow alphabet (before the enum ops diluted the rejection rate), the
generator produced **thousands of genuine reference-safety rejections** — and the two checkers
still agreed on all of them:

| seed | compared | graph_rej | regex_rej | divergence (either direction) |
|---|---|---|---|---|
| A | 6,018,451 | 7686 | 7686 | 0 |
| B | 6,008,981 | 3910 | 3910 | 0 |

~11,600 real rejections, `graph_rej == regex_rej` exactly, zero disagreement in either direction.
This is the meaningful negative: where the property is actually exercised, the graph and regex
analyses are behaviorally identical on this input class.

## Coverage-guided campaign (cargo-fuzz + libfuzzer)

Beyond the blind/structured drivers, a real coverage-guided campaign was run with
`cargo-fuzz 0.13.2` on nightly, using `diff_refsafety.rs` as a libfuzzer target
(`bytecode-verifier-libfuzzer` crate). libfuzzer mutates the fuzzed function body with coverage
feedback; the same production-faithful per-function gate (`stack_usage → type_safety →
locals_safety`) runs before comparing the two reference checkers.

**Result of one 500-second run:**

| metric | value |
|---|---|
| executions | 1,152,359 |
| exec/sec | ~2,300 |
| new coverage units discovered | 4,303 |
| crashes / candidate-P divergences | **0** |

Coverage genuinely expanded (4,303 new units, corpus grew to ~1,500 inputs) — this is real guided
exploration, not blind spraying — and it surfaced **no divergence**.

### False positives triaged (important methodology note)

The first two cargo-fuzz crashes were **not** divergences. Both were debug-only `safe_assert!`
panics in the bounds checker (`check_bounds.rs:531` and `:562`) on deprecated global-storage ops.
The `safe_assert!` macro is:

```rust
if cfg!(debug_assertions) { panic!("{:?}", err) } else { return Err(err); }
```

cargo-fuzz enables `debug_assertions`, so these panic under fuzzing but **return a clean `Err` in
release/production** — not bugs, exactly the "debug_assert removed in release" class. The target was
hardened (`ok()` + `catch_unwind`) to fold any debug-only verifier panic into the release-equivalent
"reject", so the campaign reflects production behavior and only a genuine candidate-P aborts.

## The one real asymmetry (not exploitable)

Before adding `StackUsageVerifier` to the gate, the graph checker **panicked** with
`Result::unwrap() on Err(Underflow)` at `reference_safety/mod.rs:95` — it uses `.pop().unwrap()` on
the abstract stack, whereas `regex_reference_safety` uses `safe_unwrap!` (returns `Err`). This is a
genuine robustness asymmetry, but it is **unreachable in production**: `StackUsageVerifier` runs
before reference safety in `code_unit_verifier::verify_common` and guarantees no underflow. Once the
gate mirrors that order, the panic disappears. Latent, not a bug an attacker can trigger.

## Honest limitations (why "0 divergences" is not "proven safe")

1. **Generator strength.** Once gated correctly, random bodies rarely produce *valid-but-
   borrow-conflicting* functions (the `graph_rej` rate falls to ~0 in the enum-heavy alphabet), so
   the property under test is under-stressed. Absence of divergence here is weak evidence, not proof.
2. **No coverage feedback.** This is blind structured generation, not coverage-guided fuzzing. A
   real campaign needs libfuzzer/AFL (nightly) over `diff_refsafety.rs`, run for days, plus a
   generator biased toward borrow *conflicts* that still pass stack+type+locals safety.
3. **Scaffold scope.** One struct, one enum, no generics, no vectors, no nested references, no
   `VariantSwitch`/jump tables, single module. Divergences could live outside this shape.
4. **Even a real divergence would be latent**, not live, until `switch_to_regex_reference_safety`
   is flipped to `true` (see FINDINGS.md).

## Reproduce

Place `guided_driver.rs` (as `src/guided.rs`) and `driver.Cargo.toml` (as `Cargo.toml`) in a crate
under `external-crates/move/crates/`, apply the three `pub` exposures listed above to
`move-bytecode-verifier`, then:

```bash
cargo build --release -p refsafety-diff-driver --bin guided_driver
./target/release/guided_driver 5000000 <seed>
```
