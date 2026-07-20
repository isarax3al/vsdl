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
