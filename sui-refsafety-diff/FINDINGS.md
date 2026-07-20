# Differential reference-safety analysis — Sui Move bytecode verifier

**Target:** `external-crates/move/crates/move-bytecode-verifier`
**Analyzed commit:** `8d47098` (tip of `main` at analysis time; the two checkers and the
consistency-check wiring below are present unchanged)
**Scope:** `reference_safety` (graph-based) vs `regex_reference_safety` (path/regex-based),
and the consistency check that connects them in `code_unit_verifier.rs`.

> **Honest status: no exploitable vulnerability confirmed.** This is a *fuzz target + trust-boundary
> assessment*, not a bug report. Everything below is verified against the real source; the
> conclusion is that the current configuration is not exploitable, and the interesting direction
> is a *latent, config-gated* concern, not a live one.

---

## What was verified in the source (not assumed)

1. **The enforced checker is the graph-based one.** `code_unit_verifier.rs:191` branches on
   `verifier_config.switch_to_regex_reference_safety`. When it is `false`, execution returns
   `reference_safety::verify(...)` (graph-based) as the authoritative verdict
   (`reference_safety_with_optional_regex_sanity_check`, lines 211–274). The regex checker runs
   only as a *shadow* sanity check, gated behind `sanity_check_with_regex_reference_safety.is_some()`
   (line 231).

2. **The consistency check direction (line 262).**
   ```rust
   let is_consistent = regex_res.is_ok() || reference_safety_res.is_err();
   ```
   This rejects exactly one combination: **`regex rejects ∧ classic accepts`** — i.e. it enforces
   "regex is strictly *more permissive* than the graph checker." The comment (257–261) states this
   intent explicitly.

3. **The direction that is NOT guarded** is the opposite: **`regex accepts ∧ classic rejects`**
   (`regex_res.is_ok() && reference_safety_res.is_err()`). `is_consistent` is `true` here, so no
   error is raised. This is the "candidate P" divergence the harness searches for.

4. **Why candidate P is not currently exploitable.** In the default/enforced configuration the
   graph checker is authoritative and, for candidate P, it *rejected*. A rejected module never
   executes, so a divergence where the (inactive) regex checker would have accepted it cannot reach
   runtime and cannot move funds today.

5. **The consistency check runs on the signing/publish path only** — it is part of module
   verification, which gates admission, not per-execution. This matches the methodology's claim.

---

## Correction to the methodology assumptions

- The methodology's harness proposed an in-crate `pub(crate)` wrapper `__diff_refsafety` behind a
  `fuzzing` feature. **Not needed:** both `reference_safety::verify` and
  `regex_reference_safety::verify` are already `pub`, as is `FunctionContext::new` and
  `verify_module_unmetered`. The harness in `diff_refsafety.rs` uses the public API only — no patch
  to the verifier crate is required, which also keeps it honest (no test-only symbols invented).
- The signatures differ: the graph checker takes an extra `name_def_map:
  &HashMap<IdentifierIndex, FunctionDefinitionIndex>` argument; the regex checker does not. The
  harness builds `name_def_map` the same way `code_unit_verifier.rs:73–76` does.

---

## When candidate P would matter (the only path to criticality)

The single condition that would promote a candidate-P divergence from "latent" to "live" is a flip
of `switch_to_regex_reference_safety` to `true` (line 191). At that point the regex checker becomes
authoritative; a module it accepts but the graph checker would have rejected would execute. Even
then, criticality requires the divergence to be a genuine **soundness** hole in the regex checker
(aliasing / dangling / use-after-move that the graph checker correctly caught), not one of the many
*intended* benign cases where the regex checker is simply more permissive. The base rate for a given
divergence being a real soundness hole is low; the regex checker is designed to be more permissive.

**Terminal honesty:** proving any candidate is critical requires (a) the switch being enabled, and
(b) a manual proof per Template ج that the graph checker's rejection was safety-relevant and that
`paranoid_type_checks` + the adapter do not catch the resulting bytecode at runtime. Neither has
been demonstrated here. Do not file this as a vulnerability in its current state.

---

## How to run the search

See `diff_refsafety.rs` and `HARNESS_NOTES.md`. The harness panics on a candidate-P divergence and
saves the offending module bytes for manual triage under Template ج.
