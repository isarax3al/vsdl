# Sui critical-bug investigation — honest end-to-end summary

Source: MystenLabs/sui `8d47098`. Everything below verified against real code this session.
**Bottom line: no exploitable vulnerability found across every surface examined.**

## Surfaces examined and outcome

| # | Surface | Method | Result |
|---|---|---|---|
| 1 | `reference_safety` vs `regex_reference_safety` (bytecode verifier) | Blind + guided drivers (tens of M iters) **and** coverage-guided cargo-fuzz (1.15M execs, production-faithful gating) | **Clean.** 0 divergences. ~11.6k genuine rejections all agreed exactly. One non-exploitable robustness asymmetry (`.pop().unwrap()` vs `safe_unwrap!`, gated behind StackUsageVerifier). |
| 2 | `object_funds_checker::try_withdraw` (over-withdrawal guard) | Static invariant analysis | **Sound.** Check uses conservative running-max; records net≤max; per-account serialization makes `unsettled ≤ funds` inductive. Worst case if `net≤max` were violable in release = validator `assert!` panic = DoS (MEDIUM), and reachability not demonstrable statically. |
| 3 | `funds_accumulator.rs` native (`withdraw_from_accumulator_address`) | Line-by-line | **Clean.** Produced `Balance(u64)` == emitted `Split(U64)` (same value); u256→u64 narrowing **rejected** with `E_OVERFLOW`, never truncated. Deposit side symmetric. |
| 4 | Bella Ciao `Withdrawal→Coin` path (non-SUI T) | Static + harness adaptation | Path **reachable** from unprivileged PTB (`balance::redeem_funds` is `public fun`), but all three conservation backstops hold. No mint found. |

## Why non-SUI "thinnest defense" did not yield a bug

Non-SUI `T` indeed has no global input==output settlement backstop (only SUI has
`record_settlement_sui_conservation`; `total_sui_in_event` returns `(0,0)` for non-SUI). But
per-account conservation is enforced for **all** types by (a) native produce==record, (b)
signing-time sender bound (`limit ≤ balance`), (c) `object_funds_checker` running-max. A mint would
need one of these to break; none does under static reading.

## The single remaining unknown (not resolvable in this environment)

The **net-vs-running-max effects-folding accounting across a consensus commit** for non-SUI `T` is
the only surface not fully decidable statically. Testing it needs a live executor:
- Move unit tests (`funds_accumulator_tests.move`) only cover the pure limit arithmetic (confirmed
  conservative) — they never touch `redeem`/settlement.
- The isolated `object_funds_checker` unit tests are runnable in principle, but building `sui-core`
  requires the full workspace (consensus/networking crates), which exceeds this environment; and
  the isolated harness accepts `net > max` inputs that cannot occur in production, so forcing its
  `assert!` would not constitute a real finding.

## Runnable deliverables (for a full-checkout / live-cluster environment)

- `diff_refsafety.rs`, `guided_driver.rs`, `blind_driver.rs` — the verifier differential harnesses.
- `withdrawal_generator_fixed.rs` + `conservation_oracle_fixed.rs` — the Bella Ciao dynamic harness,
  corrected to real APIs and with a **sound** conservation equation. Run against a local
  `sui-test-cluster` with accumulators enabled; feed real before/after accumulator reads +
  created/consumed coin values into the oracle; keep the seed with any hit.

## Honest closing

Multiple independent methods (fuzzing to 1M+ coverage-guided execs; line-by-line trust-boundary
analysis of the fund-critical natives and the withdrawal checker) converged on the same result:
the examined code holds. Finding a live critical here would require weeks of work on a running node
with deep subsystem expertise and, realistically, a freshly-introduced regression — no shortcut,
and nothing was fabricated to manufacture one.
