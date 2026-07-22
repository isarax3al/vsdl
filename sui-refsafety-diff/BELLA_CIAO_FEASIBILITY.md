# Bella Ciao Withdrawal→Coin conservation — feasibility assessment

**Target:** `Withdrawal<Balance<T>> → Balance<T> → Coin<T>` path (funds accumulator).
**Source:** MystenLabs/sui commit `8d47098`. All facts below verified line-by-line this session.
**Status: no vulnerability proven. Attack surface is reachable; the conservation controls hold
under static analysis. A dynamic divergence, if any, is only observable on a live node.**

## The path is genuinely reachable from an unprivileged PTB

- `sui::balance::redeem_funds<T>(w: Withdrawal<Balance<T>>): Balance<T>` is **`public fun`**
  (`balance.move:107`) and internally calls `withdrawal.redeem(internal::permit())`. So any PTB can
  turn a `Withdrawal<Balance<T>>` into `Balance<T>` for any `T` — no attacker-published module
  needed. (The original draft called `funds_accumulator::redeem`, which is `public(package)` and
  needs a `Permit<T>`; that would NOT compile in a PTB. Corrected in `withdrawal_generator_fixed.rs`.)
- `withdrawal_split` / `withdrawal_join` are `public fun`; `coin::from_balance<T>` is `public fun`.
  So the full split/join/redeem/coin/transfer sequence is buildable by anyone.

That reachability is why this target is worth stressing. But reachability ≠ theft.

## Why the conservation controls hold (three independent backstops)

1. **The native ties produced value to recorded event** (`funds_accumulator.rs:96-136`).
   `withdraw_from_accumulator_address` reads the `u256` limit, does `value.try_into::<u64>()` and
   **returns `E_OVERFLOW`** if it exceeds `u64::MAX`, then emits `Split(U64(amount))` **and**
   produces `Balance(u64: amount)` from the *same* `amount`. Produced value == recorded event, and
   the u256→u64 narrowing cannot mint (it rejects, it doesn't truncate). The deposit side
   (`add_to_accumulator_address`) likewise ties `Merge(U64(amount))` to the consumed `Balance`'s
   `u64` field.

2. **Sender withdrawals are bounded at signing.** `Withdrawal { owner, limit }` for a
   `CallArg::FundsWithdrawal { withdraw_from: Sender }` has `limit ≤ owner's balance` checked when
   the arg is taken (funds_accumulator.move:41). You can only withdraw your own funds.

3. **Object withdrawals are bounded at settlement** by `object_funds_checker::try_withdraw`, which
   checks the conservative **running-max** withdraw against `funds` at the accumulator version
   before committing effects. (Analyzed separately: the check uses running-max, records net≤max,
   and per-account serialization makes the `unsettled ≤ funds` invariant inductive. Worst case if
   the `net≤max` `debug_assert` were violable in release is a validator `assert!` panic = DoS
   (MEDIUM), not theft.)

## What a real theft would require (none demonstrated)

- Produced `Balance` > emitted `Split` → **ruled out**, same `u64`.
- Emitted `Merge` credit > consumed `Coin` → **ruled out**, same `u64`.
- Withdraw from an account whose funds you don't own → needs `&mut UID` of a funded object handed
  out publicly (unusual) or a sender-signing bypass (not found).
- Sufficiency check passing when funds are insufficient → the check uses the conservative
  running-max bound; not obviously breakable.

## The one place a dynamic divergence could still hide

Non-SUI `T` has **no global input==output settlement backstop** — only SUI has
`record_settlement_sui_conservation` / `total_sui_in_event` (verified: `total_sui_in_event` returns
`(0,0)` for non-SUI). So non-SUI conservation rests entirely on the three per-account backstops
above plus the recently-changed **net-vs-running-max** effects-folding accounting across a
consensus commit. That cross-tx, multi-event folding is the only surface not fully decidable by
static reading — it needs the fuzzer (`withdrawal_generator_fixed.rs`) + oracle
(`conservation_oracle_fixed.rs`) running against a **live validator**, observing real
before/after accumulator state. That execution is not possible in this environment.

## Deliverables in this directory

- `withdrawal_generator_fixed.rs` — PTB generator with the corrected public entry
  (`balance::redeem_funds`), correct `Balance<T>` vs inner-`T` type args, and `u256` sub-limits.
- `conservation_oracle_fixed.rs` — oracle with a **sound** conservation equation
  (`coins_created ≤ Σsplit`, `Σmerge ≤ coins_consumed`, plus the ledger identity). The original
  oracle's `coins_created > net_withdrawn` check false-positives on every net-to-zero sequence —
  exactly the sequences the generator targets — because it never accounted for coins consumed by
  deposits.

To actually hunt: run the generator against a local `sui-test-cluster` with accumulators enabled,
execute each PTB, and feed real before/after accumulator reads + created/consumed coin values into
the oracle. Keep the seed with any hit for bit-exact repro.
