//! Conservation oracle for the Bella Ciao Withdrawal<T> -> Coin<T> path — CORRECTED.
//!
//! Authorized HackenProof research. ORACLE only: no tx generation, no I/O. Feed it the
//! before/after accumulator state, the emitted accumulator events, and the coins the tx
//! produced/consumed; it reports value-conservation violations (mints, double refunds).
//!
//! WHAT CHANGED vs the original draft (verified against real source, commit 8d47098):
//!
//! 1. IMPORT PATHS FIXED. AccumulatorOperation / AccumulatorValue / AccumulatorWriteV1 live in
//!    `sui_types::effects` (module `effects::object_change`), NOT `accumulator_event`.
//!    AccumulatorEvent { accumulator_obj: AccumulatorObjId, write: AccumulatorWriteV1 } and
//!    AccumulatorWriteV1 { address, operation, value: AccumulatorValue::Integer(u64) } confirmed.
//!    AccumulatorObjId.inner() -> &ObjectID confirmed.
//!
//! 2. THE MINT CHECK WAS UNSOUND (false-positive machine). The original compared
//!    `coins_created > net_withdrawn` where net_withdrawn = max(0, splits - merges). That flags
//!    EVERY net-to-zero sequence — withdraw 10 (Split, mints Coin 10) then deposit 10 (Merge) has
//!    net 0 but created 10 -> spurious "Mint", even though a Coin worth 10 was CONSUMED by the
//!    deposit. Those net-to-zero sequences are exactly what the generator targets, so the original
//!    oracle would drown the real signal in false positives.
//!
//!    Correct conservation is per gross flow, not net:
//!      - each Split event mints a Coin -> `coins_created[acc]` must equal Σ Split amounts.
//!        `coins_created > Σsplit`  => value minted out of thin air (MINT).
//!      - each Merge event credits the account -> must be backed by a consumed Coin.
//!        `Σmerge > coins_consumed[acc]` => balance credited with no coin behind it (MINT).
//!    Plus the ledger identity `after == before + Σmerge - Σsplit` (kept from the original — it was
//!    the one sound check).
//!
//! 3. GROUNDED IN THE REAL NATIVE (funds_accumulator.rs:96-136): withdraw_from_accumulator_address
//!    produces `Balance(amount:u64)` AND emits `Split(U64(amount))` from the SAME u64, and rejects
//!    u256->u64 overflow with E_OVERFLOW. So a static mint (produce != record) is NOT present in
//!    that native; this oracle's value is catching a DYNAMIC divergence at settlement/effects-fold
//!    time on a live node — which is the only place left for one to hide.

use std::collections::{BTreeMap, BTreeSet};

use sui_types::accumulator_event::AccumulatorEvent;
use sui_types::effects::{AccumulatorOperation, AccumulatorValue};
use sui_types::base_types::ObjectID;

/// A single conservation check unit for one executed transaction.
pub struct TxObservation {
    /// Accumulator balances immediately BEFORE the tx, keyed by accumulator obj id.
    pub balance_before: BTreeMap<ObjectID, u128>,
    /// Accumulator balances immediately AFTER settlement of the tx.
    pub balance_after: BTreeMap<ObjectID, u128>,
    /// The accumulator events the tx emitted (Split/Merge with amounts).
    pub events: Vec<AccumulatorEvent>,
    /// Value of Coin<T> objects CREATED by the tx (withdraw -> coin handed out), per acc obj id.
    pub coins_created: BTreeMap<ObjectID, u128>,
    /// Value of Coin<T> objects CONSUMED by the tx (deposited back into an accumulator), per acc.
    /// REQUIRED for soundness: a Merge must be backed by a consumed coin of equal value.
    pub coins_consumed: BTreeMap<ObjectID, u128>,
    /// For the compat path: per reservation, (reserved, redeemed, refunded).
    pub reservations: Vec<Reservation>,
    /// True if this accumulator/type is SUI (has the extra settlement conservation backstop).
    pub is_sui: bool,
}

pub struct Reservation {
    pub acc: ObjectID,
    pub reserved: u128,
    pub redeemed: u128,
    pub refunded: u128,
}

#[derive(Debug)]
pub enum Violation {
    /// after != before + Σmerge - Σsplit: the ledger and the effects disagree.
    BalanceDelta { acc: ObjectID, before: u128, after: u128, net_events: i128 },
    /// Coins handed out exceed gross Split withdrawals: value minted on the withdraw side.
    MintOnWithdraw { acc: ObjectID, coins_created: u128, gross_split: u128 },
    /// Gross Merge credit exceeds coins actually consumed: balance minted on the deposit side.
    MintOnDeposit { acc: ObjectID, gross_merge: u128, coins_consumed: u128 },
    /// refunded more than was left unused: a double refund.
    DoubleRefund { acc: ObjectID, reserved: u128, redeemed: u128, refunded: u128 },
}

/// Returns every conservation violation for one transaction. Empty == clean.
pub fn check(obs: &TxObservation) -> Vec<Violation> {
    let mut out = vec![];

    // Gross Split / Merge totals per accumulator, plus signed net for the ledger identity.
    let mut gross_split: BTreeMap<ObjectID, u128> = BTreeMap::new();
    let mut gross_merge: BTreeMap<ObjectID, u128> = BTreeMap::new();
    let mut net: BTreeMap<ObjectID, i128> = BTreeMap::new();
    for ev in &obs.events {
        let acc = *ev.accumulator_obj.inner();
        let amount = amount_of(ev);
        match ev.write.operation {
            AccumulatorOperation::Merge => {
                *gross_merge.entry(acc).or_insert(0) += amount;
                *net.entry(acc).or_insert(0) += amount as i128;
            }
            AccumulatorOperation::Split => {
                *gross_split.entry(acc).or_insert(0) += amount;
                *net.entry(acc).or_insert(0) -= amount as i128;
            }
        }
    }

    let accs: BTreeSet<ObjectID> = obs
        .balance_before
        .keys()
        .chain(obs.balance_after.keys())
        .chain(net.keys())
        .chain(obs.coins_created.keys())
        .chain(obs.coins_consumed.keys())
        .copied()
        .collect();

    for acc in accs {
        // (1) Ledger identity: state moves exactly by the net of the events.
        let before = *obs.balance_before.get(&acc).unwrap_or(&0);
        let after = *obs.balance_after.get(&acc).unwrap_or(&0);
        let net_events = net.get(&acc).copied().unwrap_or(0);
        if (before as i128) + net_events != (after as i128) {
            out.push(Violation::BalanceDelta { acc, before, after, net_events });
        }

        // (2) Withdraw side: coins handed out must not exceed gross withdrawals.
        let created = obs.coins_created.get(&acc).copied().unwrap_or(0);
        let gsplit = gross_split.get(&acc).copied().unwrap_or(0);
        if created > gsplit {
            out.push(Violation::MintOnWithdraw { acc, coins_created: created, gross_split: gsplit });
        }

        // (3) Deposit side: account credit must be backed by a consumed coin.
        let gmerge = gross_merge.get(&acc).copied().unwrap_or(0);
        let consumed = obs.coins_consumed.get(&acc).copied().unwrap_or(0);
        if gmerge > consumed {
            out.push(Violation::MintOnDeposit { acc, gross_merge: gmerge, coins_consumed: consumed });
        }
    }

    // (4) Compat refund: refunded <= reserved - redeemed, always.
    for r in &obs.reservations {
        let usable_refund = r.reserved.saturating_sub(r.redeemed);
        if r.refunded > usable_refund {
            out.push(Violation::DoubleRefund {
                acc: r.acc,
                reserved: r.reserved,
                redeemed: r.redeemed,
                refunded: r.refunded,
            });
        }
    }

    out
}

/// AccumulatorValue::Integer(u64) is the balance-path shape; the tuple/digest shapes never appear
/// on this path (settlement `fatal!`s on them), so treating them as 0 here is a defensive no-op.
fn amount_of(ev: &AccumulatorEvent) -> u128 {
    match &ev.write.value {
        AccumulatorValue::Integer(a) => *a as u128,
        _ => 0,
    }
}
