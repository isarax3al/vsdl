//! Stateful PTB generator for the Bella Ciao Withdrawal<Balance<T>> -> Coin<T> path — CORRECTED.
//!
//! Authorized HackenProof research. Deterministic: one u64 seed -> one PTB.
//!
//! CORRECTIONS vs the original draft (all verified against real source, commit 8d47098):
//!
//! 1. redeem is NOT PTB-callable as drafted. `funds_accumulator::redeem` is `public(package)` and
//!    needs an `internal::Permit<T>`. The real public entry is
//!        sui::balance::redeem_funds<T>(w: Withdrawal<Balance<T>>): Balance<T>   (balance.move:107)
//!    which internally does `withdrawal.redeem(internal::permit())`. It IS `public fun`, callable
//!    from any PTB for any T — so the surface is genuinely reachable (see FEASIBILITY notes).
//!
//! 2. TYPE PARAMETER SHAPE. The accumulator holds `Balance<T>` values. So:
//!      - the Withdrawal is `Withdrawal<Balance<T>>`;
//!      - `withdrawal_split` / `withdrawal_join` take type arg `Balance<T>` (the whole Balance);
//!      - `balance::redeem_funds` and `coin::from_balance` take the INNER type arg `T`.
//!    `FundsWithdrawalArg::balance_from_sender(amount, T)` already wraps to
//!    `WithdrawalTypeArg::Balance(T)` — pass the INNER T there.
//!
//! 3. sub_limit is `u256`, not `u64` (Withdrawal.limit: u256). Serialize the pure as u256.
//!
//! 4. `coin::from_balance<T>(Balance<T>, &mut TxContext)` — the TxContext is auto-injected by the
//!    PTB runtime; do not pass it as an argument.
//!
//! ADVERSARIAL INTENT unchanged: split / join / redeem / drop-refund sequences that NET TO ZERO or
//! oscillate, to stress the net-vs-running-max settlement accounting and the refund path, where a
//! "skip zero net" optimization (object_funds_checker filters Split(0)) could in principle leak.

use rand::Rng;
use rand::SeedableRng;
use rand_pcg::Pcg64;

use move_core_types::language_storage::{StructTag, TypeTag};
use sui_types::{
    Identifier, SUI_FRAMEWORK_PACKAGE_ID,
    base_types::SuiAddress,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{Argument, CallArg, FundsWithdrawalArg, ProgrammableTransaction},
};

#[derive(Clone, Debug)]
enum Op {
    Split(u8 /*src handle*/, u64 /*sub_limit, widened to u256*/),
    Join(u8 /*dst*/, u8 /*src*/),
    Redeem(u8 /*handle*/),
    DropRefund(u8 /*handle*/),
}

pub struct GeneratedCase {
    pub seed: u64,
    pub ptb: ProgrammableTransaction,
    pub note: String,
}

/// `inner_type` MUST be the INNER coin type T (e.g. `0x2::sui::SUI`, or better a non-SUI T for the
/// thinnest conservation defense). The accumulator/withdrawal is over `Balance<inner_type>`.
pub fn generate(
    seed: u64,
    owner: SuiAddress,
    inner_type: TypeTag,
    reservation: u64,
) -> GeneratedCase {
    let mut rng = Pcg64::seed_from_u64(seed);
    let plan = plan_ops(&mut rng, reservation);
    let note = format!(
        "{} ops, reservation={}, inner_type={:?}",
        plan.len(),
        reservation,
        inner_type
    );

    // `Balance<inner_type>` — the type arg for split/join.
    let balance_type = balance_type_tag(&inner_type);

    let mut b = ProgrammableTransactionBuilder::new();

    // Input 0: the root Withdrawal<Balance<inner_type>> (reservation/limit for `owner`).
    let root = b
        .input(CallArg::FundsWithdrawal(
            FundsWithdrawalArg::balance_from_sender(reservation, inner_type.clone()),
        ))
        .unwrap();

    let mut handles = vec![root];

    for op in &plan {
        match op {
            Op::Split(src, sub) => {
                if let Some(&src_arg) = handles.get(*src as usize) {
                    // sub_limit is u256.
                    let sub_arg = b.pure(*sub as u256).unwrap();
                    let new = move_call(
                        &mut b,
                        "funds_accumulator",
                        "withdrawal_split",
                        vec![balance_type.clone()],
                        vec![src_arg, sub_arg],
                    );
                    handles.push(new);
                }
            }
            Op::Join(dst, src) => {
                if let (Some(&d), Some(&s)) =
                    (handles.get(*dst as usize), handles.get(*src as usize))
                {
                    move_call(
                        &mut b,
                        "funds_accumulator",
                        "withdrawal_join",
                        vec![balance_type.clone()],
                        vec![d, s],
                    );
                }
            }
            Op::Redeem(h) => {
                if let Some(&arg) = handles.get(*h as usize) {
                    // redeem_funds<T>(Withdrawal<Balance<T>>) -> Balance<T>   [inner type arg T]
                    let bal = move_call(
                        &mut b,
                        "balance",
                        "redeem_funds",
                        vec![inner_type.clone()],
                        vec![arg],
                    );
                    // from_balance<T>(Balance<T>) -> Coin<T>   (TxContext auto-injected)
                    let coin = move_call(
                        &mut b,
                        "coin",
                        "from_balance",
                        vec![inner_type.clone()],
                        vec![bal],
                    );
                    b.transfer_arg(owner, coin);
                }
            }
            Op::DropRefund(_h) => { /* leaving a handle unredeemed exercises the refund path */ }
        }
    }

    GeneratedCase {
        seed,
        ptb: b.finish(),
        note,
    }
}

fn plan_ops(rng: &mut Pcg64, reservation: u64) -> Vec<Op> {
    let n = rng.gen_range(2..12);
    let mut plan = Vec::with_capacity(n);
    let mut live: u8 = 1; // handle 0 is the root
    for _ in 0..n {
        match rng.gen_range(0..4u8) {
            0 => {
                let src = rng.gen_range(0..live);
                let sub = rng.gen_range(0..=reservation);
                plan.push(Op::Split(src, sub));
                live = live.saturating_add(1);
            }
            1 if live >= 2 => {
                let dst = rng.gen_range(0..live);
                let mut src = rng.gen_range(0..live);
                if src == dst {
                    src = (src + 1) % live;
                }
                plan.push(Op::Join(dst, src));
            }
            2 => plan.push(Op::Redeem(rng.gen_range(0..live))),
            _ => plan.push(Op::DropRefund(rng.gen_range(0..live))),
        }
    }
    plan
}

/// Build the `0x2::balance::Balance<inner>` TypeTag.
fn balance_type_tag(inner: &TypeTag) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
        address: SUI_FRAMEWORK_PACKAGE_ID.into(),
        module: Identifier::new("balance").unwrap(),
        name: Identifier::new("Balance").unwrap(),
        type_params: vec![inner.clone()],
    }))
}

fn move_call(
    b: &mut ProgrammableTransactionBuilder,
    module: &str,
    function: &str,
    type_args: Vec<TypeTag>,
    args: Vec<Argument>,
) -> Argument {
    b.programmable_move_call(
        SUI_FRAMEWORK_PACKAGE_ID,
        Identifier::new(module).unwrap(),
        Identifier::new(function).unwrap(),
        type_args,
        args,
    )
}
