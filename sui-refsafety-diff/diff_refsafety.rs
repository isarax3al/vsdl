// Coverage-guided differential target: graph reference_safety vs regex_reference_safety.
// libfuzzer mutates `code` with coverage feedback; we build a fixed rich scaffold (struct S,
// enum E, helper g(&mut S,&mut S), 8 typed locals) and gate each function through the real
// per-function pipeline order (stack_usage -> type_safety -> locals_safety) before comparing the
// two reference checkers. Panics on candidate-P: regex ACCEPTS && graph REJECTS.
//
// Requires the local `pub` exposures in move-bytecode-verifier: type_safety, locals_safety,
// stack_usage_verifier, ability_cache (already pub), reference_safety, regex_reference_safety.
#![no_main]
use std::collections::HashMap;
use std::str::FromStr;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use move_binary_format::file_format::{
    Ability, AbilitySet, Bytecode, CodeUnit, DatatypeHandle, DatatypeHandleIndex, EnumDefinition,
    EnumDefinitionIndex, FieldDefinition, FieldHandle, FunctionDefinition, FunctionDefinitionIndex,
    FunctionHandle, FunctionHandleIndex, IdentifierIndex, ModuleHandleIndex, Signature,
    SignatureIndex, SignatureToken, StructDefinition, StructDefinitionIndex, StructFieldInformation,
    TypeSignature, VariantDefinition, VariantHandle, Visibility, empty_module,
};
use move_binary_format::errors::{PartialVMError, PartialVMResult};
use move_bytecode_verifier_meter::dummy::DummyMeter;
use move_core_types::vm_status::StatusCode;
use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use move_vm_config::verifier::VerifierConfig;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;

#[derive(Arbitrary, Debug)]
struct In {
    code: Vec<Bytecode>,
}

// Production-faithful: under cargo-fuzz, debug_assertions are ON, so safe_assert!/safe_unwrap! in
// the verifier PANIC where a release build would `return Err(..)`. We run each stage under
// catch_unwind and map a panic to that same Err, so the differential reflects RELEASE behavior.
// Only a genuine candidate-P (regex accepts, graph rejects/panics) is surfaced as a crash.
static SILENCE: Once = Once::new();
fn silence_panics() {
    SILENCE.call_once(|| {
        std::panic::set_hook(Box::new(|_| {}));
    });
}
// true iff f runs without panicking AND returns Ok. A debug-only panic (safe_assert/safe_unwrap)
// is folded into "not ok", matching release behavior where those return Err.
fn ok<T, E>(f: impl FnOnce() -> Result<T, E>) -> bool {
    matches!(catch_unwind(AssertUnwindSafe(f)), Ok(Ok(_)))
}

fn locals() -> Vec<SignatureToken> {
    let s = || SignatureToken::Datatype(DatatypeHandleIndex(0));
    let e = || SignatureToken::Datatype(DatatypeHandleIndex(1));
    vec![
        s(),
        SignatureToken::MutableReference(Box::new(s())),
        SignatureToken::Reference(Box::new(s())),
        SignatureToken::U64,
        SignatureToken::MutableReference(Box::new(SignatureToken::U64)),
        e(),
        SignatureToken::MutableReference(Box::new(e())),
        SignatureToken::Reference(Box::new(e())),
    ]
}

fn build(code: Vec<Bytecode>) -> move_binary_format::file_format::CompiledModule {
    let mut m = empty_module();
    m.version = 7;
    let cds = AbilitySet::EMPTY | Ability::Copy | Ability::Drop | Ability::Store;
    m.datatype_handles.push(DatatypeHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(1), abilities: cds, type_parameters: vec![] });
    m.datatype_handles.push(DatatypeHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(6), abilities: cds, type_parameters: vec![] });
    m.identifiers.extend(
        ["S", "f", "g", "f0", "f1", "E", "V0", "V1", "e0", "e1", "e2"]
            .into_iter().map(|s| Identifier::from_str(s).unwrap()),
    );
    m.address_identifiers.push(AccountAddress::random());
    m.struct_defs.push(StructDefinition {
        struct_handle: DatatypeHandleIndex(0),
        field_information: StructFieldInformation::Declared(vec![
            FieldDefinition { name: IdentifierIndex::new(4), signature: TypeSignature(SignatureToken::U64) },
            FieldDefinition { name: IdentifierIndex::new(5), signature: TypeSignature(SignatureToken::U64) },
        ]),
    });
    m.enum_defs.push(EnumDefinition {
        enum_handle: DatatypeHandleIndex(1),
        variants: vec![
            VariantDefinition { variant_name: IdentifierIndex::new(7), fields: vec![FieldDefinition { name: IdentifierIndex::new(9), signature: TypeSignature(SignatureToken::U64) }] },
            VariantDefinition { variant_name: IdentifierIndex::new(8), fields: vec![
                FieldDefinition { name: IdentifierIndex::new(10), signature: TypeSignature(SignatureToken::U64) },
                FieldDefinition { name: IdentifierIndex::new(11), signature: TypeSignature(SignatureToken::U64) },
            ] },
        ],
    });
    m.variant_handles.push(VariantHandle { enum_def: EnumDefinitionIndex(0), variant: 0 });
    m.variant_handles.push(VariantHandle { enum_def: EnumDefinitionIndex(0), variant: 1 });
    m.field_handles.push(FieldHandle { owner: StructDefinitionIndex(0), field: 0 });
    m.field_handles.push(FieldHandle { owner: StructDefinitionIndex(0), field: 1 });

    m.signatures.clear();
    m.signatures.push(Signature(vec![]));       // 0 empty
    m.signatures.push(Signature(locals()));     // 1 f locals
    let smut = || SignatureToken::MutableReference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(0))));
    m.signatures.push(Signature(vec![smut(), smut()])); // 2 g params

    m.function_handles.push(FunctionHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(2), parameters: SignatureIndex(0), return_: SignatureIndex(0), type_parameters: vec![] });
    m.function_handles.push(FunctionHandle { module: ModuleHandleIndex(0), name: IdentifierIndex(3), parameters: SignatureIndex(2), return_: SignatureIndex(0), type_parameters: vec![] });

    m.function_defs.push(FunctionDefinition {
        code: Some(CodeUnit { code, locals: SignatureIndex(1), jump_tables: vec![] }),
        function: FunctionHandleIndex(0), visibility: Visibility::Public, is_entry: false, acquires_global_resources: vec![],
    });
    m.function_defs.push(FunctionDefinition {
        code: Some(CodeUnit { code: vec![Bytecode::MoveLoc(0), Bytecode::ReadRef, Bytecode::Pop, Bytecode::MoveLoc(1), Bytecode::ReadRef, Bytecode::Pop, Bytecode::Ret], locals: SignatureIndex(0), jump_tables: vec![] }),
        function: FunctionHandleIndex(1), visibility: Visibility::Public, is_entry: false, acquires_global_resources: vec![],
    });
    m
}

fuzz_target!(|input: In| {
    silence_panics();
    let mut code = input.code;
    code.push(Bytecode::Ret);
    let module = build(code);
    let config = VerifierConfig::default();

    // structural gate — panic (debug safe_assert) mapped to "not ok" = release "reject".
    if !ok(|| {
        let mut ac = move_bytecode_verifier::ability_cache::AbilityCache::new(&module);
        move_bytecode_verifier::verifier::verify_module_with_config_metered_up_to_code_units(&config, &module, &mut ac, &mut DummyMeter)
    }) { return; }

    let mut ndm: HashMap<IdentifierIndex, FunctionDefinitionIndex> = HashMap::new();
    for (idx, fdef) in module.function_defs().iter().enumerate() {
        ndm.insert(module.function_handle_at(fdef.function).name, FunctionDefinitionIndex(idx as u16));
    }
    for (idx, fdef) in module.function_defs().iter().enumerate() {
        let Some(cu) = fdef.code.as_ref() else { continue };
        let fh = module.function_handle_at(fdef.function);
        let fctx = move_bytecode_verifier::absint::FunctionContext::new(&module, FunctionDefinitionIndex(idx as u16), cu, fh);
        // per-function pipeline order: stack_usage -> type_safety -> locals_safety (all caught)
        if !ok(|| move_bytecode_verifier::stack_usage_verifier::StackUsageVerifier::verify(&config, &module, &fctx, &mut DummyMeter)) { continue; }
        if !ok(|| { let mut a = move_bytecode_verifier::ability_cache::AbilityCache::new(&module); move_bytecode_verifier::type_safety::verify(&config, &module, &fctx, &mut a, &mut DummyMeter) }) { continue; }
        if !ok(|| { let mut a = move_bytecode_verifier::ability_cache::AbilityCache::new(&module); move_bytecode_verifier::locals_safety::verify(&module, &fctx, &mut a, &mut DummyMeter) }) { continue; }

        // graph panic (e.g. .pop().unwrap()) == release Err (gated behind stack usage anyway).
        let graph_ok = ok(|| move_bytecode_verifier::reference_safety::verify(&config, &module, &fctx, &ndm, &mut DummyMeter));
        let regex_ok = ok(|| move_bytecode_verifier::regex_reference_safety::verify(&config, &module, &fctx, &mut DummyMeter));
        if regex_ok && !graph_ok {
            let mut bytes = vec![];
            module.serialize(&mut bytes).unwrap();
            std::fs::write(format!("/tmp/refgap_fn{idx}.mvb"), &bytes).ok();
            // Bypass the silenced hook: report explicitly and abort so libfuzzer records it.
            eprintln!("CANDIDATE P: fn#{idx} regex=OK graph=REJECT/PANIC (production divergence)");
            std::process::abort();
        }
    }
});
