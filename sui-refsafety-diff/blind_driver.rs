// Differential driver: graph-based `reference_safety` vs `regex_reference_safety`.
// Stable-Rust poor-man's fuzzer: seed random bytes -> arbitrary -> build a scaffold module
// (mirrors crates/bytecode-verifier-libfuzzer/fuzz_targets/mixed.rs) -> run BOTH verifiers on the
// function context. Reports candidate-P divergences: regex ACCEPTS && graph REJECTS.
//
// Usage: diff_driver [iterations] [seed]
use std::collections::HashMap;
use std::str::FromStr;

use arbitrary::{Arbitrary, Unstructured};
use move_binary_format::file_format::{
    AbilitySet, Bytecode, CodeUnit, Constant, DatatypeHandle, DatatypeHandleIndex, FieldDefinition,
    FunctionDefinition, FunctionDefinitionIndex, FunctionHandle, FunctionHandleIndex,
    IdentifierIndex, ModuleHandleIndex, Signature, SignatureIndex, SignatureToken,
    SignatureToken::{Address, Bool},
    StructDefinition, StructFieldInformation, TypeSignature, Visibility, empty_module,
};
use move_bytecode_verifier::absint::FunctionContext;
use move_bytecode_verifier_meter::dummy::DummyMeter;
use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use move_vm_config::verifier::VerifierConfig;

#[derive(Arbitrary, Debug)]
struct Mixed {
    code: Vec<Bytecode>,
    abilities: AbilitySet,
    param_types: Vec<SignatureToken>,
    return_type: Option<SignatureToken>,
}

fn build_module(mix: Mixed) -> move_binary_format::file_format::CompiledModule {
    let mut module = empty_module();
    module.version = 5;
    module.datatype_handles.push(DatatypeHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(1),
        abilities: mix.abilities,
        type_parameters: vec![],
    });
    module.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(2),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(1),
        type_parameters: vec![],
    });
    module.signatures.pop();
    module.signatures.push(Signature(mix.param_types));
    module
        .signatures
        .push(Signature(mix.return_type.map(|s| vec![s]).unwrap_or_default()));
    module.signatures.push(Signature(vec![Address, Bool, Address]));
    module.identifiers.extend(
        [
            "zf_hello_world",
            "awldFnU18mlDKQfh6qNfBGx8X",
            "aQPwJNHyAHpvJ",
            "aT7ZphKTrKcYCwCebJySrmrKlckmnL5",
            "arYpsFa2fvrpPJ",
        ]
        .into_iter()
        .map(|s| Identifier::from_str(s).unwrap()),
    );
    module.address_identifiers.push(AccountAddress::random());
    module.constant_pool.push(Constant {
        type_: Address,
        data: AccountAddress::ZERO.into_bytes().to_vec(),
    });
    module.struct_defs.push(StructDefinition {
        struct_handle: DatatypeHandleIndex(0),
        field_information: StructFieldInformation::Declared(vec![FieldDefinition {
            name: IdentifierIndex::new(3),
            signature: TypeSignature(Address),
        }]),
    });
    module.function_defs.push(FunctionDefinition {
        code: Some(CodeUnit {
            code: mix.code,
            locals: SignatureIndex(0),
            jump_tables: vec![],
        }),
        function: FunctionHandleIndex(0),
        visibility: Visibility::Public,
        is_entry: false,
        acquires_global_resources: vec![],
    });
    module
}

fn main() {
    let iters: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(2_000_000);
    let mut state: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(0xC0FFEE);
    let config = VerifierConfig::default();
    let mut buf = vec![0u8; 512];
    let (mut passed_bounds, mut candidates) = (0u64, 0u64);

    for i in 0..iters {
        // xorshift64 -> fill buffer deterministically from seed
        for b in buf.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = (state & 0xff) as u8;
        }
        let mut u = Unstructured::new(&buf);
        let Ok(mix) = Mixed::arbitrary(&mut u) else { continue };
        let module = build_module(mix);

        // Only consider modules that clear cheap structural/bounds checks.
        if move_bytecode_verifier::verify_module_unmetered(&module).is_err() {
            continue;
        }
        passed_bounds += 1;

        let mut name_def_map: HashMap<IdentifierIndex, FunctionDefinitionIndex> = HashMap::new();
        for (idx, fdef) in module.function_defs().iter().enumerate() {
            let fh = module.function_handle_at(fdef.function);
            name_def_map.insert(fh.name, FunctionDefinitionIndex(idx as u16));
        }

        for (idx, fdef) in module.function_defs().iter().enumerate() {
            let Some(code) = fdef.code.as_ref() else { continue };
            let fh = module.function_handle_at(fdef.function);
            let fctx = FunctionContext::new(&module, FunctionDefinitionIndex(idx as u16), code, fh);

            let graph = move_bytecode_verifier::reference_safety::verify(
                &config, &module, &fctx, &name_def_map, &mut DummyMeter,
            );
            let regex = move_bytecode_verifier::regex_reference_safety::verify(
                &config, &module, &fctx, &mut DummyMeter,
            );
            if regex.is_ok() && graph.is_err() {
                candidates += 1;
                let mut bytes = vec![];
                module.serialize(&mut bytes).unwrap();
                let path = format!("/tmp/refgap_{:016x}.mvb", fnv(&bytes));
                std::fs::write(&path, &bytes).ok();
                println!(
                    "CANDIDATE P @iter={i} fn#{idx}: regex=OK graph={:?} saved={path}",
                    graph.as_ref().err().map(|e| e.major_status())
                );
            }
        }
        if i % 200_000 == 0 && i > 0 {
            eprintln!("[{i}] passed_bounds={passed_bounds} candidates={candidates}");
        }
    }
    println!(
        "DONE iters={iters} passed_bounds={passed_bounds} candidates={candidates}"
    );
}

fn fnv(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
