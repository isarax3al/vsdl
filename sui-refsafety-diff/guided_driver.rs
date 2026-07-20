// Guided differential generator: builds a rich borrow environment (struct with fields, a helper
// fn taking two &mut, several typed locals) and emits sequences drawn from a curated,
// borrow-relevant opcode alphabet with in-range indices. This raises the valid-module yield by
// orders of magnitude vs blind arbitrary and concentrates on the patterns where a path-based
// analysis (regex) can diverge from a graph-based one (multi-level field paths, double &mut to the
// same local passed to a 2-arg call, branch-join borrow merges).
//
// Reports candidate-P: regex ACCEPTS && graph REJECTS (the direction the in-tree consistency
// check at code_unit_verifier.rs:262 does NOT reject).
//
// Usage: guided_driver [iterations] [seed]
use std::collections::HashMap;
use std::str::FromStr;

use move_binary_format::file_format::{
    AbilitySet, Bytecode, CodeUnit, DatatypeHandle, DatatypeHandleIndex, EnumDefinition,
    EnumDefinitionIndex, FieldDefinition, FieldHandle, FieldHandleIndex, FunctionDefinition,
    FunctionDefinitionIndex, FunctionHandle, FunctionHandleIndex, IdentifierIndex, ModuleHandleIndex,
    Signature, SignatureIndex, SignatureToken, StructDefinition, StructFieldInformation,
    TypeSignature, VariantDefinition, VariantHandle, VariantHandleIndex, Visibility, empty_module,
};
use move_bytecode_verifier::absint::FunctionContext;
use move_bytecode_verifier_meter::dummy::DummyMeter;
use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use move_vm_config::verifier::VerifierConfig;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// Build the fixed module scaffold: struct S { f0: u64, f1: u64 }, helper fn g(&mut S, &mut S),
// and the fuzzed target fn f() with `locals`.
fn build_module(code: Vec<Bytecode>, locals: Vec<SignatureToken>) -> move_binary_format::file_format::CompiledModule {
    let mut m = empty_module();
    m.version = 7;

    // datatype handle 0 = struct S, 1 = enum E (copy+drop+store so values are freely droppable)
    let cds = AbilitySet::EMPTY | move_binary_format::file_format::Ability::Copy
        | move_binary_format::file_format::Ability::Drop
        | move_binary_format::file_format::Ability::Store;
    m.datatype_handles.push(DatatypeHandle {
        module: ModuleHandleIndex(0), name: IdentifierIndex(1), abilities: cds, type_parameters: vec![],
    });
    m.datatype_handles.push(DatatypeHandle {
        module: ModuleHandleIndex(0), name: IdentifierIndex(6), abilities: cds, type_parameters: vec![],
    });

    // identifiers: 0=DUMMY(module). 1=S 2=f 3=g 4=f0 5=f1 6=E 7=V0 8=V1 9=e0 10=e1 11=e2
    m.identifiers.extend(
        ["S", "f", "g", "f0", "f1", "E", "V0", "V1", "e0", "e1", "e2"]
            .into_iter().map(|s| Identifier::from_str(s).unwrap()),
    );
    m.address_identifiers.push(AccountAddress::random());

    // struct S with two u64 fields
    m.struct_defs.push(StructDefinition {
        struct_handle: DatatypeHandleIndex(0),
        field_information: StructFieldInformation::Declared(vec![
            FieldDefinition { name: IdentifierIndex::new(4), signature: TypeSignature(SignatureToken::U64) },
            FieldDefinition { name: IdentifierIndex::new(5), signature: TypeSignature(SignatureToken::U64) },
        ]),
    });

    // enum E { V0 { e0: u64 }, V1 { e1: u64, e2: u64 } }
    m.enum_defs.push(EnumDefinition {
        enum_handle: DatatypeHandleIndex(1),
        variants: vec![
            VariantDefinition {
                variant_name: IdentifierIndex::new(7),
                fields: vec![FieldDefinition { name: IdentifierIndex::new(9), signature: TypeSignature(SignatureToken::U64) }],
            },
            VariantDefinition {
                variant_name: IdentifierIndex::new(8),
                fields: vec![
                    FieldDefinition { name: IdentifierIndex::new(10), signature: TypeSignature(SignatureToken::U64) },
                    FieldDefinition { name: IdentifierIndex::new(11), signature: TypeSignature(SignatureToken::U64) },
                ],
            },
        ],
    });
    // variant handles: 0 -> E::V0, 1 -> E::V1
    m.variant_handles.push(VariantHandle { enum_def: EnumDefinitionIndex(0), variant: 0 });
    m.variant_handles.push(VariantHandle { enum_def: EnumDefinitionIndex(0), variant: 1 });

    // field handles: 0 -> S.f0, 1 -> S.f1
    m.field_handles.push(FieldHandle { owner: move_binary_format::file_format::StructDefinitionIndex(0), field: 0 });
    m.field_handles.push(FieldHandle { owner: move_binary_format::file_format::StructDefinitionIndex(0), field: 1 });

    // signatures (deduped — Move forbids duplicate signature-pool entries):
    //  0 = empty (reused for all empty sigs), 1 = target locals, 2 = helper g params (&mut S,&mut S)
    m.signatures.clear();
    m.signatures.push(Signature(vec![])); // 0 empty
    m.signatures.push(Signature(locals)); // 1 locals of f
    let smut = || SignatureToken::MutableReference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(0))));
    m.signatures.push(Signature(vec![smut(), smut()])); // 2 g params

    // function handles: 0 = f (()->()), 1 = g ((&mut S,&mut S)->())
    m.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0), name: IdentifierIndex(2),
        parameters: SignatureIndex(0), return_: SignatureIndex(0), type_parameters: vec![],
    });
    m.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0), name: IdentifierIndex(3),
        parameters: SignatureIndex(2), return_: SignatureIndex(0), type_parameters: vec![],
    });

    // fn f (fuzzed body), locals = sig 1
    m.function_defs.push(FunctionDefinition {
        code: Some(CodeUnit { code, locals: SignatureIndex(1), jump_tables: vec![] }),
        function: FunctionHandleIndex(0), visibility: Visibility::Public, is_entry: false,
        acquires_global_resources: vec![],
    });
    // fn g: must consume its two &mut params to satisfy reference safety; pop+drop via a body that
    // moves them out. Simplest valid body: MoveLoc(0);Pop... but references aren't droppable by Pop.
    // Instead read both then return. Locals = the two params (sig 2), no extra locals.
    m.function_defs.push(FunctionDefinition {
        code: Some(CodeUnit {
            code: vec![
                Bytecode::MoveLoc(0), Bytecode::ReadRef, Bytecode::Pop,
                Bytecode::MoveLoc(1), Bytecode::ReadRef, Bytecode::Pop,
                Bytecode::Ret,
            ],
            locals: SignatureIndex(0),
            jump_tables: vec![],
        }),
        function: FunctionHandleIndex(1), visibility: Visibility::Public, is_entry: false,
        acquires_global_resources: vec![],
    });
    m
}

fn gen_code(rng: &mut Rng, num_locals: u8) -> Vec<Bytecode> {
    let len = 2 + rng.below(22) as usize;
    let mut code = Vec::with_capacity(len + 2);
    for _ in 0..len {
        let l = (rng.below(num_locals as u64)) as u8;
        let f = FieldHandleIndex(rng.below(2) as u16);
        let v = VariantHandleIndex(rng.below(2) as u16);
        let pick = rng.below(22);
        let bc = match pick {
            0 => Bytecode::MutBorrowLoc(l),
            1 => Bytecode::ImmBorrowLoc(l),
            2 => Bytecode::MutBorrowField(f),
            3 => Bytecode::ImmBorrowField(f),
            4 => Bytecode::CopyLoc(l),
            5 => Bytecode::MoveLoc(l),
            6 => Bytecode::StLoc(l),
            7 => Bytecode::ReadRef,
            8 => Bytecode::WriteRef,
            9 => Bytecode::FreezeRef,
            10 => Bytecode::Pop,
            11 => Bytecode::LdU64(rng.next()),
            12 => Bytecode::Call(FunctionHandleIndex(1)), // g(&mut S, &mut S)
            13 => Bytecode::Branch((rng.below((len as u64).max(1))) as u16),
            14 => Bytecode::BrTrue((rng.below((len as u64).max(1))) as u16),
            // enum/variant paths (flagged least-covered)
            15 => Bytecode::UnpackVariantMutRef(v),
            16 => Bytecode::UnpackVariantImmRef(v),
            17 => Bytecode::UnpackVariant(v),
            18 => Bytecode::PackVariant(v),
            19 => Bytecode::ImmBorrowField(f),
            20 => Bytecode::MutBorrowField(f),
            _ => Bytecode::Nop,
        };
        code.push(bc);
    }
    code.push(Bytecode::Ret);
    code
}

fn main() {
    let iters: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5_000_000);
    let seed: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(0xABCDEF);
    let mut rng = Rng(seed | 1);
    let config = VerifierConfig::default();

    // locals: mix of struct S, &mut S, &S, u64 — indices 0..num_locals
    let locals_template = vec![
        SignatureToken::Datatype(DatatypeHandleIndex(0)),                                            // 0: S
        SignatureToken::MutableReference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(0)))),// 1: &mut S
        SignatureToken::Reference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(0)))),       // 2: &S
        SignatureToken::U64,                                                                         // 3: u64
        SignatureToken::MutableReference(Box::new(SignatureToken::U64)),                             // 4: &mut u64
        SignatureToken::Datatype(DatatypeHandleIndex(1)),                                            // 5: E
        SignatureToken::MutableReference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(1)))),// 6: &mut E
        SignatureToken::Reference(Box::new(SignatureToken::Datatype(DatatypeHandleIndex(1)))),       // 7: &E
    ];
    let num_locals = locals_template.len() as u8;

    let (mut passed, mut cands) = (0u64, 0u64);
    let (mut compared, mut graph_rej, mut regex_rej, mut guarded_dir) = (0u64, 0u64, 0u64, 0u64);
    for i in 0..iters {
        let code = gen_code(&mut rng, num_locals);
        let module = build_module(code, locals_template.clone());
        // GATE: structural checks only (bounds/limits/dup/signature/instr/constants/friends/
        // ability/recursive/loops) — this stops BEFORE type/reference/locals safety, so modules
        // where the graph reference checker REJECTS are NOT filtered out (that's candidate-P).
        let mut ability_cache = move_bytecode_verifier::ability_cache::AbilityCache::new(&module);
        if move_bytecode_verifier::verifier::verify_module_with_config_metered_up_to_code_units(
            &config, &module, &mut ability_cache, &mut DummyMeter,
        ).is_err() {
            continue;
        }
        passed += 1;

        let mut ndm: HashMap<IdentifierIndex, FunctionDefinitionIndex> = HashMap::new();
        for (idx, fdef) in module.function_defs().iter().enumerate() {
            ndm.insert(module.function_handle_at(fdef.function).name, FunctionDefinitionIndex(idx as u16));
        }
        for (idx, fdef) in module.function_defs().iter().enumerate() {
            let Some(cu) = fdef.code.as_ref() else { continue };
            let fh = module.function_handle_at(fdef.function);
            let fctx = FunctionContext::new(&module, FunctionDefinitionIndex(idx as u16), cu, fh);
            // Mirror the real pipeline order: stack_usage -> type_safety -> locals_safety -> ref.
            // StackUsageVerifier guarantees no stack underflow; skipping it lets unbalanced inputs
            // reach the reference verifiers (graph uses .pop().unwrap() -> panic; regex -> Err).
            if move_bytecode_verifier::stack_usage_verifier::StackUsageVerifier::verify(&config, &module, &fctx, &mut DummyMeter).is_err() {
                continue;
            }
            // Only compare the two reference checkers on inputs that already pass both, otherwise
            // the reference verifiers face type-unsafe states they were never meant to handle
            // (spurious panics/errors that the real pipeline rejects earlier).
            let mut ac = move_bytecode_verifier::ability_cache::AbilityCache::new(&module);
            if move_bytecode_verifier::type_safety::verify(&config, &module, &fctx, &mut ac, &mut DummyMeter).is_err() {
                continue;
            }
            let mut ac2 = move_bytecode_verifier::ability_cache::AbilityCache::new(&module);
            if move_bytecode_verifier::locals_safety::verify(&module, &fctx, &mut ac2, &mut DummyMeter).is_err() {
                continue;
            }
            compared += 1;
            let graph = move_bytecode_verifier::reference_safety::verify(&config, &module, &fctx, &ndm, &mut DummyMeter);
            let regex = move_bytecode_verifier::regex_reference_safety::verify(&config, &module, &fctx, &mut DummyMeter);
            if graph.is_err() { graph_rej += 1; }
            if regex.is_err() { regex_rej += 1; }
            if graph.is_err() != regex.is_err() {
                // any disagreement (either direction) — track both
                if graph.is_ok() && regex.is_err() { guarded_dir += 1; }
            }
            if regex.is_ok() && graph.is_err() {
                cands += 1;
                let mut bytes = vec![];
                module.serialize(&mut bytes).unwrap();
                let path = format!("/tmp/refgap_{:016x}.mvb", fnv(&bytes));
                std::fs::write(&path, &bytes).ok();
                println!("CANDIDATE P @iter={i} fn#{idx}: regex=OK graph={:?} saved={path}",
                    graph.as_ref().err().map(|e| e.major_status()));
            }
        }
        if i % 1_000_000 == 0 && i > 0 { eprintln!("[{i}] passed={passed} candidates={cands}"); }
    }
    println!("DONE iters={iters} passed_bounds={passed} compared={compared} \
        graph_rej={graph_rej} regex_rej={regex_rej} guarded_dir(graph_ok&regex_rej)={guarded_dir} \
        CANDIDATE_P(regex_ok&graph_rej)={cands}");
}

fn fnv(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &x in b { h ^= x as u64; h = h.wrapping_mul(0x100000001b3); }
    h
}
