// Differential fuzz target: graph-based `reference_safety` vs `regex_reference_safety`.
//
// Drop into a libfuzzer fuzz crate that depends on `move-bytecode-verifier` and
// `move-binary-format`. All symbols used here were confirmed `pub` at commit 8d47098:
//   - move_bytecode_verifier::verify_module_unmetered            (verifier.rs:40)
//   - move_bytecode_verifier::reference_safety::verify           (reference_safety/mod.rs:70)
//   - move_bytecode_verifier::regex_reference_safety::verify     (regex_reference_safety/mod.rs:67)
//   - move_bytecode_verifier::absint::FunctionContext::new       (absint.rs:91)
// No in-crate patch / test-only wrapper is required.
//
// Semantics of a hit (see FINDINGS.md): regex ACCEPTS ∧ graph REJECTS ("candidate P"). This is the
// direction the in-tree consistency check (code_unit_verifier.rs:262) does NOT reject. It is a
// LATENT concern only — not currently exploitable, because the graph checker is authoritative in
// the default config and it rejected the module. Triage every hit with Template ج before believing
// it is anything.
#![no_main]

use std::collections::HashMap;

use libfuzzer_sys::fuzz_target;
use move_binary_format::file_format::{
    CompiledModule, FunctionDefinitionIndex, IdentifierIndex,
};
use move_bytecode_verifier::absint::FunctionContext;
use move_bytecode_verifier_meter::dummy::DummyMeter; // zero-cost meter (verifier.rs:26)
use move_vm_config::verifier::VerifierConfig;

fuzz_target!(|module: CompiledModule| {
    // Only consider modules that pass the cheap structural/bounds checks; otherwise both checkers
    // reject for unrelated reasons and any "divergence" is noise.
    if move_bytecode_verifier::verify_module_unmetered(&module).is_err() {
        return;
    }

    let config = VerifierConfig::default();

    // Rebuild name_def_map exactly as code_unit_verifier.rs:73-76 does.
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
            &config,
            &module,
            &fctx,
            &name_def_map,
            &mut DummyMeter,
        );
        let regex = move_bytecode_verifier::regex_reference_safety::verify(
            &config,
            &module,
            &fctx,
            &mut DummyMeter,
        );

        // Candidate P: the unguarded direction. regex accepts, graph rejects.
        if regex.is_ok() && graph.is_err() {
            let mut bytes = vec![];
            module.serialize(&mut bytes).expect("serialize");
            let name = format!(
                "refgap_{:016x}.mvb",
                seahash_like(&bytes)
            );
            let _ = std::fs::write(std::path::Path::new("/tmp").join(&name), &bytes);
            panic!(
                "candidate P (LATENT, not a confirmed vuln): fn#{idx} regex=OK graph={:?} -> {name}",
                graph.as_ref().err().map(|e| e.major_status())
            );
        }
    }
});

// Tiny non-cryptographic hash just to name corpus files distinctly; correctness not security-relevant.
fn seahash_like(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
