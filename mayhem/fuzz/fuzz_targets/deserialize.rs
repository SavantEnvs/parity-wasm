#![no_main]
// In-process libFuzzer harness over parity-wasm's binary deserializer, holding the
// SAME input interface as the historical mayhemheroes `deserialize` target this
// branch reproduces (mayhemheroes/parity-wasm @ 26b08eb, fuzz/fuzz_targets/deserialize.rs):
// the fuzzer's bytes are a seed for binaryen's module generator, not wasm. Binaryen
// emits a module it considers valid; parity-wasm must be able to read it back.
// Failing to do so is the defect the original run recorded (BACKPORT.md,
// "input-interface caveat" — the run-19 corpus is binaryen seeds, so a harness that
// parsed the raw bytes as wasm would reproduce nothing).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let binaryen_module = binaryen::tools::translate_to_fuzz(data);

    // enable binaryen's validation if in doubt.
    // assert!(binaryen_module.is_valid());

    let wasm = binaryen_module.write();

    let _module: parity_wasm::elements::Module = parity_wasm::deserialize_buffer(&wasm)
        .expect("deserialize output of wasm-opt, indicating possible bug in deserializer");
});
