#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz CLI argument parsing
        let _ = s.split_whitespace().collect::<Vec<_>>();
    }
});
