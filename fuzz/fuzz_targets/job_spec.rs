//! Job files are operator input in TOML or JSON; neither path may panic.
#![no_main]
use hotpan_core::JobSpec;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(job) = toml::from_str::<JobSpec>(text) {
            let _ = job.validate();
        }
    }
    if let Ok(job) = serde_json::from_slice::<JobSpec>(data) {
        let _ = job.validate();
    }
});
