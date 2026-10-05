//! The length-prefixed frame reader over arbitrary byte streams.
#![no_main]
use hotpan_wire::{read_frame, NodeMsg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let mut r = data;
        // Keep reading frames until the stream is exhausted or invalid.
        while read_frame::<_, NodeMsg>(&mut r).await.is_ok() {}
    });
});
