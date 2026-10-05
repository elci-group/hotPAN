//! Every message type a peer can send, parsed from arbitrary bytes, and any
//! advertisement or heartbeat that parses is run through validation.
#![no_main]
use hotpan_core::Limits;
use hotpan_wire::{ClientMsg, Hello, NodeMsg, Welcome};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let l = Limits::default();
    if let Ok(Hello::Node { advertisement, .. }) = serde_json::from_slice::<Hello>(data) {
        let _ = advertisement.validate(&l);
    }
    if let Ok(NodeMsg::Heartbeat { vector }) = serde_json::from_slice::<NodeMsg>(data) {
        let _ = vector.validate(&l);
    }
    if let Ok(ClientMsg::Submit { job }) = serde_json::from_slice::<ClientMsg>(data) {
        let _ = job.validate_with(&l);
    }
    let _ = serde_json::from_slice::<Welcome>(data);
});
