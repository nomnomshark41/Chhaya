#![no_main]
use libfuzzer_sys::fuzz_target;
use chhaya::decode_label_hash;

fuzz_target!(|data: &[u8]| {
    let _ = decode_label_hash(data, b"INIT-OK");
});
