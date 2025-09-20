#![no_main]
use libfuzzer_sys::fuzz_target;
use chhaya::decode_resp_ok;

fuzz_target!(|data: &[u8]| {
    let _ = decode_resp_ok(data);
});
