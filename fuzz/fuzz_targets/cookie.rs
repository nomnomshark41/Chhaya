#![no_main]
use libfuzzer_sys::fuzz_target;
use chhaya::decode_retry_cookie;

fuzz_target!(|data: &[u8]| {
    let _ = decode_retry_cookie(data);
});
