//! Service-name normalization never panics, is idempotent, and the phishing
//! checks accept anything it produces.
#![no_main]
use codepass::{crypto::normalize_site_v2, phishing};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(site) = std::str::from_utf8(data) else { return };
    let once = normalize_site_v2(site);
    assert_eq!(normalize_site_v2(&once), once, "input {site:?}");
    let _ = phishing::suspicious_parts(&once);
    assert!(phishing::lookalikes(&once, [once.as_str()]).is_empty(), "a name is never its own look-alike");
});
