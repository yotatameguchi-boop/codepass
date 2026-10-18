//! A signed entry verifies, and flipping any single bit of the signed bytes or of
//! the signature makes it fail.
#![no_main]
use codepass::{
    crypto::{Charset, Settings},
    profile::{Entry, MacStatus},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 40 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let text = String::from_utf8_lossy(&data[40..]).into_owned();
    let mid = text.char_indices().nth(text.chars().count() / 2).map_or(text.len(), |(i, _)| i);
    let (site, account) = text.split_at(mid);
    let mut entry = Entry {
        source_sha256: hex::encode(&key),
        settings: Settings {
            site: site.to_string(),
            account: account.to_string(),
            length: 8 + (data[32] as usize % 57),
            charset: if data[33] & 1 == 0 { Charset::Strong } else { Charset::Alnum },
            revision: u32::from(data[34]) + 1,
            require_classes: data[35] & 1 == 0,
            spec_version: 2,
            symbols: None,
        },
        source_path: (data[36] & 1 == 0).then(|| format!("/k/{}", data[37])),
        git_commit: None,
        mac: None,
    };
    entry.sign(&key);
    assert!(matches!(entry.verify(&key), MacStatus::Valid));
    let mut other = key;
    other[usize::from(data[38]) % 32] ^= 1 << (data[39] % 8);
    assert!(matches!(entry.verify(&other), MacStatus::Invalid));
    let mut tag = hex::decode(entry.mac.as_ref().unwrap()).unwrap();
    tag[usize::from(data[38]) % 32] ^= 1 << (data[39] % 8);
    entry.mac = Some(hex::encode(tag));
    assert!(matches!(entry.verify(&key), MacStatus::Invalid));
});
