//! For any key, code hash and settings the generator accepts, the password has
//! exactly the requested length, only allowed characters, and every required class.
#![no_main]
use codepass::crypto::{canonical_symbols, derive_with_master, Charset, Settings};
use libfuzzer_sys::fuzz_target;

const DEFAULT_SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

fuzz_target!(|data: &[u8]| {
    if data.len() < 66 {
        return;
    }
    let master: [u8; 32] = data[..32].try_into().unwrap();
    let hash: [u8; 32] = data[32..64].try_into().unwrap();
    let length = 8 + (data[64] as usize % 57);
    let flags = data[65];
    let alnum = flags & 1 == 1;
    let symbols = if alnum || flags & 2 == 0 {
        None
    } else {
        std::str::from_utf8(&data[66..]).ok().and_then(|s| canonical_symbols(s).ok())
    };
    let settings = Settings {
        site: "example.com".into(),
        account: String::new(),
        length,
        charset: if alnum { Charset::Alnum } else { Charset::Strong },
        revision: 1,
        require_classes: flags & 4 == 0,
        spec_version: 2,
        symbols: symbols.clone(),
    };
    let password = derive_with_master(&master, &hash, &settings).unwrap();
    assert_eq!(password.len(), length);
    let allowed: &[u8] = match (&alnum, &symbols) {
        (true, _) => b"",
        (false, Some(s)) => s.as_bytes(),
        (false, None) => DEFAULT_SYMBOLS,
    };
    assert!(password.bytes().all(|b| b.is_ascii_alphanumeric() || allowed.contains(&b)));
    if settings.require_classes {
        assert!(password.bytes().any(|b| b.is_ascii_lowercase()));
        assert!(password.bytes().any(|b| b.is_ascii_uppercase()));
        assert!(password.bytes().any(|b| b.is_ascii_digit()));
        assert!(alnum || password.bytes().any(|b| allowed.contains(&b)));
    }
});
