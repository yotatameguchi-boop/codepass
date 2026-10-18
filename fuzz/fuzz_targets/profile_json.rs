//! Any bytes as a profile file: never panics, and whatever validates survives a
//! save/load round trip unchanged (the salt above all).
#![no_main]
use codepass::profile::Profile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(profile) = serde_json::from_slice::<Profile>(data) else { return };
    if profile.validate().is_err() {
        return;
    }
    let bytes = serde_json::to_vec(&profile).unwrap();
    let again: Profile = serde_json::from_slice(&bytes).unwrap();
    again.validate().unwrap();
    assert_eq!(again.salt, profile.salt);
    assert_eq!(serde_json::to_value(&again).unwrap(), serde_json::to_value(&profile).unwrap());
});
