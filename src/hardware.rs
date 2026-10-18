//! Optional second factor: a FIDO2 security key's `hmac-secret` extension.
//!
//! At `init --hardware-key` a credential is created on the key (the key keeps the
//! secret; CodePass stores only the credential id). Each time the master key is
//! derived, the key is asked for HMAC(its secret, challenge) — which needs a touch —
//! and the answer is mixed into the master key (`crypto::with_hardware`).
//!
//! Real devices are behind the `fido2` cargo feature. Tests use `SoftKey`.

use crate::Result;

pub const RP_ID: &str = "codepass";

pub trait SecurityKey {
    /// Creates a credential with hmac-secret enabled; returns its id.
    fn enroll(&self, rp_id: &str) -> Result<Vec<u8>>;
    /// Returns the 32-byte hmac-secret output for `challenge`.
    fn hmac_secret(&self, rp_id: &str, credential_id: &[u8], challenge: &[u8; 32]) -> Result<[u8; 32]>;
}

/// A software stand-in for tests: deterministic, never for real use.
pub struct SoftKey(pub [u8; 32]);

impl SecurityKey for SoftKey {
    fn enroll(&self, rp_id: &str) -> Result<Vec<u8>> {
        Ok(soft_hmac(&self.0, &[b"enroll", rp_id.as_bytes()]).to_vec())
    }
    fn hmac_secret(&self, rp_id: &str, credential_id: &[u8], challenge: &[u8; 32]) -> Result<[u8; 32]> {
        if credential_id != self.enroll(rp_id)? {
            return Err("このセキュリティキーには、この設定の資格情報がありません".into());
        }
        Ok(soft_hmac(&self.0, &[credential_id, challenge]))
    }
}

fn soft_hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

#[cfg(feature = "fido2")]
pub use device::Fido2Key;

#[cfg(feature = "fido2")]
mod device {
    use super::SecurityKey;
    use crate::Result;
    use ctap_hid_fido2::{
        fidokey::{get_assertion::Extension as Gext, make_credential::Extension as Mext},
        FidoKeyHidFactory, LibCfg,
    };

    /// The first FIDO2 device found over USB HID.
    pub struct Fido2Key(ctap_hid_fido2::FidoKeyHid);

    impl Fido2Key {
        pub fn open() -> Result<Self> {
            FidoKeyHidFactory::create(&LibCfg::init())
                .map(Self)
                .map_err(|_| "セキュリティキーが見つかりません。USBに挿してからもう一度試してください".into())
        }
    }

    // The CTAP challenge is not used for anything secret here: hmac-secret output
    // depends only on the credential and the salt, so a fixed challenge is fine.
    const CLIENT_DATA_HASH: [u8; 32] = [0u8; 32];

    impl SecurityKey for Fido2Key {
        fn enroll(&self, rp_id: &str) -> Result<Vec<u8>> {
            eprintln!("セキュリティキーに触れてください（登録）…");
            let att = self
                .0
                .make_credential_with_extensions(
                    rp_id,
                    &CLIENT_DATA_HASH,
                    None,
                    Some(&vec![Mext::HmacSecret(Some(true))]),
                )
                .map_err(|e| format!("セキュリティキーへの登録に失敗しました: {e}"))?;
            if !att.extensions.iter().any(|e| matches!(e, Mext::HmacSecret(Some(true)))) {
                return Err("このセキュリティキーは hmac-secret に対応していません".into());
            }
            Ok(att.credential_descriptor.id)
        }

        fn hmac_secret(&self, rp_id: &str, credential_id: &[u8], challenge: &[u8; 32]) -> Result<[u8; 32]> {
            eprintln!("セキュリティキーに触れてください…");
            let ass = self
                .0
                .get_assertion_with_extensions(
                    rp_id,
                    &CLIENT_DATA_HASH,
                    &[credential_id.to_vec()],
                    None,
                    Some(&vec![Gext::HmacSecret(Some(*challenge))]),
                )
                .map_err(|e| format!("セキュリティキーでの認証に失敗しました: {e}"))?;
            ass.extensions
                .iter()
                .find_map(|e| match e {
                    Gext::HmacSecret(Some(out)) => Some(*out),
                    _ => None,
                })
                .ok_or_else(|| "セキュリティキーが hmac-secret を返しませんでした".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hardware_challenge, with_hardware};

    #[test]
    fn hardware_factor_changes_the_master_key() {
        let key = SoftKey([5; 32]);
        let id = key.enroll(RP_ID).unwrap();
        let challenge = hardware_challenge(&[1; 16]);
        let a = key.hmac_secret(RP_ID, &id, &challenge).unwrap();
        assert_eq!(a, key.hmac_secret(RP_ID, &id, &challenge).unwrap(), "same answer every time");
        let master = [9u8; 32];
        let with = with_hardware(&master, &a).unwrap();
        assert_ne!(*with, master);
        let other = SoftKey([6; 32]).hmac_secret(RP_ID, &SoftKey([6; 32]).enroll(RP_ID).unwrap(), &challenge);
        assert_ne!(
            *with_hardware(&master, &other.unwrap()).unwrap(),
            *with,
            "another key gives another master"
        );
        assert!(SoftKey([6; 32]).hmac_secret(RP_ID, &id, &challenge).is_err(), "wrong key is refused");
    }
}
