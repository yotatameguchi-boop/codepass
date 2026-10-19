//! Break-glass team profiles: k of n people together reproduce the passwords.
//!
//! A random 32-byte team secret replaces the master secret. It is split with Shamir's
//! secret sharing (the `blahaj` crate: GF(256), polynomial 0x11d, x = 1, 2, …) into n
//! shares; any k of them recover it, fewer reveal nothing. The team secret is never
//! stored. Each share carries a checksum (typos), and the profile keeps a verifier of
//! the team secret (a wrong combination is caught before anything is derived).
//! docs/SPEC.md "チームの共有（緊急用アカウント）" is the normative text.

use crate::Result;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SHARE_PREFIX: &str = "cpshare1";

/// What the profile keeps about the team (none of it secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamConfig {
    pub threshold: u8,
    pub shares: u8,
    /// Changes with every split, so shares of different splits are never mixed.
    pub set_id: String,
    /// HKDF of the team secret: confirms a recovered secret without revealing it.
    pub verifier: String,
}

impl TeamConfig {
    pub fn validate(&self) -> Result<()> {
        if !(2..=self.shares).contains(&self.threshold) || self.shares > 16 {
            return Err("チームの設定が不正です（2 ≦ 必要人数 ≦ 人数 ≦ 16）".into());
        }
        if self.set_id.len() != 8 || !self.set_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("チームの設定が不正です（set_id）".into());
        }
        if self.verifier.len() != 32 || !self.verifier.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("チームの設定が不正です（verifier）".into());
        }
        Ok(())
    }
}

pub fn verifier(team_secret: &[u8; 32]) -> String {
    let mut out = [0u8; 16];
    Hkdf::<Sha256>::new(Some(b"CodePass/team/v1"), team_secret)
        .expand(b"CodePass/team-verifier/v1", &mut out)
        .expect("16 bytes is a valid HKDF length");
    hex::encode(out)
}

/// The master key of a team profile. The team secret is 256 random bits, so no
/// password stretching is needed; the profile salt keeps profiles apart.
pub fn team_master(team_secret: &[u8; 32], salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), team_secret)
        .expand(b"CodePass/team-master/v1", &mut out[..])
        .expect("32 bytes is a valid HKDF length");
    out
}

pub fn new_team_secret() -> Result<Zeroizing<[u8; 32]>> {
    let mut s = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut s[..]).map_err(|_| "安全な乱数を取得できません")?;
    Ok(s)
}

pub fn new_set_id() -> Result<String> {
    let mut id = [0u8; 4];
    getrandom::getrandom(&mut id).map_err(|_| "安全な乱数を取得できません")?;
    Ok(hex::encode(id))
}

fn checksum(set_id: &str, threshold: u8, x: u8, y: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"CodePass/share/v1\0");
    h.update(set_id.as_bytes());
    h.update([threshold, x]);
    h.update(y);
    hex::encode(&h.finalize()[..4])
}

/// One share as people handle it: `cpshare1-<set>-<k>-<x>-<y in 8 groups>-<checksum>`.
pub fn format_share(set_id: &str, threshold: u8, x: u8, y: &[u8; 32]) -> String {
    let groups: Vec<String> = y.chunks(4).map(hex::encode).collect();
    format!(
        "{SHARE_PREFIX}-{set_id}-{threshold}-{x:02x}-{}-{}",
        groups.join("-"),
        checksum(set_id, threshold, x, y)
    )
}

/// Splits `team_secret` into `n` shares, any `k` of which recover it.
#[cfg(feature = "cli")]
pub fn split(team_secret: &[u8; 32], k: u8, n: u8, set_id: &str) -> Result<Vec<Zeroizing<String>>> {
    if !(2..=n).contains(&k) || n > 16 {
        return Err("必要人数は2人以上、人数は必要人数以上16人以下にしてください".into());
    }
    let dealer = blahaj::Sharks(k).dealer(team_secret);
    Ok(dealer
        .take(n as usize)
        .map(|share| {
            let bytes = Zeroizing::new(Vec::<u8>::from(&share));
            let y: [u8; 32] = bytes[1..].try_into().expect("32-byte secret gives 32-byte shares");
            Zeroizing::new(format_share(set_id, k, bytes[0], &y))
        })
        .collect())
}

pub struct ParsedShare {
    pub set_id: String,
    pub threshold: u8,
    pub x: u8,
    pub y: Zeroizing<[u8; 32]>,
}

/// Reads a share as typed: spaces, line breaks and case do not matter.
pub fn parse_share(text: &str) -> Result<ParsedShare> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_lowercase();
    let parts: Vec<&str> = clean.split('-').collect();
    let bad = || "共有の形式が違います（cpshare1- で始まる文字列をそのまま入力してください）".to_string();
    if parts.len() != 13 || parts[0] != SHARE_PREFIX {
        return Err(bad());
    }
    let set_id = parts[1].to_string();
    let threshold: u8 = parts[2].parse().map_err(|_| bad())?;
    let x = u8::from_str_radix(parts[3], 16).map_err(|_| bad())?;
    let y_hex: String = parts[4..12].concat();
    let mut y = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(&y_hex, &mut y[..]).map_err(|_| bad())?;
    if set_id.len() != 8 || x == 0 {
        return Err(bad());
    }
    if checksum(&set_id, threshold, x, &y[..]) != parts[12] {
        return Err("共有の確認用の文字が合いません。写し間違いがないか確かめてください".into());
    }
    Ok(ParsedShare { set_id, threshold, x, y })
}

/// Recovers the team secret from at least `threshold` distinct shares of this split.
#[cfg(feature = "cli")]
pub fn combine(shares: &[ParsedShare], cfg: &TeamConfig) -> Result<Zeroizing<[u8; 32]>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut points = Vec::new();
    for s in shares {
        if s.set_id != cfg.set_id || s.threshold != cfg.threshold {
            return Err("別の分割で作られた共有が混ざっています（古い共有ではありませんか）".into());
        }
        if seen.insert(s.x) {
            let mut bytes = Zeroizing::new(Vec::with_capacity(33));
            bytes.push(s.x);
            bytes.extend_from_slice(&s.y[..]);
            points.push(blahaj::Share::try_from(&bytes[..]).map_err(|e| e.to_string())?);
        }
    }
    if points.len() < cfg.threshold as usize {
        return Err(format!("共有が足りません（{} 人分が必要です）", cfg.threshold));
    }
    let secret = Zeroizing::new(blahaj::Sharks(cfg.threshold).recover(&points[..cfg.threshold as usize])?);
    let secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(secret[..].try_into().map_err(|_| "共有から復元できませんでした".to_string())?);
    if verifier(&secret) != cfg.verifier {
        return Err("共有から復元した値が合いません。違う共有が混ざっていないか確かめてください".into());
    }
    Ok(secret)
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::*;

    fn team(k: u8, n: u8) -> (Zeroizing<[u8; 32]>, TeamConfig, Vec<Zeroizing<String>>) {
        let secret = new_team_secret().unwrap();
        let set_id = new_set_id().unwrap();
        let shares = split(&secret, k, n, &set_id).unwrap();
        (secret.clone(), TeamConfig { threshold: k, shares: n, set_id, verifier: verifier(&secret) }, shares)
    }

    #[test]
    fn any_k_of_n_recover_and_fewer_do_not() {
        let (secret, cfg, shares) = team(3, 5);
        let parsed: Vec<ParsedShare> = shares.iter().map(|s| parse_share(s).unwrap()).collect();
        for combo in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [4, 3, 2]] {
            let pick: Vec<ParsedShare> = combo.iter().map(|&i| parse_share(&shares[i]).unwrap()).collect();
            assert_eq!(*combine(&pick, &cfg).unwrap(), *secret, "{combo:?}");
        }
        assert!(combine(&parsed[..2], &cfg).is_err(), "two of three needed");
        // The same share twice counts once.
        let twice = vec![
            parse_share(&shares[0]).unwrap(),
            parse_share(&shares[0]).unwrap(),
            parse_share(&shares[1]).unwrap(),
        ];
        assert!(combine(&twice, &cfg).is_err());
    }

    #[test]
    fn typos_and_foreign_shares_are_caught() {
        let (_, cfg, shares) = team(2, 3);
        // Spaces, line breaks and capitals are fine.
        let spaced = shares[0].to_uppercase().replace('-', " - ");
        assert!(parse_share(&spaced).is_ok());
        // One wrong character: the checksum fails.
        let mut typo = shares[0].to_string();
        let i = typo.len() - 20;
        let wrong = if &typo[i..i + 1] == "0" { "1" } else { "0" };
        typo.replace_range(i..i + 1, wrong);
        assert!(parse_share(&typo).is_err());
        // Shares of another split are refused, even with the right threshold.
        let (_, _, other) = team(2, 3);
        let mixed = vec![parse_share(&shares[0]).unwrap(), parse_share(&other[1]).unwrap()];
        assert!(combine(&mixed, &cfg).is_err());
    }

    #[test]
    fn resharing_keeps_the_secret() {
        let (secret, _, _) = team(2, 3);
        let set_id = new_set_id().unwrap();
        let again = split(&secret, 3, 4, &set_id).unwrap();
        let cfg = TeamConfig { threshold: 3, shares: 4, set_id, verifier: verifier(&secret) };
        let pick: Vec<ParsedShare> = again[1..].iter().map(|s| parse_share(s).unwrap()).collect();
        assert_eq!(*combine(&pick, &cfg).unwrap(), *secret);
    }
}
