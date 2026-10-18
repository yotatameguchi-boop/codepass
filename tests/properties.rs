use codepass::crypto::{derive_with_master, normalize_site_v2, Charset, Settings};
use proptest::prelude::*;

fn settings(length: usize, charset: Charset, symbols: Option<String>, require_classes: bool) -> Settings {
    Settings {
        site: "example.com".into(),
        account: String::new(),
        length,
        charset,
        revision: 1,
        require_classes,
        spec_version: 2,
        symbols,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn output_always_meets_the_rules(
        master in any::<[u8; 32]>(), hash in any::<[u8; 32]>(), length in 8usize..=64,
        alnum in any::<bool>(), symbols in proptest::option::of("[!-/:-@\\[-`{-~]{1,10}"),
    ) {
        let charset = if alnum { Charset::Alnum } else { Charset::Strong };
        let symbols = if alnum { None } else { symbols.map(|s| codepass::crypto::canonical_symbols(&s).unwrap()) };
        let s = settings(length, charset, symbols.clone(), true);
        let p = derive_with_master(&master, &hash, &s).unwrap();
        prop_assert_eq!(&*p, &*derive_with_master(&master, &hash, &s).unwrap());
        prop_assert_eq!(p.len(), length);
        let allowed_symbol = |b: u8| match (&charset, &symbols) {
            (Charset::Alnum, _) => false,
            (_, Some(sym)) => sym.as_bytes().contains(&b),
            (_, None) => b"!#$%&()*+,-./:;<=>?@[]^_{|}~".contains(&b),
        };
        prop_assert!(p.bytes().all(|b| b.is_ascii_alphanumeric() || allowed_symbol(b)), "{}", &*p);
        prop_assert!(p.bytes().any(|b| b.is_ascii_lowercase()));
        prop_assert!(p.bytes().any(|b| b.is_ascii_uppercase()));
        prop_assert!(p.bytes().any(|b| b.is_ascii_digit()));
        prop_assert!(alnum || p.bytes().any(allowed_symbol));
    }

    #[test]
    fn site_normalization_is_idempotent(site in "\\PC{0,40}") {
        let once = normalize_site_v2(&site);
        prop_assert_eq!(normalize_site_v2(&once), once.clone(), "input {:?}", site);
    }

    #[test]
    fn url_forms_reduce_to_the_host(
        scheme in "(https?://)?", www in "(www\\.|WWW\\.)?", host in "[a-z][a-z0-9-]{0,10}\\.[a-z]{2,6}",
        port in "(:[0-9]{1,5})?", path in "(/[a-zA-Z0-9]{0,8})?",
    ) {
        let input = format!("{scheme}{www}{}{port}{path}", host.to_uppercase());
        prop_assert_eq!(normalize_site_v2(&input), host);
    }

    #[test]
    fn corrupt_profiles_are_rejected_without_panicking(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        std::fs::write(&path, &bytes).unwrap();
        let _ = codepass::profile::load(&path);
    }
}

// Rejection sampling must not favour any character. 128k samples over 62 characters;
// the chi-square bound is far above what an unbiased generator reaches (df = 61, p ≈ 1e-6).
#[test]
fn characters_are_uniform() {
    let s = settings(64, Charset::Alnum, None, false);
    let mut counts = [0u64; 128];
    let mut total = 0u64;
    for i in 0..2000u32 {
        let mut master = [0u8; 32];
        master[..4].copy_from_slice(&i.to_be_bytes());
        for b in derive_with_master(&master, &[0; 32], &s).unwrap().bytes() {
            counts[b as usize] += 1;
            total += 1;
        }
    }
    let used: Vec<u64> = counts.iter().copied().filter(|&c| c > 0).collect();
    assert_eq!(used.len(), 62);
    let expected = total as f64 / 62.0;
    let chi2: f64 = used.iter().map(|&c| (c as f64 - expected).powi(2) / expected).sum();
    assert!(chi2 < 130.0, "chi-square {chi2}");
}

mod syntax_material {
    use codepass::syntax;
    use proptest::prelude::*;

    const TOKENS: &[&str] = &[
        "a",
        "b1",
        "_x",
        "$el",
        "名前",
        "return",
        "if",
        "(",
        ")",
        "{",
        "}",
        "[",
        "]",
        "+",
        "-",
        "*",
        "/",
        "=",
        ";",
        ":",
        "<",
        ">",
        "!",
        "&",
        "|",
        ".",
        ",",
        "\"s\"",
        "\"a // b\"",
        "'q'",
        "`t ${x}`",
        "1",
        "0x1F",
    ];
    const SEPARATORS: &[&str] =
        &[" ", "  ", "\n", "\r\n", "\t", " /* note */ ", " // note\n", "\n\n    ", " /**/ "];

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Layout and comments never change the syntax hash (JavaScript rules).
        #[test]
        fn layout_and_comments_do_not_matter(
            toks in proptest::collection::vec(proptest::sample::select(TOKENS), 1..40),
            seps in proptest::collection::vec(proptest::sample::select(SEPARATORS), 40),
        ) {
            let compact = toks.join(" ");
            let noisy: String = toks.iter().enumerate().map(|(i, t)| format!("{t}{}", seps[i])).collect();
            prop_assert_eq!(
                syntax::hash(compact.as_bytes(), "a.js").unwrap(),
                syntax::hash(noisy.as_bytes(), "a.js").unwrap(),
                "{:?}", noisy
            );
        }

        /// Changing any one token changes the hash.
        #[test]
        fn a_changed_token_changes_the_hash(
            toks in proptest::collection::vec(proptest::sample::select(TOKENS), 1..40),
            at in any::<prop::sample::Index>(),
        ) {
            let i = at.index(toks.len());
            prop_assume!(!matches!(toks[i], "," | ")" | "]" | "}"));
            let mut changed = toks.clone();
            changed[i] = "zz_changed";
            prop_assert_ne!(
                syntax::hash(toks.join(" ").as_bytes(), "a.js").unwrap(),
                syntax::hash(changed.join(" ").as_bytes(), "a.js").unwrap()
            );
        }
    }
}
