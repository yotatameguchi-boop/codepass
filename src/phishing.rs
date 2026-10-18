//! Look-alike domain detection (Unicode TR39 confusables and mixed scripts).
//!
//! A phishing site copies the look of a real domain (`gіthub.com` with a Cyrillic
//! `і`, `paypa1.com` with a digit one). CodePass binds passwords to the exact
//! service name, so a look-alike already gets a *different* password; these checks
//! make that visible and stop `get` from answering for a look-alike at all.

use unicode_security::{confusable_detection::skeleton, MixedScript};

/// The TR39 skeleton: two strings that render alike share it.
pub fn skeleton_of(site: &str) -> String {
    skeleton(site).collect()
}

/// Warnings about the name itself, independent of what is registered.
pub fn suspicious_parts(site: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    for label in site.split('.').filter(|l| !l.is_empty()) {
        if !label.is_single_script() {
            warnings
                .push(format!("「{label}」に複数の文字体系（例: ラテン文字とキリル文字）が混ざっています"));
        }
    }
    if !site.is_ascii() {
        // Only the non-ASCII characters are swapped for their look-alikes, so the
        // message shows what the reader thinks they see ("github.com", not "github.corn").
        let look: String = site
            .chars()
            .map(|c| if c.is_ascii() { c.to_string() } else { skeleton(&c.to_string()).collect() })
            .collect();
        if look.is_ascii() && look != site {
            warnings.push(format!("「{look}」と見分けにくい文字が含まれています"));
        }
    }
    warnings
}

/// Registered names that look the same as `site` but are not it.
pub fn lookalikes<'a>(site: &str, registered: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let look = skeleton_of(site);
    let mut found: Vec<String> =
        registered.into_iter().filter(|r| *r != site && skeleton_of(r) == look).map(str::to_string).collect();
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cyrillic_and_digit_lookalikes() {
        let registered = ["github.com", "paypal.com", "example.com"];
        // Cyrillic і (U+0456) in place of Latin i.
        assert_eq!(lookalikes("g\u{456}thub.com", registered), ["github.com"]);
        assert_eq!(lookalikes("paypa1.com", registered), ["paypal.com"]);
        assert_eq!(lookalikes("rnicrosoft.com", ["microsoft.com"]), ["microsoft.com"]);
        assert!(lookalikes("github.com", registered).is_empty(), "the same name is not a look-alike");
        assert!(lookalikes("gitlab.com", registered).is_empty());
    }

    #[test]
    fn flags_mixed_scripts_but_not_honest_unicode() {
        let warnings = suspicious_parts("g\u{456}thub.com");
        assert!(warnings.iter().any(|w| w.contains("「github.com」")), "{warnings:?}");
        assert!(suspicious_parts("github.com").is_empty());
        assert!(suspicious_parts("bücher.example").is_empty());
        assert!(suspicious_parts("例え.テスト").is_empty());
    }
}
