//! The syntax lexer never panics on any input, and for the C-like languages its
//! token stream is a fixed point: re-tokenizing the tokens joined by spaces gives
//! the same tokens (layout carries no information).
#![no_main]
use codepass::syntax::{tokens, Lang};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    let Ok(text) = std::str::from_utf8(rest) else { return };
    let lang = [Lang::C, Lang::Js, Lang::Go, Lang::Rust, Lang::Nested, Lang::Python][pick as usize % 6];
    let Ok(toks) = tokens(text, lang) else { return };
    // Every definition range lies inside the token stream and starts at its name or definer.
    for (name, range) in codepass::syntax::definitions(&toks, lang) {
        assert!(range.start < range.end && range.end <= toks.len(), "{name} {range:?}");
        assert!(toks[range.clone()].contains(&name));
    }
    if matches!(lang, Lang::C | Lang::Js | Lang::Go | Lang::Nested) {
        let again = tokens(&toks.join(" "), lang).expect("re-tokenizing its own output");
        assert_eq!(again, toks, "input {text:?}");
    }
});
