//! Syntax material (`--material syntax`): the password follows what the code *says*,
//! not how it is laid out. Comments, whitespace, indentation width, line breaks and
//! trailing commas are dropped; names, operators, literals and (in Python) the
//! indentation structure are kept. docs/SPEC.md "構文の材料" is the normative text.
//!
//! A small hand-written lexer, not a full parser: its every rule is in the spec, so
//! another implementation (docs/reference.py) reproduces it byte for byte, and a
//! parser upgrade can never change anybody's password.

use crate::Result;
use sha2::{Digest, Sha256};

pub const MATERIAL_ID: &str = "syntax-v1";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    /// C, C++, C#, Java
    C,
    /// JavaScript, TypeScript (backtick strings)
    Js,
    /// Go (backtick raw strings)
    Go,
    /// Rust (nested block comments, raw strings, lifetimes)
    Rust,
    /// Kotlin, Scala, Swift, Dart (nested block comments)
    Nested,
    /// Python (indentation is syntax)
    Python,
}

impl Lang {
    pub fn id(self) -> &'static str {
        match self {
            Lang::C => "c",
            Lang::Js => "js",
            Lang::Go => "go",
            Lang::Rust => "rust",
            Lang::Nested => "nested-c",
            Lang::Python => "python",
        }
    }

    /// By file extension (case-insensitive). None: syntax material is not available.
    pub fn for_file(name: &str) -> Option<Lang> {
        let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
        Some(match ext.as_str() {
            "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" | "cs" | "java" => Lang::C,
            "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => Lang::Js,
            "go" => Lang::Go,
            "rs" => Lang::Rust,
            "kt" | "kts" | "scala" | "swift" | "dart" => Lang::Nested,
            "py" | "pyi" => Lang::Python,
            _ => return None,
        })
    }
}

pub const NEWLINE: &str = "\u{0}NEWLINE";
pub const INDENT: &str = "\u{0}INDENT";
pub const DEDENT: &str = "\u{0}DEDENT";

/// Whitespace for this lexer: the ASCII set plus Unicode White_Space above U+007F,
/// listed explicitly so every implementation agrees.
pub fn is_space(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
    )
}

/// Identifier characters: ASCII letters, digits, `_`, `$`, and every non-ASCII
/// character that is not whitespace.
pub fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$' || (!c.is_ascii() && !is_space(c))
}

fn is_python_prefix(word: &str) -> bool {
    !word.is_empty() && word.len() <= 2 && word.chars().all(|c| "rRbBfFuU".contains(c))
}

struct Lexer<'a> {
    s: &'a [char],
    i: usize,
    lang: Lang,
    out: Vec<String>,
    // Python
    depth: usize,
    indents: Vec<usize>,
    line_has_tokens: bool,
}

impl Lexer<'_> {
    fn at(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }
    fn starts(&self, pat: &str) -> bool {
        pat.chars().enumerate().all(|(k, c)| self.at(k) == Some(c))
    }
    fn take(&mut self, from: usize) -> String {
        self.s[from..self.i].iter().collect()
    }
    fn push(&mut self, tok: String) {
        self.out.push(tok);
        self.line_has_tokens = true;
    }

    /// A quoted literal opened by `q` at `self.i` (after any prefix). Backslash always
    /// escapes the next character. `triple` closes on three quotes.
    fn quoted(&mut self, start: usize, q: char, triple: bool) -> Result<()> {
        self.i += if triple { 3 } else { 1 };
        loop {
            match self.at(0) {
                None => return Err("文字列が閉じていません（構文の材料にできません）".into()),
                Some('\\') => self.i += 2,
                Some(c) if c == q => {
                    if !triple {
                        self.i += 1;
                        break;
                    }
                    if self.at(1) == Some(q) && self.at(2) == Some(q) {
                        self.i += 3;
                        break;
                    }
                    self.i += 1;
                }
                Some(_) => self.i += 1,
            }
        }
        self.i = self.i.min(self.s.len());
        let tok = self.take(start);
        self.push(tok);
        Ok(())
    }

    /// Rust raw string `r#"…"#` (also `br`, `cr`) starting at `start`, `self.i` on the first `#` or `"`.
    fn rust_raw(&mut self, start: usize) -> Result<()> {
        let mut hashes = 0;
        while self.at(0) == Some('#') {
            hashes += 1;
            self.i += 1;
        }
        self.i += 1; // opening quote
        loop {
            match self.at(0) {
                None => return Err("文字列が閉じていません（構文の材料にできません）".into()),
                Some('"') if (1..=hashes).all(|k| self.at(k) == Some('#')) => {
                    self.i += 1 + hashes;
                    break;
                }
                Some(_) => self.i += 1,
            }
        }
        let tok = self.take(start);
        self.push(tok);
        Ok(())
    }

    fn block_comment(&mut self) -> Result<()> {
        let nested = matches!(self.lang, Lang::Rust | Lang::Nested);
        let mut level = 1;
        self.i += 2;
        while level > 0 {
            if self.i >= self.s.len() {
                return Err("コメントが閉じていません（構文の材料にできません）".into());
            }
            if self.starts("*/") {
                level -= 1;
                self.i += 2;
            } else if nested && self.starts("/*") {
                level += 1;
                self.i += 2;
            } else {
                self.i += 1;
            }
        }
        Ok(())
    }

    /// Python: at the start of a physical line outside brackets, measure the
    /// indentation and emit INDENT/DEDENT. Blank and comment-only lines are skipped.
    fn python_line_start(&mut self) -> Result<()> {
        let mut width = 0usize;
        while let Some(c) = self.at(0) {
            match c {
                ' ' => width += 1,
                '\t' => width = (width / 8 + 1) * 8,
                '\u{c}' => width = 0,
                _ => break,
            }
            self.i += 1;
        }
        match self.at(0) {
            None | Some('\n') | Some('#') => return Ok(()),
            Some('\r') if self.at(1) == Some('\n') || self.at(1).is_none() => return Ok(()),
            _ => {}
        }
        let top = *self.indents.last().expect("never empty");
        if width > top {
            self.indents.push(width);
            self.out.push(INDENT.into());
        } else {
            while width < *self.indents.last().expect("never empty") {
                self.indents.pop();
                self.out.push(DEDENT.into());
            }
            if width != *self.indents.last().expect("never empty") {
                return Err("インデントが前の行とそろっていません（構文の材料にできません）".into());
            }
        }
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        let python = self.lang == Lang::Python;
        if python {
            self.python_line_start()?;
        }
        while let Some(c) = self.at(0) {
            if python
                && c == '\\'
                && (self.at(1) == Some('\n') || (self.at(1) == Some('\r') && self.at(2) == Some('\n')))
            {
                // Explicit line joining: the next line continues this one.
                self.i += if self.at(1) == Some('\n') { 2 } else { 3 };
                continue;
            }
            if c == '\n' {
                self.i += 1;
                if python && self.depth == 0 {
                    if self.line_has_tokens {
                        self.out.push(NEWLINE.into());
                        self.line_has_tokens = false;
                    }
                    self.python_line_start()?;
                }
                continue;
            }
            if is_space(c) {
                self.i += 1;
                continue;
            }
            if python && c == '#' {
                while self.at(0).is_some_and(|c| c != '\n') {
                    self.i += 1;
                }
                continue;
            }
            if !python && self.starts("//") {
                while self.at(0).is_some_and(|c| c != '\n') {
                    self.i += 1;
                }
                continue;
            }
            if !python && self.starts("/*") {
                self.block_comment()?;
                continue;
            }
            let start = self.i;
            if c == '"'
                || (c == '\'' && self.lang != Lang::Rust)
                || (c == '`' && matches!(self.lang, Lang::Js | Lang::Go))
            {
                let triple =
                    c != '`' && self.at(1) == Some(c) && self.at(2) == Some(c) && (python || c == '"');
                self.quoted(start, c, triple)?;
                continue;
            }
            if c == '\'' {
                // Rust: a char literal ('a', '\n', 'é') or a lifetime marker ('a).
                if self.at(1) == Some('\\') {
                    self.quoted(start, '\'', false)?;
                } else if self.at(2) == Some('\'') && self.at(1).is_some() {
                    self.i += 3;
                    let tok = self.take(start);
                    self.push(tok);
                } else {
                    self.i += 1;
                    self.push("'".into());
                }
                continue;
            }
            if is_word(c) {
                while self.at(0).is_some_and(is_word) {
                    self.i += 1;
                }
                let word = self.take(start);
                if self.lang == Lang::Rust
                    && matches!(word.as_str(), "r" | "br" | "cr")
                    && matches!(self.at(0), Some('#' | '"'))
                {
                    let mut k = 0;
                    while self.at(k) == Some('#') {
                        k += 1;
                    }
                    if self.at(k) == Some('"') {
                        self.rust_raw(start)?;
                        continue;
                    }
                }
                if self.lang == Lang::Rust && matches!(word.as_str(), "b" | "c") && self.at(0) == Some('"') {
                    self.quoted(start, '"', false)?;
                    continue;
                }
                if self.lang == Lang::Rust && word == "b" && self.at(0) == Some('\'') {
                    self.quoted(start, '\'', false)?;
                    continue;
                }
                if python && is_python_prefix(&word) && matches!(self.at(0), Some('"' | '\'')) {
                    let q = self.at(0).expect("checked");
                    let triple = self.at(1) == Some(q) && self.at(2) == Some(q);
                    self.quoted(start, q, triple)?;
                    continue;
                }
                self.push(word);
                continue;
            }
            self.i += 1;
            if python {
                match c {
                    '(' | '[' | '{' => self.depth += 1,
                    ')' | ']' | '}' => self.depth = self.depth.saturating_sub(1),
                    _ => {}
                }
            }
            self.push(c.to_string());
        }
        if python {
            if self.line_has_tokens {
                self.out.push(NEWLINE.into());
            }
            for _ in 1..self.indents.len() {
                self.out.push(DEDENT.into());
            }
        }
        Ok(())
    }
}

/// Drops the commas that directly precede a closing bracket — except Python's
/// one-element tuple `(x,)`, where that single comma is the only one in the
/// parentheses. Removing the whole run at once keeps the result stable when
/// applied again.
fn drop_trailing_commas(tokens: Vec<String>, lang: Lang) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    let mut commas: Vec<usize> = vec![0];
    for tok in tokens {
        match tok.as_str() {
            "(" | "[" | "{" => commas.push(0),
            "," => *commas.last_mut().expect("never empty") += 1,
            ")" | "]" | "}" => {
                let total = *commas.last().expect("never empty");
                let trailing = out.iter().rev().take_while(|t| *t == ",").count();
                let tuple = lang == Lang::Python && tok == ")" && total == 1 && trailing == 1;
                if !tuple {
                    out.truncate(out.len() - trailing);
                }
                if commas.len() > 1 {
                    commas.pop();
                }
            }
            _ => {}
        }
        out.push(tok);
    }
    out
}

/// The tokens the password depends on, for a file of language `lang`.
pub fn tokens(text: &str, lang: Lang) -> Result<Vec<String>> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let chars: Vec<char> = text.chars().collect();
    let mut lx =
        Lexer { s: &chars, i: 0, lang, out: Vec::new(), depth: 0, indents: vec![0], line_has_tokens: false };
    lx.run()?;
    Ok(drop_trailing_commas(lx.out, lang))
}

pub fn lang_for(file_name: &str) -> Result<Lang> {
    Lang::for_file(file_name).ok_or_else(|| {
        format!(
            "「{file_name}」は構文の材料に対応していない種類のファイルです\
            （対応: .rs .py .js .ts .go .c .cpp .java .cs .kt .scala .swift .dart など）"
        )
    })
}

/// SHA-256 of the token stream, domain-separated from the plain byte hash.
pub fn hash(bytes: &[u8], file_name: &str) -> Result<[u8; 32]> {
    let lang = lang_for(file_name)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "構文の材料には UTF-8 のテキストファイルが必要です".to_string())?;
    let toks = tokens(text, lang)?;
    let mut h = Sha256::new();
    h.update(format!("CodePass/{MATERIAL_ID}\0{}\0", lang.id()).as_bytes());
    for t in &toks {
        h.update((t.len() as u32).to_be_bytes());
        h.update(t.as_bytes());
    }
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(lang_file: &str, a: &str, b: &str) {
        assert_eq!(
            hash(a.as_bytes(), lang_file).unwrap(),
            hash(b.as_bytes(), lang_file).unwrap(),
            "{a:?} vs {b:?}"
        );
    }
    fn differ(lang_file: &str, a: &str, b: &str) {
        assert_ne!(
            hash(a.as_bytes(), lang_file).unwrap(),
            hash(b.as_bytes(), lang_file).unwrap(),
            "{a:?} vs {b:?}"
        );
    }

    #[test]
    fn rust_layout_and_comments_do_not_matter() {
        let base = "fn main() {\n    let x = add(1, 2);\n    println!(\"{x}\");\n}\n";
        same("main.rs", base, "fn main(){let x=add(1,2);println!(\"{x}\");}");
        same(
            "main.rs",
            base,
            "// entry point\nfn main() {\r\n\tlet x = add(1, 2,); /* sum */\r\n    println!(\"{x}\");\r\n}",
        );
        same(
            "main.rs",
            base,
            "\u{feff}fn main() {\n  let x = add(\n    1,\n    2,\n  );\n  println!(\"{x}\");\n}\n",
        );
        same(
            "main.rs",
            base,
            "fn main() { /* outer /* nested */ still comment */ let x = add(1, 2); println!(\"{x}\"); }",
        );
        differ("main.rs", base, "fn main() {\n    let x = add(1, 3);\n    println!(\"{x}\");\n}\n");
        differ("main.rs", base, "fn main() {\n    let y = add(1, 2);\n    println!(\"{y}\");\n}\n");
        differ("main.rs", base, "fn main() {\n    let x = add(1, 2);\n    println!(\"{ x}\");\n}\n");
    }

    #[test]
    fn rust_literals_are_kept_whole() {
        let toks =
            tokens("let s = r#\"a // not a comment \"# ; let c = '\"'; fn f<'a>(x: &'a str) {}", Lang::Rust)
                .unwrap();
        assert!(toks.contains(&"r#\"a // not a comment \"#".to_string()), "{toks:?}");
        assert!(toks.contains(&"'\"'".to_string()), "{toks:?}");
        assert!(toks.windows(2).any(|w| w == ["'", "a"]), "lifetime split as ' a: {toks:?}");
    }

    #[test]
    fn python_indentation_is_structure() {
        let base = "def f(x, y):\n    if x:\n        return 1\n    return y\n";
        same("a.py", base, "def f(x, y):\n  if x:\n      return 1\n  return y\n");
        same(
            "a.py",
            base,
            "# comment\ndef f(x, y):  # trailing\n\n    if x:\n        return 1\n\n    return y",
        );
        same("a.py", base, "def f(\n    x,\n    y,\n):\n    if x:\n        return 1\n    return y\n");
        differ("a.py", base, "def f(x, y):\n    if x:\n        return 1\n        return y\n");
        assert!(hash(b"if x:\n        a\n    b\n", "a.py").is_err(), "inconsistent dedent");
    }

    #[test]
    fn python_strings_and_tuples() {
        same("a.py", "x = (1,)\n", "x = ( 1 , )\n");
        differ("a.py", "x = (1,)\n", "x = (1)\n");
        same("a.py", "x = [1, 2,]\n", "x = [1, 2]\n");
        same("a.py", "s = '''a # b\n c'''\n", "s = '''a # b\n c'''  # note\n");
        differ("a.py", "s = 'a'\n", "s = \"a\"\n");
        let toks = tokens("s = rb'\\d+' + f\"{x}\"\n", Lang::Python).unwrap();
        assert!(toks.contains(&"rb'\\d+'".to_string()) && toks.contains(&"f\"{x}\"".to_string()), "{toks:?}");
    }

    #[test]
    fn trailing_comma_runs_go_at_once() {
        same("a.js", "f(a,,)", "f(a)");
        same("a.py", "x = [1,,]\n", "x = [1]\n");
        differ("a.py", "x = (1,)\n", "x = (1)\n");
    }

    #[test]
    fn javascript_template_and_comments() {
        same("a.js", "const s = `a ${b} // c`;", "const s=`a ${b} // c` ; // trailing");
        differ("a.js", "const s = `a`;", "const s = 'a';");
        same("a.ts", "f(a, b,)", "f(a, b)");
    }

    #[test]
    fn unsupported_and_broken_inputs_are_errors() {
        assert!(hash(b"x", "notes.txt").is_err());
        assert!(hash(b"fn main() { \"open", "main.rs").is_err());
        assert!(hash(b"/* open", "main.c").is_err());
        assert!(hash(&[0xff, 0xfe], "main.rs").is_err());
        assert_ne!(hash(b"a", "a.rs").unwrap(), hash(b"a", "a.go").unwrap(), "language is part of the hash");
    }
}
