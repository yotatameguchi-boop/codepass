//! Differential testing against docs/reference_syntax.py: reads JSON lines
//! {"name": ..., "code": ...} and prints the syntax hash, the definitions found and
//! the symbol hashes of the first three (or ERR) for each.
use std::io::BufRead;

fn main() {
    for line in std::io::stdin().lock().lines() {
        let v: serde_json::Value = serde_json::from_str(&line.expect("stdin")).expect("JSON line");
        let name = v["name"].as_str().expect("name");
        let code = v["code"].as_str().expect("code");
        let line = (|| -> Result<String, String> {
            use codepass::syntax;
            let mut out = vec![hex::encode(syntax::hash(code.as_bytes(), name)?)];
            let lang = syntax::lang_for(name)?;
            let defs = syntax::definitions(&syntax::tokens(code, lang)?, lang);
            out.push(defs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(","));
            let mut seen: Vec<&str> = Vec::new();
            for (n, _) in &defs {
                if !seen.contains(&n.as_str()) {
                    seen.push(n);
                }
            }
            for n in seen.iter().take(3) {
                out.push(hex::encode(syntax::symbol_hash(code.as_bytes(), name, n)?)[..16].to_string());
            }
            Ok(out.join(" "))
        })();
        println!("{}", line.unwrap_or_else(|_| "ERR".into()));
    }
}
