//! Differential testing against docs/reference_syntax.py: reads JSON lines
//! {"name": ..., "code": ...} and prints the syntax hash (or ERR) for each.
use std::io::BufRead;

fn main() {
    for line in std::io::stdin().lock().lines() {
        let v: serde_json::Value = serde_json::from_str(&line.expect("stdin")).expect("JSON line");
        let name = v["name"].as_str().expect("name");
        let code = v["code"].as_str().expect("code");
        match codepass::syntax::hash(code.as_bytes(), name) {
            Ok(h) => println!("{}", hex::encode(h)),
            Err(_) => println!("ERR"),
        }
    }
}
