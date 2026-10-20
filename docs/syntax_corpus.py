# Differential test for the syntax material: random code-like inputs, hashed by the
# Python reference and by the Rust implementation (examples/syntax_hash.rs).
#   python docs/syntax_corpus.py corpus > corpus.jsonl
#   cargo run -q --example syntax_hash < corpus.jsonl > rust.txt
#   python docs/syntax_corpus.py hash < corpus.jsonl > python.txt && diff rust.txt python.txt
import json
import random
import sys

sys.path.insert(0, "docs")
from reference_syntax import SyntaxError_, definitions, lang_for, symbol_hash, syntax_hash, tokens  # noqa: E402

PIECES = [
    "fn", "def", "let", "x", "y_1", "$v", "é", "名前", "if", "return", "lambda",
    " ", "  ", "\t", "\n", "\r\n", "\n    ", "\n\t", "\n  ", "\\\n", "　", " ", "﻿",
    "(", ")", "[", "]", "{", "}", ",", ";", ":", ".", "+", "-", "*", "/", "<", ">", "=", "!", "&", "|", "#", "@", "?",
    "//", "/*", "*/", "#", "'", '"', "`", '"""', "'''", "\\", "\\n", "\\\"",
    "'a", "'a'", "'\\n'", 'r"', 'r#"', '"#', "br\"", "b'", "f\"", "rb'", "u'",
    "1", "0x1F", "1_000", "3.14",
    "fn key() { 1 }", "def key():\n    return 1\n", "int key(void) { return 1; }", "class K { }", "const K = 1;",
    "let mut v = 2;", "static int ", "&'static str", "-> &'a ", "impl ", "func (r T) ", "K = 3\n", "= ", "function ",
]
NAMES = ["a.rs", "a.py", "a.js", "a.ts", "a.go", "a.c", "a.java", "a.kt", "a.swift", "a.txt"]


def corpus(count=30000, seed=7):
    rng = random.Random(seed)
    for _ in range(count):
        code = "".join(rng.choice(PIECES) for _ in range(rng.randint(0, 40)))
        print(json.dumps({"name": rng.choice(NAMES), "code": code}, ensure_ascii=False))


def hashes():
    for line in sys.stdin:
        v = json.loads(line)
        try:
            data = v["code"].encode()
            out = [syntax_hash(data, v["name"]).hex()]
            lang = lang_for(v["name"])
            defs = definitions(tokens(v["code"], lang), lang)
            out.append(",".join(d[0] for d in defs))
            seen = []
            for d in defs:
                if d[0] not in seen:
                    seen.append(d[0])
            for name in seen[:3]:
                out.append(symbol_hash(data, v["name"], name).hex()[:16])
            print(" ".join(out))
        except (SyntaxError_, UnicodeDecodeError):
            print("ERR")


if __name__ == "__main__":
    {"corpus": corpus, "hash": hashes}[sys.argv[1]]()
