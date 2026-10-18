# Independent reference implementation of the syntax material (docs/SPEC.md "構文の材料").
# Written from the spec; must agree with src/syntax.rs byte for byte (checked in CI).
import hashlib
import struct

MATERIAL_ID = "syntax-v1"
NEWLINE, INDENT, DEDENT = "\0NEWLINE", "\0INDENT", "\0DEDENT"

LANGS = {
    "c": ["c", "h", "cc", "cpp", "cxx", "hpp", "hh", "cs", "java"],
    "js": ["js", "jsx", "mjs", "cjs", "ts", "tsx"],
    "go": ["go"],
    "rust": ["rs"],
    "nested-c": ["kt", "kts", "scala", "swift", "dart"],
    "python": ["py", "pyi"],
}
SPACES = set(" \t\n\r\x0b\x0c\x85\xa0     　") | {chr(c) for c in range(0x2000, 0x200B)}


class SyntaxError_(Exception):
    pass


def lang_for(name):
    if "." not in name:
        return None
    ext = name.rsplit(".", 1)[1].lower()
    for lang, exts in LANGS.items():
        if ext in exts:
            return lang
    return None


def is_space(c):
    return c in SPACES


def is_word(c):
    return (c.isascii() and (c.isalnum() or c in "_$")) or (not c.isascii() and not is_space(c))


def tokens(text, lang):
    if text.startswith("﻿"):
        text = text[1:]
    s = text
    n = len(s)
    out = []
    st = {"i": 0, "depth": 0, "indents": [0], "line": False}
    python = lang == "python"

    def at(k):
        j = st["i"] + k
        return s[j] if j < n else None

    def starts(p):
        return all(at(k) == c for k, c in enumerate(p))

    def push(t):
        out.append(t)
        st["line"] = True

    def quoted(start, q, triple):
        st["i"] += 3 if triple else 1
        while True:
            c = at(0)
            if c is None:
                raise SyntaxError_("unterminated string")
            if c == "\\":
                st["i"] += 2
            elif c == q:
                if not triple:
                    st["i"] += 1
                    break
                if at(1) == q and at(2) == q:
                    st["i"] += 3
                    break
                st["i"] += 1
            else:
                st["i"] += 1
        st["i"] = min(st["i"], n)
        push(s[start:st["i"]])

    def rust_raw(start):
        hashes = 0
        while at(0) == "#":
            hashes += 1
            st["i"] += 1
        st["i"] += 1
        while True:
            c = at(0)
            if c is None:
                raise SyntaxError_("unterminated raw string")
            if c == '"' and all(at(k) == "#" for k in range(1, hashes + 1)):
                st["i"] += 1 + hashes
                break
            st["i"] += 1
        push(s[start:st["i"]])

    def block_comment():
        nested = lang in ("rust", "nested-c")
        level = 1
        st["i"] += 2
        while level > 0:
            if st["i"] >= n:
                raise SyntaxError_("unterminated comment")
            if starts("*/"):
                level -= 1
                st["i"] += 2
            elif nested and starts("/*"):
                level += 1
                st["i"] += 2
            else:
                st["i"] += 1

    def line_start():
        width = 0
        while at(0) is not None:
            c = at(0)
            if c == " ":
                width += 1
            elif c == "\t":
                width = (width // 8 + 1) * 8
            elif c == "\x0c":
                width = 0
            else:
                break
            st["i"] += 1
        c = at(0)
        if c is None or c == "\n" or c == "#":
            return
        if c == "\r" and (at(1) == "\n" or at(1) is None):
            return
        ind = st["indents"]
        if width > ind[-1]:
            ind.append(width)
            out.append(INDENT)
        else:
            while width < ind[-1]:
                ind.pop()
                out.append(DEDENT)
            if width != ind[-1]:
                raise SyntaxError_("inconsistent dedent")

    if python:
        line_start()
    while at(0) is not None:
        c = at(0)
        if python and c == "\\" and (at(1) == "\n" or (at(1) == "\r" and at(2) == "\n")):
            st["i"] += 2 if at(1) == "\n" else 3
            continue
        if c == "\n":
            st["i"] += 1
            if python and st["depth"] == 0:
                if st["line"]:
                    out.append(NEWLINE)
                    st["line"] = False
                line_start()
            continue
        if is_space(c):
            st["i"] += 1
            continue
        if python and c == "#":
            while at(0) is not None and at(0) != "\n":
                st["i"] += 1
            continue
        if not python and starts("//"):
            while at(0) is not None and at(0) != "\n":
                st["i"] += 1
            continue
        if not python and starts("/*"):
            block_comment()
            continue
        start = st["i"]
        if c == '"' or (c == "'" and lang != "rust") or (c == "`" and lang in ("js", "go")):
            triple = c != "`" and at(1) == c and at(2) == c and (python or c == '"')
            quoted(start, c, triple)
            continue
        if c == "'":
            if at(1) == "\\":
                quoted(start, "'", False)
            elif at(2) == "'" and at(1) is not None:
                st["i"] += 3
                push(s[start:st["i"]])
            else:
                st["i"] += 1
                push("'")
            continue
        if is_word(c):
            while at(0) is not None and is_word(at(0)):
                st["i"] += 1
            word = s[start:st["i"]]
            if lang == "rust" and word in ("r", "br", "cr") and at(0) in ("#", '"'):
                k = 0
                while at(k) == "#":
                    k += 1
                if at(k) == '"':
                    rust_raw(start)
                    continue
            if lang == "rust" and word in ("b", "c") and at(0) == '"':
                quoted(start, '"', False)
                continue
            if lang == "rust" and word == "b" and at(0) == "'":
                quoted(start, "'", False)
                continue
            if python and 1 <= len(word) <= 2 and all(ch in "rRbBfFuU" for ch in word) and at(0) in ('"', "'"):
                q = at(0)
                quoted(start, q, at(1) == q and at(2) == q)
                continue
            push(word)
            continue
        st["i"] += 1
        if python:
            if c in "([{":
                st["depth"] += 1
            elif c in ")]}":
                st["depth"] = max(0, st["depth"] - 1)
        push(c)
    if python:
        if st["line"]:
            out.append(NEWLINE)
        out.extend([DEDENT] * (len(st["indents"]) - 1))

    # Trailing commas: the run of commas right before a closer goes, except the
    # single comma of a Python one-element tuple.
    result, commas = [], [0]
    for tok in out:
        if tok in ("(", "[", "{"):
            commas.append(0)
        elif tok == ",":
            commas[-1] += 1
        elif tok in (")", "]", "}"):
            total = commas[-1]
            trailing = 0
            while trailing < len(result) and result[len(result) - 1 - trailing] == ",":
                trailing += 1
            tuple_ = lang == "python" and tok == ")" and total == 1 and trailing == 1
            if not tuple_ and trailing:
                del result[len(result) - trailing:]
            if len(commas) > 1:
                commas.pop()
        result.append(tok)
    return result


def syntax_hash(data, name):
    lang = lang_for(name)
    if lang is None:
        raise SyntaxError_("unsupported file type")
    text = data.decode("utf-8")
    h = hashlib.sha256(f"CodePass/{MATERIAL_ID}\0{lang}\0".encode())
    for t in tokens(text, lang):
        b = t.encode()
        h.update(struct.pack(">I", len(b)) + b)
    return h.digest()
