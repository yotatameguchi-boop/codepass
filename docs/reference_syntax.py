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
SPACES = set(" \t\n\r\x0b\x0c\x85\xa0\u1680\u2028\u2029\u202f\u205f\u3000\ufeff") | {chr(c) for c in range(0x2000, 0x200B)}


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


# ---- Symbol material (docs/SPEC.md "関数単位の材料") ----

SYMBOL_MATERIAL_ID = "symbol-v1"
DEFINERS = ["fn", "func", "function", "def", "class", "struct", "enum", "trait", "interface", "type", "impl", "mod",
            "module", "object", "fun", "val", "var", "let", "const", "static", "union", "namespace", "record", "mut"]
NOT_A_TYPE = ["if", "while", "for", "switch", "return", "else", "catch", "sizeof", "new", "case", "do", "throw", "await"]


def is_word_token(t):
    return t != "" and all(is_word(c) for c in t)


def c_like_end(toks, at):
    rnd = 0
    j = at + 1
    while j < len(toks):
        t = toks[j]
        if t in ("(", "["):
            rnd += 1
        elif t in (")", "]"):
            rnd -= 1
        elif t == ";" and rnd <= 0:
            return j + 1, False
        elif t == "{" and rnd <= 0:
            braces = 0
            for k in range(j, len(toks)):
                if toks[k] == "{":
                    braces += 1
                elif toks[k] == "}":
                    braces -= 1
                    if braces == 0:
                        return k + 1, True
            return len(toks), True
        j += 1
    return len(toks), False


def python_block_end(toks, start):
    j = start
    while j < len(toks) and toks[j] != NEWLINE:
        j += 1
    if j + 1 < len(toks) and toks[j + 1] == INDENT:
        level = 0
        for k in range(j + 1, len(toks)):
            if toks[k] == INDENT:
                level += 1
            elif toks[k] == DEDENT:
                level -= 1
                if level == 0:
                    return k + 1
        return len(toks)
    return min(j + 1, len(toks))


def line_end(toks, start):
    j = start
    while j < len(toks) and toks[j] != NEWLINE:
        j += 1
    return min(j + 1, len(toks))


def definitions(toks, lang):
    out = []
    for i, name in enumerate(toks):
        if not is_word_token(name) or name in DEFINERS:
            continue
        prev = toks[i - 1] if i > 0 else None
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        names_something = not (nxt is not None and is_word_token(nxt))
        after_lifetime = i >= 2 and toks[i - 2] == "'"
        if prev is not None and prev in DEFINERS and names_something and not after_lifetime:
            start = i - 1
            if lang == "python":
                end = python_block_end(toks, start) if toks[start] in ("def", "class") else line_end(toks, start)
            else:
                end = c_like_end(toks, i)[0]
            out.append((name, start, end))
            continue
        if lang == "python":
            if prev in (None, NEWLINE, INDENT, DEDENT) and nxt == "=":
                out.append((name, i, line_end(toks, i)))
            continue
        type_like = prev is not None and (
            (is_word_token(prev) and prev not in NOT_A_TYPE) or prev in ("*", "&", ">", "]", ")"))
        if type_like and nxt == "(":
            end, braced = c_like_end(toks, i)
            if braced:
                out.append((name, i, end))
    return out


def symbol_hash(data, file_name, name):
    lang = lang_for(file_name)
    if lang is None or not is_word_token(name):
        raise SyntaxError_("unsupported")
    toks = tokens(data.decode("utf-8"), lang)
    found = [d for d in definitions(toks, lang) if d[0] == name]
    if not found:
        raise SyntaxError_("no such definition")
    _, start, end = found[0]
    h = hashlib.sha256(f"CodePass/{SYMBOL_MATERIAL_ID}\0{lang}\0{name}\0".encode())
    for t in toks[start:end]:
        b = t.encode()
        h.update(struct.pack(">I", len(b)) + b)
    return h.digest()
