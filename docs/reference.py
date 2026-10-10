# Independent reference implementation of docs/SPEC.md (v1 and v2).
# Needs: pip install argon2-cffi
# Run from the repository root. Prints the same values pinned in tests/vectors.rs.
import hashlib, hmac, re, struct, unicodedata
from argon2.low_level import hash_secret_raw, Type

L = b"abcdefghijklmnopqrstuvwxyz"; U = L.upper(); D = b"0123456789"
SY = b"!#$%&()*+,-./:;<=>?@[]^_{|}~"
WORDS = re.findall(r'"([a-z]+)"', open("src/words.rs").read())
assert len(WORDS) == 256


def hkdf(salt, ikm, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest(); t = b""; out = b""; i = 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:n]


def master_key(secret, salt):
    return hash_secret_raw(secret.encode(), salt, time_cost=3, memory_cost=65536, parallelism=1,
                           hash_len=32, type=Type.ID, version=19)


def check_code(master):
    return "-".join(WORDS[b] for b in hkdf(b"CodePass/HKDF/v1", master, b"CodePass/check-code/v1", 3))


def site_v2(site):
    cur = site_pass_v2(site)
    for _ in range(8):
        nxt = site_pass_v2(cur)
        if nxt == cur: break
        cur = nxt
    return cur


def site_pass_v2(site):
    t = unicodedata.normalize("NFKC", site).strip()
    if "://" in t: t = t.split("://", 1)[1]
    t = re.split(r"[/?#]", t, maxsplit=1)[0]
    if "@" in t: t = t.rsplit("@", 1)[1]
    if ":" in t:
        host, port = t.rsplit(":", 1)
        if (host.startswith("[") and host.endswith("]") or ":" not in host) and re.fullmatch(r"[0-9]+", port, re.ASCII): t = host
    t = t.lstrip()
    while t and (t[-1] == "." or t[-1].isspace()): t = t[:-1]
    h = unicodedata.normalize("NFKC", t.lower())
    while h and (h[-1] == "." or h[-1].isspace()): h = h[:-1]
    return h[4:] if h.startswith("www.") and "." in h[4:] else h


def gen(master, code_hash, site, acct, length, cs, rev, req, ver=1, symbols=None):
    if ver == 1:
        keys = [unicodedata.normalize("NFC", site), unicodedata.normalize("NFC", acct)]
    else:
        keys = [site_v2(site), unicodedata.normalize("NFC", acct.strip())]
    sym = b"" if cs == "alnum" else (symbols.encode() if symbols else SY)
    ctx = f"CodePass/context/v{ver}\0".encode() + code_hash
    for k in keys:
        b = k.encode(); ctx += struct.pack(">I", len(b)) + b
    ctx += struct.pack(">I", rev) + bytes([length, 1 if cs == "strong" else 2, int(req)])
    if ver >= 2: ctx += bytes([len(sym)]) + sym
    key = hkdf(f"CodePass/HKDF/v{ver}".encode(), master, ctx)
    a = L + U + D + sym; lim = 256 // len(a) * len(a)
    label = f"CodePass/stream/v{ver}\0".encode()

    def stream():
        i = 0
        while True:
            yield from hmac.new(key, label + struct.pack(">Q", i), hashlib.sha256).digest(); i += 1
    st = stream()
    while True:
        c = bytearray()
        while len(c) < length:
            b = next(st)
            if b < lim: c.append(a[b % len(a)])
        classes = [L, U, D] + ([sym] if sym else [])
        if not req or all(any(x in cl for x in c) for cl in classes): return c.decode()


src = b'fn main() {\n    println!("hello");\n}\n'
m = master_key("correct horse battery staple 2026", b"CodePassTestSalt")
h = hashlib.sha256(src).digest()
for args in [("github.com", "", 24, "strong", 1, True), ("github.com", "personal", 24, "strong", 2, True),
             ("example.com", "", 8, "alnum", 1, True), ("café.example", "ゆうた", 64, "strong", 1, False)]:
    print("VECTOR", args[0], gen(m, h, *args))
for args, sym in [(("https://www.GitHub.com/login", " personal ", 24, "strong"), None),
                  (("example.com", "", 16, "strong"), "!#$%@"), (("Bücher.example", "", 12, "alnum"), None)]:
    print("VECTOR2", site_v2(args[0]), gen(m, h, *args, 1, True, ver=2, symbols=sym))
print("CHECK", check_code(m))
