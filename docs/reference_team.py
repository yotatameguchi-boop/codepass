# Independent reference for team profiles (docs/SPEC.md "チームの共有"): share format and
# checksum, Shamir recovery over GF(256) with polynomial 0x11d, verifier, team master key.
import hashlib
import hmac


def _hkdf(salt, ikm, info, n):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    out = b""
    i = 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def gf_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11D
        b >>= 1
    return r


def gf_inv(a):
    return next(b for b in range(1, 256) if gf_mul(a, b) == 1)


def checksum(set_id, threshold, x, y):
    return hashlib.sha256(b"CodePass/share/v1\0" + set_id.encode() + bytes([threshold, x]) + y).hexdigest()[:8]


def format_share(set_id, threshold, x, y):
    groups = "-".join(y[i:i + 4].hex() for i in range(0, 32, 4))
    return f"cpshare1-{set_id}-{threshold}-{x:02x}-{groups}-{checksum(set_id, threshold, x, y)}"


def parse_share(text):
    parts = "".join(text.split()).lower().split("-")
    assert len(parts) == 13 and parts[0] == "cpshare1"
    set_id, threshold, x = parts[1], int(parts[2]), int(parts[3], 16)
    y = bytes.fromhex("".join(parts[4:12]))
    assert checksum(set_id, threshold, x, y) == parts[12], "checksum"
    return set_id, threshold, x, y


def combine(shares):
    """Lagrange interpolation at x = 0 for each byte."""
    xs = [s[2] for s in shares]
    out = bytearray()
    for b in range(32):
        acc = 0
        for i, s in enumerate(shares):
            term = s[3][b]
            for j, xj in enumerate(xs):
                if j != i:
                    term = gf_mul(term, gf_mul(xj, gf_inv(xj ^ xs[i])))
            acc ^= term
        out.append(acc)
    return bytes(out)


def verifier(secret):
    return _hkdf(b"CodePass/team/v1", secret, b"CodePass/team-verifier/v1", 16).hex()


def team_master(secret, salt):
    return _hkdf(salt, secret, b"CodePass/team-master/v1", 32)
