# CodePass

[日本語](README.md)

Regenerate the **same** password for every site from a source-code file and one master secret — nothing is stored.
The CLI, the browser extension and the web demo all run the same Rust code.

```
source code + master secret + site → password
```

| | |
|---|---|
| **CLI** | `codepass get github.com --copy` |
| **Browser extension** | Click the icon on a login page and type your secret. It judges the page by the domain the browser actually has open, and refuses look-alike phishing domains. |
| **Web demo** | https://yotatameguchi-boop.github.io/codepass/ (no install, no network) |

> **Experimental.** The cryptographic design has not had an external review yet; do not use it for important accounts.
> Source code is not treated as a secret (it may be public). Security rests on the master secret, and optionally a security key.

## A repository is a keyring

| Property only code has | How CodePass uses it |
|---|---|
| Structure | Same password after reformatting or comments (`--material syntax`) |
| Functions | **One function per service** (`--symbol`): editing other functions changes nothing; editing it rotates only that service |
| Signed commits | **Only commits you signed count as material** (`--require-signed`) |
| History | Pin material to a commit (`--git`); old passwords come back from old commits |
| Volume (a repository) | **A whole directory or repository as material** (`--tree`); sealed, the private repository itself is a second factor |

## The code's meaning is the key

Register with `--material syntax` and the password follows the code's **syntax**, not its bytes:
adding comments, re-indenting, reformatting or adding trailing commas gives the **same** password;
renaming, changing logic or a string literal gives a **different** one.

```sh
codepass generate main.rs --site github.com --material syntax
codepass inspect main.rs     # show which tokens count
```

Rust, Python, JS/TS, Go, C/C++/C#/Java, Kotlin/Scala/Swift/Dart. A small lexer fully specified in docs/SPEC.md — not a
parser whose upgrades could change passwords — reproduced byte for byte by an independent Python implementation
(30,000 random inputs compared in CI).

## Your code as a second factor (sealing)

Normally the settings file keeps the code's hash, so a stolen settings file plus the secret is enough. After
`codepass profile seal-code` (or `generate --seal-code`) it keeps only a value that can be checked with the secret,
so a **private** code file becomes something you *have* — a second factor. Passwords do not change.
`codepass doctor` warns when the code is short or sits in a repository with a remote.

## Break-glass accounts for teams

`codepass --config team.json team init --threshold 2 --shares 3` splits a random team secret into three shares
(Shamir, via the `blahaj` crate); any two holders together reproduce the password of an emergency account, one alone
learns nothing, and the team secret is stored nowhere. Shares carry a checksum against typos.

## Rotating everything after a leak

`codepass rotate plan --reason secret|code|member|site` explains the steps and lists affected sites;
`rotate start --to new.json` creates a new profile (new salt, new secret or team shares, optionally new code),
and `rotate next` walks through the sites showing the old and the new password until `rotate status` is done.
After a member leaves, `rotate start --threshold 2 --shares 3` replaces the team secret: their old share stops working.

## Why source code?

Developers carry their code everywhere, version it with Git, and often care about a particular file (a first program,
a favourite project). CodePass uses it as personal material:

- **Remember one secret.** Per-site passwords are recomputed each time, so there is no vault to leak.
- **Git protects the material.** Pin it to a commit (`--git <tag>`) and editing the file, line-ending conversion or a new machine change nothing.
- **The code is not a secret.** Strength comes only from the secret (and an optional FIDO2 key).

Deterministic password generation is an old idea. CodePass focuses on making it **reproducible for years, on every
platform**, and on **showing evidence** for that: a written spec, an independent reference implementation, formal
verification, fuzzing and signed releases.

## Install

```sh
cargo install --locked codepass
cargo install --locked codepass --features fido2   # with security-key support
```

Prebuilt binaries for macOS, Linux and Windows, and the browser extension, are on
[Releases](https://github.com/yotatameguchi-boop/codepass/releases). Each file carries a Sigstore-signed SLSA build
provenance and an SBOM:

```sh
gh attestation verify codepass-v0.8.0-aarch64-apple-darwin.tar.gz -R yotatameguchi-boop/codepass
```

## Use

```sh
codepass init                                                 # creates a random salt
codepass profile export --output codepass-backup.json         # back the salt up
codepass generate keys/main.py --site github.com --git v1     # make and register a password
codepass get github.com --copy                                # later: by site name only
codepass doctor                                               # check the setup
codepass bench                                                # key-derivation time and brute-force cost
```

After typing the secret you see a three-word **check code** (e.g. `koala-torch-coconut`); a different one means a typo.
For registered sites a typo is caught for certain, because every entry is signed with a key derived from the secret.

## Security

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (Japanese) for assets, attackers, mitigations and residual risks.

| Goal | Mechanism |
|---|---|
| A leaked password does not reveal the others | Argon2id (64 MiB, 3 passes); `codepass bench` shows the brute-force cost |
| No password for phishing sites | Look-alikes of registered sites (Unicode TR39 confusables, mixed scripts, Punycode) are refused |
| Detect edits to the settings file | Each entry carries an HMAC-SHA256 signature keyed from the master key |
| A stolen secret is not enough (optional) | `init --hardware-key` mixes a FIDO2 key's hmac-secret into the master key (not yet tested on real hardware) |
| Keys never reach the disk | Core dumps off, `mlock`, zeroize; Linux also refuses ptrace |
| Untampered releases | SLSA provenance + SBOM, SHA-pinned Actions, cargo-deny, RustSec, OpenSSF Scorecard |

## Verification

- [docs/SPEC.md](docs/SPEC.md) (Japanese) specifies every byte; [docs/reference.py](docs/reference.py), written from the
  spec alone, must match [tests/vectors.rs](tests/vectors.rs) — checked in CI.
- **Kani** proves the rejection sampler is exactly uniform for every alphabet size CodePass uses (62–94).
- Five **cargo-fuzz** targets run on every push (45 s each) and weekly (10 min each). Fuzzing has already found and
  fixed a real idempotence bug in host normalization.
- proptest, a chi-square test, and CI on Linux, macOS and Windows.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo +nightly fuzz run derive_rules -- -max_total_time=60
cargo kani --lib
./scripts/build-web.sh        # WebAssembly for web/www and extension/
```

License: [MIT](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
