# Cybersecurity 101

[![CI](https://github.com/mmohamedkhaled/cybersecurity-101/actions/workflows/ci.yml/badge.svg)](https://github.com/mmohamedkhaled/cybersecurity-101/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A hands-on collection of small, self-contained Python implementations of
classical and modern cryptography, error-detection, number-theory primitives,
and applied networking maths — written for learning and light enough to read in
one sitting.

Every script is **import-safe** (no side effects on import) and ships with a
built-in `run_tests()` you can execute directly:

```bash
python3 caesar_cipher.py     # prints a short demo, then "All ... tests passed."
```

## Requirements

- **Python 3.10+** (the code uses PEP 604 `X | Y` type hints; tested on 3.12).
- **No dependencies for the core.** 27 of the 36 scripts run on the standard
  library alone. The other 9 use optional third-party packages (see below).

## Quick start

```bash
git clone <your-repo-url>
cd cybersecurity-101
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt     # optional: pulls in the AES / AI / Bloom extras
```

## Optional dependencies

Each entry is **optional** — install only the ones for the scripts you want to
run. With the package absent, the affected script prints a
`... skipped (missing dependency: X)` line and exits `0` instead of failing.

| Package | Used by | Purpose |
|---------|---------|---------|
| `pycryptodome` | `aes_cbc`, `aes_ecb`, `aes_ecb_pattern_leak`, `aes_inverse_steps` *(demo only)* | Real AES encryption for the demos |
| `cryptography` | `rsa_encrypt_decrypt` | 2048-bit OAEP RSA — **hard dependency** (imported at module level) |
| `numpy` | `aes_ecb_pattern_leak` | Byte-array backing the visualisation |
| `scipy` | `aes_sbox_analysis` | Chi-square uniformity test of the S-box |
| `matplotlib` | `aes_ecb_pattern_leak` | Renders `ecb_pattern.png` |
| `scikit-learn` | `caesar_random_forest`, `caesar_ngram_model` | RandomForest shift prediction |
| `mmh3`, `bitarray` | `bloom_filter` | Hashing + bit array for the Bloom filter |

## Learning Path (by difficulty)

Work through these in order — each level builds on the one before. Files stay
flat in the repo, so every one runs with `python3 <file>`.

### Level 1 — Foundations (one concept, basic maths)
- **`modulo.py`** — the remainder operator, the backbone of all crypto maths.
- **`modular_arithmetic.py`** — add and multiply inside a finite ring (mod *n*).
- **`modular_congruence.py`** — test equivalence classes: *a ≡ b (mod n)*.
- **`euler_totient.py`** — count numbers coprime to *n* (Euler's totient), the basis of RSA.
- **`caesar_cipher.py`** — shift letters, then break it with frequency analysis.
- **`xor_cipher.py`** — see why XOR is its own inverse (a stream-cipher primitive).
- **`xor_hash.py`** — build a trivial checksum-style hash from XOR.
- **`sha256.py`** — use a real cryptographic hash (SHA-256).
- **`password_strength.py`** — judge password strength with rule-based checks.

### Level 2 — Classic algorithms (small state machines, multi-step)
- **`modular_exponentiation.py`** — compute powers mod *n* step-by-step (fast reduction).
- **`modular_inverse.py`** — find the modular inverse via the extended Euclidean algorithm.
- **`primitive_root.py`** — detect generators of a multiplicative group.
- **`columnar_transposition.py`** — encrypt by rearranging columns (transposition).
- **`playfair.py`** — use a 5×5 keyword matrix for digraph substitution.
- **`checksum.py`** — generate and validate 4-/8-bit Internet-style checksums.
- **`crc.py`** — detect errors with polynomial (mod-2) division.
- **`salted_password_hash.py`** — store passwords safely with a per-user salt.
- **`hmac_auth.py`** — authenticate messages with HMAC + timing-safe verification.
- **`tcp_math.py`** — apply the arithmetic behind TCP/IP (headers, ports, DNS TTL).
- **`subnet.py`** — size and allocate CIDR subnets for a network.
- **`caesar_frequency_attack.py`** — crack Caesar automatically using English letter frequencies.

### Level 3 — Public-key, AES & applied ML
- **`diffie_hellman.py`** — agree on a shared secret over an open channel.
- **`rsa_modular_exponentiation.py`** — perform modular exponentiation *m = c^d mod n* with a trace.
- **`rsa_keygen.py`** — derive *n*, *φ(n)*, and the public/private key pair.
- **`rsa_signature.py`** — sign and verify messages with RSA.
- **`rsa_hash_signature.py`** — sign a SHA-256 digest for integrity + authenticity.
- **`rsa_encrypt_decrypt.py`** — use the `cryptography` library for real RSA encrypt/decrypt.
- **`aes_cbc.py`** — encrypt with AES-CBC (random key + IV).
- **`aes_ecb.py`** — see AES in its simplest form (ECB).
- **`aes_inverse_steps.py`** — walk the AES round transforms and their inverses by hand.
- **`aes_sbox_analysis.py`** — inspect the AES S-box and test its uniformity (chi-square).
- **`aes_subbytes.py`** — apply SubBytes and its inverse on a 4×4 state.
- **`aes_ecb_pattern_leak.py`** — visualise why ECB leaks plaintext patterns.
- **`bloom_filter.py`** — trade correctness for space with a probabilistic set.
- **`caesar_random_forest.py`** — train a model to predict the Caesar shift from letter frequencies.
- **`caesar_ngram_model.py`** — crack Caesar with char n-grams + RandomForest.

## What's inside

### Classical ciphers
| File | Description |
|------|-------------|
| `caesar_cipher.py` | Caesar shift cipher + single-letter frequency-analysis attack |
| `columnar_transposition.py` | Columnar transposition cipher |
| `playfair.py` | Playfair 5x5 keyword cipher |
| `xor_cipher.py` | Single-byte XOR stream cipher |

### Modern symmetric encryption (AES)
| File | Description |
|------|-------------|
| `aes_cbc.py` | AES-CBC encrypt/decrypt with random key + IV *(needs pycryptodome)* |
| `aes_ecb.py` | Minimal AES-ECB demo *(needs pycryptodome)* |
| `aes_ecb_pattern_leak.py` | Visualises the ECB "pattern leak" weakness *(needs pycryptodome, matplotlib)* |
| `aes_inverse_steps.py` | Forward + inverse AES round transforms (SubBytes, ShiftRows, MixColumns) worked by hand |
| `aes_sbox_analysis.py` | AES SubBytes + chi-square uniformity test *(needs scipy)* |
| `aes_subbytes.py` | SubBytes / inverse-SubBytes on a 4x4 state (standard generated AES S-box) |

### Asymmetric crypto & key exchange
| File | Description |
|------|-------------|
| `rsa_modular_exponentiation.py` | Verbose modular exponentiation `m = c^d mod n` |
| `rsa_keygen.py` | RSA key derivation: `n`, `phi(n)`, public/private keys |
| `rsa_signature.py` | RSA sign + verify, plus valid `e` enumeration |
| `rsa_hash_signature.py` | RSA signature over a SHA-256 digest |
| `diffie_hellman.py` | Diffie-Hellman shared-secret agreement |
| `rsa_encrypt_decrypt.py` | Real RSA encrypt/decrypt via `cryptography` *(needs cryptography)* |

### Hashing, MAC & passwords
| File | Description |
|------|-------------|
| `sha256.py` | SHA-256 digest wrapper |
| `hmac_auth.py` | HMAC-SHA256 generation + timing-safe verification |
| `salted_password_hash.py` | Salted password hashing with a `verify_password` helper |
| `xor_hash.py` | Simple bit-by-bit XOR hash with a trace |
| `bloom_filter.py` | Probabilistic Bloom filter with false-positive simulation *(needs mmh3, bitarray)* |
| `password_strength.py` | Rule-based password strength scorer |

### Error detection
| File | Description |
|------|-------------|
| `checksum.py` | 4- and 8-bit Internet-style checksum (generate + validate) |
| `crc.py` | Cyclic Redundancy Code generator + validator, any polynomial |

### Number theory
| File | Description |
|------|-------------|
| `modulo.py` | Basic modulo |
| `modular_arithmetic.py` | Modular addition and multiplication |
| `modular_exponentiation.py` | Step-by-step modular exponentiation |
| `modular_congruence.py` | Congruence test `a ≡ b (mod n)` |
| `euler_totient.py` | Euler's totient `phi(n)` with its coprime list |
| `modular_inverse.py` | Extended Euclidean algorithm → modular inverse |
| `primitive_root.py` | Primitive-root detection and enumeration |

### Networking maths
| File | Description |
|------|-------------|
| `subnet.py` | CIDR subnet sizing + multi-location allocation |
| `tcp_math.py` | TCP header/handshake maths, port classification, DNS TTL/birthday-attack |

### AI vs. crypto (experiments)
| File | Description |
|------|-------------|
| `caesar_frequency_attack.py` | Break Caesar via English letter-frequency scoring |
| `caesar_random_forest.py` | RandomForest learns the Caesar shift *(needs scikit-learn)* |
| `caesar_ngram_model.py` | Char n-gram + RandomForest Caesar cracker *(needs scikit-learn)* |

## Testing

Each module ends with a `run_tests()` function (plain `assert`s, no test
framework required). Run a single file:

```bash
python3 crc.py
```

Or run the whole suite at once:

```bash
for f in *.py; do echo "== $f =="; python3 "$f" | tail -n 1; done
```

Most files whose optional dependency is missing print a
`... skipped (missing dependency: X)` line and exit `0`. The single exception
is `rsa_encrypt_decrypt.py`, which imports `cryptography` at module level and
needs that package installed to run.

## Status

All 36 scripts pass their built-in test suites (with the optional packages
from `requirements.txt` installed). On a minimal install every affected file
skips gracefully except `rsa_encrypt_decrypt.py`, which needs `cryptography`
installed to run.

## Layout notes

- Filenames use `snake_case`; demo/test code is always guarded by
  `if __name__ == "__main__":`.

## Contributing

Contributions are welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) for
the conventions every module follows (Google-style docstrings, type hints, an
`assert`-based `run_tests()` suite, and graceful optional-dependency handling).
This repo follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

Quick checks before opening a PR:

```bash
make all      # ruff + mypy + every module's run_tests()
```

## License

Released under the [MIT License](LICENSE) — © 2026 mmohamedkhaled.

If you find a real bug or logic error, please report it **privately** via a
[Security Advisory](https://github.com/mmohamedkhaled/cybersecurity-101/security/advisories/new)
(see [`SECURITY.md`](SECURITY.md)) rather than a public issue.
