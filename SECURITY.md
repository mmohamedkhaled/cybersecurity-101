# Security Policy

## ⚠️ Educational software — not for production use

This repository is a **learning lab**. The implementations (textbook RSA with
no padding, single-iteration SHA-256 password hashing, ECB mode, toy key sizes,
fixed Caesar shifts, etc.) are written to be **read and understood**, not to
protect real data. Several files deliberately demonstrate known weaknesses.

**Do not use any code here to secure real systems, data, or communications.**

For production cryptography use vetted libraries such as
[`cryptography`](https://cryptography.io/) or
[`pycryptodome`](https://www.pycryptodome.org/) (this repo already uses both
for its *demos*), and follow current best practices (e.g. AEAD modes like
AES-GCM, Argon2/bcrypt/scrypt for passwords, RSA-OAEP/PSS).

## Reporting a vulnerability in this repository

Found a real bug — e.g. an incorrect result, a crash on valid input, or a logic
error in an algorithm? Please report it **responsibly**:

1. **Do not open a public GitHub issue** for security-sensitive problems.
2. Use GitHub's private reporting:
   [**Report a vulnerability**](https://github.com/mmohamedkhaled/cybersecurity-101/security/advisories/new)
   (Security → Advisories → New draft advisory), **or**
3. Contact the maintainer privately via their GitHub profile.

Please include:

- The affected file and a minimal reproducer.
- What you expected vs. what actually happened.
- Your Python version and installed dependencies.

You should get an acknowledgement within a few days.

## Scope

In scope: correctness bugs, crashes on valid input, and clear logical errors in
the implementations.

Out of scope (these are **intentional** teaching demonstrations, not bugs):
- Use of textbook/unpadded RSA, ECB mode, small key sizes, single-iteration
  hashes, deterministic signatures, MITM-vulnerable Diffie–Hellman, etc. — these
  weaknesses are the lesson and are documented in each module's docstring.

## Supported versions

Only the latest `main` branch is supported.
