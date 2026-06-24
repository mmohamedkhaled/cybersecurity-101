# Contributing to Cybersecurity 101

Thanks for your interest in improving this repository! These scripts are meant
to be **readable teaching examples**, so contributions should favour clarity and
correctness over cleverness.

## Ground rules

- Be kind and respectful. This project follows the
  [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
- **Educational scope.** Every implementation is a *learning* example of a
  concept. It is **not** production cryptography — please don't add fixes that
  trade readability for real-world hardening unless the weakness is clearly
  documented.

## Before you start

1. You need **Python 3.10+**.
2. Set up a virtual environment and install tooling + optional deps:

   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install ruff mypy
   pip install -r requirements.txt      # optional deps so every suite runs
   ```

## Adding or changing a script

Each module follows a few conventions — please match them:

- **Flat, runnable file.** A learner runs it with `python3 <file>.py`.
- **`snake_case` filename and functions.**
- **Google-style docstrings** with `Args`, `Returns`, and `Raises` sections.
- **Type hints** on every public function (`from __future__` is not used; we
  rely on Python 3.10+ builtin generics and `X | Y` unions).
- **Import-safe:** no side effects on import. All demo/test code lives under
  an `if __name__ == "__main__":` guard.
- **A `run_tests()` function** using plain `assert` statements covering
  standard *and* edge cases. It prints `All <topic> tests passed.` on success.
- **Graceful optional-dependency handling.** If a script needs a third-party
  package, import it lazily (inside a `try/except ImportError`) and print a
  `... skipped (missing dependency: X)` line that exits `0`, so the suite
  stays green on a minimal install. (`rsa_encrypt_decrypt.py` is the one
  exception and documents its hard dependency.)

## Quality gates (CI runs these too)

```bash
ruff check .        # lint
mypy *.py           # type-check
make test           # run every module's suite
```

Your PR must pass `ruff check`, `mypy`, and all module suites. You can run
everything at once with `make all`.

## Commit & PR style

- Use clear, imperative commit messages (e.g. `Fix modular exponentiation
  result for modulus 1`).
- Keep PRs focused — one concept or fix per PR.
- Fill in the pull-request template and link any related issue.

## Reporting bugs

Open a [GitHub Issue](https://github.com/mmohamedkhaled/cybersecurity-101/issues)
using the Bug Report template. For security-sensitive matters, see
[SECURITY.md](SECURITY.md) instead of opening a public issue.
