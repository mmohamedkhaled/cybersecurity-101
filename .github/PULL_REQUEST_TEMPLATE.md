<!--
Thanks for contributing! Please read CONTRIBUTING.md before opening this PR.
Keep PRs focused: one concept or fix per PR.
-->

## Summary

<!-- What does this PR change, and why? -->

## Related issue

<!-- "Closes #123", "Refs #123", or "N/A". -->

## Checklist

Please confirm each item below (tick the boxes). Your PR must pass `make all`
(ruff + mypy + every module's `run_tests()`).

- [ ] `ruff check .` passes
- [ ] `mypy *.py` passes
- [ ] All module suites pass (`make test`)
- [ ] New/changed code is **import-safe** (no side effects on import; demo/test code is under `if __name__ == "__main__":`)
- [ ] Public functions have **type hints** and **Google-style docstrings** (`Args` / `Returns` / `Raises`)
- [ ] `run_tests()` covers standard **and** edge cases
- [ ] Any new third-party dependency is imported **lazily** and degrades gracefully (prints `... skipped (missing dependency: X)`, exits `0`)
- [ ] `README.md` / `requirements.txt` updated if a new script or dependency was added
- [ ] Commit messages are clear and imperative (e.g. `Fix modular exponentiation result for modulus 1`)
