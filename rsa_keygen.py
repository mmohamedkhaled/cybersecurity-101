"""Step-by-step RSA key-parameter derivation for a worked example.

Derives n = p*q, phi(n) = (p-1)*(q-1), verifies that d is the modular inverse
of e modulo phi(n), and reports the public/private keys. Numeric values are
also returned so the worked solution can be checked programmatically.
"""


def rsa_key_params(p: int, q: int, e: int, d: int) -> dict[str, int | bool]:
    """Compute the core RSA key parameters from primes p, q and exponents e, d.

    Args:
        p: First prime factor.
        q: Second prime factor.
        e: Public exponent.
        d: Candidate private exponent.

    Returns:
        A dict with keys 'n', 'phi_n', 'inverse_check' (value of (e*d) mod
        phi_n), and 'is_inverse' (True iff inverse_check == 1).

    Raises:
        ValueError: If p or q < 2, or e or d < 1.
    """
    if p < 2:
        raise ValueError(f"p must be >= 2, got {p}")
    if q < 2:
        raise ValueError(f"q must be >= 2, got {q}")
    if e < 1:
        raise ValueError(f"e must be >= 1, got {e}")
    if d < 1:
        raise ValueError(f"d must be >= 1, got {d}")

    n = p * q
    phi_n = (p - 1) * (q - 1)
    inverse_check = (e * d) % phi_n
    return {
        "n": n,
        "phi_n": phi_n,
        "inverse_check": inverse_check,
        "is_inverse": inverse_check == 1,
    }


def rsa_verbose_steps(p: int, q: int, e: int, d: int) -> tuple[str, dict[str, int | bool]]:
    """Print and return the worked RSA key-parameter derivation.

    Args:
        p: First prime factor.
        q: Second prime factor.
        e: Public exponent.
        d: Candidate private exponent.

    Returns:
        A tuple (steps_text, params) where params is the dict produced by
        rsa_key_params.

    Raises:
        ValueError: If p or q < 2, or e or d < 1.
    """
    params = rsa_key_params(p, q, e, d)
    n = params["n"]
    assert isinstance(n, int)
    phi_n = params["phi_n"]
    assert isinstance(phi_n, int)
    inverse_check = params["inverse_check"]
    assert isinstance(inverse_check, int)

    steps: list[str] = []
    steps.append("(a) What is the value of n?")
    steps.append(f"n = p * q = {p} * {q} = {n}\n")

    steps.append("(b) What is F(n) ?")
    steps.append(f"F(n) = (p - 1) * (q - 1) = {p - 1} * {q - 1} = {phi_n}\n")

    steps.append(f"(c) Show that the value d = {d} is the modulo F(n) inverse of e.")
    steps.append(
        f"( e * d ) mod F(n) = ( {e} * {d} ) mod {phi_n} = {e * d} mod {phi_n} = {inverse_check}"
    )
    if params["is_inverse"]:
        steps.append("=> d is the correct modular inverse of e\n")
    else:
        steps.append("=> d is NOT the correct modular inverse of e\n")

    steps.append("(d) What is the corresponding public key for these values?")
    steps.append(f"public key = {{ e, n }} = {{ {e}, {n} }}\n")

    steps.append("(e) What is the corresponding private key for these values?")
    steps.append(f"private key = {{ d, n }} = {{ {d}, {n} }}")

    return "\n".join(steps), params


def run_tests() -> None:
    params = rsa_key_params(3, 11, 7, 3)
    assert params["n"] == 33
    assert params["phi_n"] == 20
    assert params["inverse_check"] == 1
    assert params["is_inverse"] is True

    text, returned_params = rsa_verbose_steps(3, 11, 7, 3)
    assert returned_params["n"] == 33
    assert returned_params["phi_n"] == 20
    assert "33" in text and "20" in text

    bad = rsa_key_params(3, 11, 7, 4)
    assert bad["inverse_check"] == (7 * 4) % 20
    assert bad["is_inverse"] is False

    try:
        rsa_key_params(1, 11, 7, 3)
        raise AssertionError("rsa_key_params should reject p < 2")
    except ValueError:
        pass

    try:
        rsa_key_params(3, 11, 0, 3)
        raise AssertionError("rsa_key_params should reject e < 1")
    except ValueError:
        pass

    print("All RSA phi(n) tests passed.")


if __name__ == "__main__":
    P = 3
    Q = 11
    E = 7
    D = 3
    steps_text, key_params = rsa_verbose_steps(P, Q, E, D)
    print(steps_text)
    print()
    run_tests()
