"""Verbose modular exponentiation for RSA decryption.

Shows the step-by-step reduction of base**exp mod mod using a small-chunk
split of the exponent (exp = EXP_CHUNK * q + r) so that RSA decryption
M = C**d mod n can be followed by hand. The numeric result is also returned
alongside the human-readable steps so it can be asserted in tests.
"""


EXP_CHUNK = 5
MIN_MODULUS = 2


def mod_exp_verbose(base: int, exp: int, mod: int) -> tuple[str, int]:
    """Explain and compute base**exp mod mod by splitting the exponent.

    Args:
        base: The base value (e.g. the RSA ciphertext C).
        exp: The non-negative exponent (e.g. the private exponent d).
        mod: The modulus (e.g. n); must be >= 2.

    Returns:
        A tuple (steps_text, result) where steps_text is the formatted
        derivation and result equals base**exp mod mod.

    Raises:
        ValueError: If mod < 2, base < 0, or exp < 0.
    """
    if base < 0:
        raise ValueError(f"base must be >= 0, got {base}")
    if exp < 0:
        raise ValueError(f"exponent must be >= 0, got {exp}")
    if mod < MIN_MODULUS:
        raise ValueError(f"modulus must be >= {MIN_MODULUS}, got {mod}")

    steps: list[str] = []
    quotient = exp // EXP_CHUNK
    remainder = exp % EXP_CHUNK

    steps.append(f"M = C^d mod n = {base}^{exp} mod {mod}\n")
    steps.append(
        f"      = (( {base}^{EXP_CHUNK} mod {mod} )^{quotient} mod {mod})"
        f"( {base}^{remainder} mod {mod} ) mod {mod}"
    )

    base_pow_chunk = pow(base, EXP_CHUNK)
    steps.append(
        f"      = (( {base_pow_chunk} mod {mod} )^{quotient} mod {mod})"
        f"( {base}^{remainder} mod {mod} ) mod {mod}"
    )

    reduced_pow_chunk = base_pow_chunk % mod
    steps.append(
        f"      = ( {reduced_pow_chunk}^{quotient} mod {mod})"
        f"( {base}^{remainder} mod {mod} ) mod {mod}"
    )

    left_factor = pow(reduced_pow_chunk, quotient, mod)
    right_factor = pow(base, remainder, mod)
    steps.append(f"      = ( {left_factor} )( {right_factor} ) mod {mod}")

    result = (left_factor * right_factor) % mod
    steps.append(f"      = ( {left_factor} * {right_factor} ) mod {mod}")
    steps.append(f"      = {result}")

    return "\n".join(steps), result


def run_tests() -> None:
    text, result = mod_exp_verbose(10, 23, 14)
    assert result == pow(10, 23, 14)
    assert result == 12
    assert isinstance(text, str) and "12" in text

    _, small = mod_exp_verbose(10, 3, 14)
    assert small == pow(10, 3, 14)

    _, zero_exp = mod_exp_verbose(5, 0, 7)
    assert zero_exp == 1

    for base, exp, mod in [(2, 10, 1000), (7, 13, 19), (3, 0, 5), (9, 1, 4)]:
        _, value = mod_exp_verbose(base, exp, mod)
        assert value == pow(base, exp, mod)

    try:
        mod_exp_verbose(5, 3, 1)
        raise AssertionError("mod_exp_verbose should reject mod < 2")
    except ValueError:
        pass

    try:
        mod_exp_verbose(5, -1, 7)
        raise AssertionError("mod_exp_verbose should reject negative exp")
    except ValueError:
        pass

    try:
        mod_exp_verbose(-5, 3, 7)
        raise AssertionError("mod_exp_verbose should reject negative base")
    except ValueError:
        pass

    print("All RSA mod-exp tests passed.")


if __name__ == "__main__":
    CIPHERTEXT = 10
    PRIVATE_EXP = 23
    MODULUS = 14
    steps_text, decrypted = mod_exp_verbose(CIPHERTEXT, PRIVATE_EXP, MODULUS)
    print(steps_text)
    print(f"\nNumeric result: {decrypted}")
    print()
    run_tests()
