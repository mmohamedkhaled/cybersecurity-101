"""AES SubBytes substitution with a chi-square uniformity check.

Applies the standard AES S-box to random bytes, tallies the resulting hex-digit
frequencies, and runs a chi-square goodness-of-fit test against a uniform
distribution. The S-box is generated from the AES specification (GF(2^8)
inverse + affine map), so it is the complete, correct 256-entry table.
"""

import random
import string

try:
    from scipy.stats import chisquare
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


NUM_HEX_CHARS = 16
HEX_ALPHABET = string.digits + "ABCDEF"
P_VALUE_THRESHOLD = 0.05
DEFAULT_NUM_TESTS = 10000


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) modulo the AES polynomial 0x11B."""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return product


def _gf_inverse(a: int) -> int:
    """Return the multiplicative inverse of ``a`` in GF(2^8); 0 maps to 0."""
    if a == 0:
        return 0
    result, base, exponent = 1, a, 254
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exponent >>= 1
    return result


def _affine_transform(b: int) -> int:
    """Apply the AES affine transformation to byte ``b``."""
    out = 0
    for i in range(8):
        bit = (
            ((b >> i) & 1)
            ^ ((b >> ((i + 4) % 8)) & 1)
            ^ ((b >> ((i + 5) % 8)) & 1)
            ^ ((b >> ((i + 6) % 8)) & 1)
            ^ ((b >> ((i + 7) % 8)) & 1)
            ^ ((0x63 >> i) & 1)
        )
        out |= bit << i
    return out


# Standard AES S-box, complete (256 entries) and a valid permutation.
AES_S_BOX = [_affine_transform(_gf_inverse(i)) for i in range(256)]


def sub_bytes(byte: int) -> int:
    """Substitute a single byte through the AES S-box.

    Args:
        byte: An integer in ``[0, 255]``.

    Returns:
        The substituted byte value.

    Raises:
        ValueError: If ``byte`` is outside ``[0, 255]``.
    """
    if 0 <= byte < 256:
        return AES_S_BOX[byte]
    raise ValueError(f"byte {byte} is outside the valid range 0-255")


def generate_random_byte() -> int:
    """Return a uniformly random byte in ``[0, 255]``."""
    return random.randint(0, 255)


def count_frequencies(hex_string: str) -> dict[str, int]:
    """Count occurrences of each hex digit (0-9, A-F) in ``hex_string``.

    Args:
        hex_string: A hexadecimal string (case-insensitive).

    Returns:
        A mapping from each hex character to its count.
    """
    frequencies: dict[str, int] = dict.fromkeys(HEX_ALPHABET, 0)
    for char in hex_string.upper():
        if char in frequencies:
            frequencies[char] += 1
    return frequencies


def chi_square_test(
    frequencies: dict[str, int],
    num_categories: int = NUM_HEX_CHARS,
) -> tuple[float, float]:
    """Run a chi-square goodness-of-fit test against a uniform distribution.

    Args:
        frequencies: Observed counts keyed by hex character.
        num_categories: Number of categories (default 16 hex digits).

    Returns:
        A ``(chi2_statistic, p_value)`` tuple.

    Raises:
        ImportError: If ``scipy`` is not installed.
    """
    if not SCIPY_AVAILABLE:
        raise ImportError("scipy is required for chi_square_test")
    observed = [frequencies[char] for char in HEX_ALPHABET]
    total_observed = sum(observed)
    expected = [total_observed / num_categories] * num_categories
    chi2_stat, p_value = chisquare(observed, expected)
    print(f"Chi-square statistic: {chi2_stat:.2f}")
    print(f"P-value: {p_value:.4f}")
    if p_value < P_VALUE_THRESHOLD:
        print("The distribution is significantly different from a uniform distribution.")
    else:
        print("The distribution is not significantly different from a uniform distribution.")
    return float(chi2_stat), float(p_value)


def test_statistical_appearance(num_tests: int = DEFAULT_NUM_TESTS) -> dict[str, int]:
    """Substitute many random bytes and assess hex-digit uniformity.

    Args:
        num_tests: Number of random bytes to substitute.

    Returns:
        The hex-character frequency mapping.
    """
    hex_string = "".join(format(sub_bytes(generate_random_byte()), "02X") for _ in range(num_tests))
    frequencies = count_frequencies(hex_string)
    print("Frequencies of hexadecimal characters:")
    for char in sorted(frequencies):
        print(f"{char}: {frequencies[char]}")
    expected_frequency = num_tests * 2 / NUM_HEX_CHARS
    print(f"\nExpected frequency (uniform distribution): {expected_frequency:.1f}")
    chi_square_test(frequencies)
    return frequencies


def run_tests() -> None:
    """Validate the S-box and, when scipy is present, the uniformity test."""
    assert len(AES_S_BOX) == 256, "S-box must have 256 entries"
    assert len(set(AES_S_BOX)) == 256, "S-box must be a permutation"
    assert AES_S_BOX[0] == 0x63, "S-box[0x00] should be 0x63"
    assert AES_S_BOX[0x10] == 0xCA, "S-box[0x10] should be 0xCA"
    for byte in range(256):
        assert 0 <= sub_bytes(byte) <= 0xFF

    if not SCIPY_AVAILABLE:
        print("AES S-box tests passed; chi-square test skipped (missing dependency: scipy).")
        return

    frequencies = test_statistical_appearance(DEFAULT_NUM_TESTS)
    expected = DEFAULT_NUM_TESTS * 2 / NUM_HEX_CHARS
    for char, count in frequencies.items():
        assert expected * 0.6 < count < expected * 1.4, f"hex digit {char} is far from uniform"
    chi2_stat, p_value = chi_square_test(frequencies)
    assert 0.0 <= p_value <= 1.0
    print("All AES S-box analysis tests passed.")


if __name__ == "__main__":
    run_tests()
