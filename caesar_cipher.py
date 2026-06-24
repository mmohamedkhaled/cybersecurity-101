"""Caesar cipher utilities: encryption/decryption and frequency-analysis attack."""

import string
from collections import Counter

ALPHABET_SIZE = 26


def caesar_cipher(text: str, shift: int) -> str:
    """Apply a Caesar shift to ``text``.

    Each letter is shifted by ``shift`` positions within its own case,
    wrapping around the alphabet. Non-letter characters are left unchanged.

    Args:
        text: The plaintext or ciphertext to transform.
        shift: Positions to shift. Positive shifts move forward (encrypt);
            negative shifts move backward (decrypt).

    Returns:
        The transformed string, preserving length, casing, and non-letters.
    """
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % ALPHABET_SIZE + base)
        else:
            result += char
    return result


def frequency_analysis_decrypt(ciphertext: str) -> str:
    """Break a Caesar cipher via single-letter frequency analysis.

    Assumes the most frequent letter in ``ciphertext`` maps to ``'e'`` (the
    most common letter in English), derives the shift, and returns the
    plaintext. This is a statistical heuristic and works best on longer,
    typical English text.

    Args:
        ciphertext: The encrypted text to decrypt.

    Returns:
        The best-guess decrypted plaintext.

    Raises:
        ValueError: If ``ciphertext`` contains no letters.
    """
    letter_freq = Counter(
        char for char in ciphertext.lower() if char in string.ascii_lowercase
    )
    if not letter_freq:
        raise ValueError("ciphertext must contain at least one letter")

    most_common_letter, _ = letter_freq.most_common(1)[0]
    shift = ord(most_common_letter) - ord('e')
    return caesar_cipher(ciphertext, -shift)


def run_tests() -> None:
    """Sanity checks for the cipher and frequency-analysis functions."""
    # Standard encryption
    assert caesar_cipher("abc", 1) == "bcd"
    # Wrap-around at the end of the alphabet
    assert caesar_cipher("xyz", 3) == "abc", "lowercase wrap-around failed"
    assert caesar_cipher("XYZ", 3) == "ABC", "uppercase wrap-around failed"
    # Case is preserved
    assert caesar_cipher("Hello", 3) == "Khoor", "case preservation failed"
    # Spaces and punctuation are preserved
    assert caesar_cipher("a b!", 1) == "b c!", "non-letter preservation failed"
    # Negative shifts decrypt correctly
    assert caesar_cipher("bcd", -1) == "abc", "negative shift failed"
    # Encrypt then decrypt is the identity
    original = "The Quick Brown Fox Jumps Over The Lazy Dog!"
    assert caesar_cipher(caesar_cipher(original, 7), -7) == original, "round-trip failed"
    # A full-alphabet shift is a no-op; anything beyond wraps
    assert caesar_cipher("abc", ALPHABET_SIZE) == "abc", "shift == size must be no-op"
    assert caesar_cipher("a", ALPHABET_SIZE + 1) == "b", "shift > size must wrap"
    # Edge case: empty input
    assert caesar_cipher("", 5) == "", "empty string failed"

    # Frequency analysis on text where 'e' is clearly dominant (shift 3)
    plain = "we need these green trees near the deep sea here please"
    assert frequency_analysis_decrypt(caesar_cipher(plain, 3)) == plain, \
        "frequency analysis failed"
    print("All Caesar cipher tests passed.")


if __name__ == "__main__":
    encrypted = caesar_cipher("Hello, this is a secret message!", 3)
    print(f"Encrypted Text: {encrypted}")
    for i in range(ALPHABET_SIZE):
        print(f"Shift: {i} => {caesar_cipher(encrypted, -i)}")

    run_tests()
