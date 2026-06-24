"""Break a Caesar cipher via English letter-frequency analysis.

The cipher shifts each letter by a fixed amount; the breaker computes
per-letter frequencies of the ciphertext, tries every possible shift,
and returns the shift whose decryption best matches typical English
letter frequencies.
"""

import string
from collections import Counter

ALPHABET_SIZE = 26

ENGLISH_FREQUENCY: dict[str, float] = {
    "E": 12.7, "T": 9.1, "A": 8.2, "O": 7.5, "I": 7.0, "N": 6.7,
    "S": 6.3, "H": 6.1, "R": 6.0, "D": 4.3, "L": 4.0, "C": 2.8,
    "U": 2.8, "M": 2.4, "W": 2.4, "F": 2.2, "G": 2.0, "Y": 2.0,
    "P": 1.9, "B": 1.5, "V": 1.0, "K": 0.8, "J": 0.2, "X": 0.2,
    "Q": 0.1, "Z": 0.1,
}


def caesar_cipher(text: str, shift: int) -> str:
    """Apply a Caesar shift of ``shift`` to ``text``.

    Args:
        text: The input string. Non-alphabetic characters are passed
            through unchanged.
        shift: The integer shift to apply (may be negative to decrypt).

    Returns:
        A new string with each alphabetic character shifted by
        ``shift`` positions within its case.

    Raises:
        ValueError: If ``text`` is empty.
    """
    if not text:
        raise ValueError("text must be non-empty")

    shifted = []
    for char in text:
        if char.isalpha():
            start = ord("A") if char.isupper() else ord("a")
            shifted.append(chr((ord(char) - start + shift) % ALPHABET_SIZE + start))
        else:
            shifted.append(char)
    return "".join(shifted)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt ``ciphertext`` that was encrypted with the given ``shift``.

    Args:
        ciphertext: The encrypted string.
        shift: The original encryption shift.

    Returns:
        The decrypted plaintext.
    """
    return caesar_cipher(ciphertext, -shift)


def letter_frequency(text: str) -> dict[str, float]:
    """Return the percentage frequency of each English letter in ``text``.

    Args:
        text: The string to analyse (case-insensitive).

    Returns:
        A mapping from each uppercase letter to its percentage share of
        the total alphabetic characters. Letters absent from ``text``
        are omitted from the result.
    """
    upper = text.upper()
    counts = Counter(upper)
    total_letters = sum(counts[ch] for ch in string.ascii_uppercase)
    if total_letters == 0:
        return {}
    return {
        ch: (counts[ch] / total_letters) * 100
        for ch in string.ascii_uppercase
        if counts[ch] > 0
    }


def break_caesar_cipher(ciphertext: str) -> tuple[int, str]:
    """Recover the Caesar shift and plaintext via frequency analysis.

    Args:
        ciphertext: The encrypted string.

    Returns:
        A ``(best_shift, decrypted_text)`` tuple where ``best_shift``
        is the shift whose decryption best matches English letter
        frequencies.

    Raises:
        ValueError: If ``ciphertext`` contains no alphabetic characters.
    """
    if not any(ch.isalpha() for ch in ciphertext):
        raise ValueError("ciphertext must contain at least one alphabetic character")

    best_shift = 0
    best_score = float("inf")
    for shift in range(ALPHABET_SIZE):
        decrypted = caesar_decrypt(ciphertext, shift)
        decrypted_freqs = letter_frequency(decrypted)
        score = sum(
            abs(decrypted_freqs.get(letter, 0.0) - ENGLISH_FREQUENCY[letter])
            for letter in ENGLISH_FREQUENCY
        )
        if score < best_score:
            best_score = score
            best_shift = shift

    return best_shift, caesar_decrypt(ciphertext, best_shift)


def run_tests() -> None:
    assert caesar_cipher("abc", 1) == "bcd"
    assert caesar_cipher("ABC", 1) == "BCD"
    assert caesar_cipher("xyz", 3) == "abc"
    assert caesar_cipher("Hello, World!", 0) == "Hello, World!"
    assert caesar_cipher("Hello, World!", ALPHABET_SIZE) == "Hello, World!"
    assert caesar_decrypt(caesar_cipher("Secret", 7), 7) == "Secret"

    assert letter_frequency("aa") == {"A": 100.0}
    assert letter_frequency("") == {}
    assert letter_frequency("123!") == {}

    long_text = "we need these green trees near the deep sea here please"
    shift = 5
    encrypted = caesar_cipher(long_text, shift)
    recovered_shift, recovered_text = break_caesar_cipher(encrypted)
    assert recovered_text == long_text, f"{recovered_text!r} != {long_text!r}"
    assert recovered_shift == shift

    try:
        caesar_cipher("", 3)
    except ValueError:
        pass
    else:
        raise AssertionError("empty text should raise ValueError")

    try:
        break_caesar_cipher("123 !?")
    except ValueError:
        pass
    else:
        raise AssertionError("non-alpha ciphertext should raise ValueError")

    print("All Caesar cipher cracking tests passed.")


if __name__ == "__main__":
    shift = 5
    original_text = "Hello, this is a secret message!"
    encrypted_text = caesar_cipher(original_text, shift)
    print("Encrypted:", encrypted_text)
    cracked_shift, cracked_text = break_caesar_cipher(encrypted_text)
    print(f"AI Cracked Shift: {cracked_shift}")
    print(f"AI Decrypted Text: {cracked_text}")
    run_tests()
