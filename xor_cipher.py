"""XOR stream cipher over ASCII characters.

Each character of the plaintext is XOR-ed with a fixed integer key.
Because XOR is its own inverse, applying the same operation twice
with the same key recovers the original text.
"""

KEY_MIN = 0
KEY_MAX = 255


def xor_encrypt(text: str, key: int) -> str:
    """Encrypt ``text`` by XOR-ing every character code with ``key``.

    Args:
        text: The input string to transform.
        key: A non-negative integer in the range ``[0, 255]`` used as
            the per-character XOR mask.

    Returns:
        A new string whose characters are ``chr(ord(c) ^ key)`` for
        each character ``c`` in ``text``.

    Raises:
        ValueError: If ``text`` is empty or ``key`` is outside the
            range ``[0, 255]``.
    """
    if not text:
        raise ValueError("text must be non-empty")
    if not isinstance(key, int) or isinstance(key, bool):
        raise ValueError("key must be an integer")
    if not KEY_MIN <= key <= KEY_MAX:
        raise ValueError("key must be an integer in the range 0-255")

    return "".join(chr(ord(ch) ^ key) for ch in text)


def run_tests() -> None:
    plaintext = "Hello, this is a secret message!"
    key = 90
    encrypted = xor_encrypt(plaintext, key)
    assert xor_encrypt(encrypted, key) == plaintext

    for sample, k in [
        ("", 0),
        ("abc", 0),
        ("ABCDEF", 1),
        ("The quick brown fox", 42),
        ("1234567890", 255),
        ("\t\n\r ", 7),
    ]:
        if sample == "":
            try:
                xor_encrypt(sample, k)
            except ValueError:
                continue
            raise AssertionError("empty text should raise ValueError")
        assert xor_encrypt(xor_encrypt(sample, k), k) == sample

    assert xor_encrypt("A", 0) == "A"
    assert xor_encrypt("A", 1) == chr(ord("A") ^ 1)

    try:
        xor_encrypt("abc", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative key should raise ValueError")

    try:
        xor_encrypt("abc", 256)
    except ValueError:
        pass
    else:
        raise AssertionError("out-of-range key should raise ValueError")

    print("All XOR encryption tests passed.")


if __name__ == "__main__":
    plaintext = "Hello, this is a secret message!"
    key = 90
    encrypted_text = xor_encrypt(plaintext, key)
    print(f"Encrypted Text: {encrypted_text}")
    decrypted_text = xor_encrypt(encrypted_text, key)
    print(f"Decrypted Text: {decrypted_text}")
    run_tests()
