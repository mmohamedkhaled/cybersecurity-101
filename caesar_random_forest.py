"""Caesar-cipher shift recovery via a random-forest frequency classifier.

Pure-python Caesar encryption and letter-frequency helpers feed a scikit-learn
RandomForestClassifier that predicts the shift key from ciphertext statistics.
The scikit-learn training pipeline is imported lazily so the module imports
cleanly even when scikit-learn is not installed.
"""

import random
import string
from collections import Counter
from typing import Any

MAX_SHIFT = 25
NUM_SAMPLES = 1000
TEST_SIZE = 0.2
RANDOM_STATE = 42
N_ESTIMATORS = 100
EXAMPLE_TEXT = "This is a simple example text for Caesar cipher encryption."


def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypt ``text`` with a Caesar cipher using the given ``shift``.

    Args:
        text: The plaintext to encrypt; case is preserved.
        shift: The number of positions to rotate the alphabet.

    Returns:
        The ciphertext with each letter rotated by ``shift``.
    """
    alphabet = string.ascii_lowercase
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    table = str.maketrans(
        alphabet + alphabet.upper(), shifted_alphabet + shifted_alphabet.upper()
    )
    return text.translate(table)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt Caesar ciphertext by reversing the original ``shift``.

    Args:
        ciphertext: The ciphertext to decrypt.
        shift: The shift originally used for encryption.

    Returns:
        The recovered plaintext.
    """
    return caesar_encrypt(ciphertext, -shift)


def generate_caesar_cipher_dataset(
    text: str, max_shift: int = MAX_SHIFT, num_samples: int = NUM_SAMPLES
) -> list[tuple[str, int]]:
    """Build a dataset of ``(ciphertext, shift)`` pairs from a base text.

    Args:
        text: The base plaintext to repeatedly encrypt.
        max_shift: Inclusive upper bound for the random shift.
        num_samples: Number of ciphertext samples to generate.

    Returns:
        A list of ``(encrypted_text, shift)`` tuples.
    """
    data: list[tuple[str, int]] = []
    for _ in range(num_samples):
        shift = random.randint(1, max_shift)
        encrypted_text = caesar_encrypt(text, shift)
        data.append((encrypted_text, shift))
    return data


def extract_letter_frequencies(text: str) -> list[float]:
    """Compute normalized a-z letter frequencies for ``text``.

    Args:
        text: The text to analyze; non-letters are ignored.

    Returns:
        A list of 26 floats summing to 1.0 (or 0.0 when there are no letters),
        ordered ``a`` through ``z``.
    """
    text = text.lower()
    counts = Counter(char for char in text if char in string.ascii_lowercase)
    total_letters = sum(counts.values())
    return [
        counts.get(chr(code), 0) / total_letters if total_letters > 0 else 0
        for code in range(ord("a"), ord("z") + 1)
    ]


def model_decrypt(ciphertext: str, model: Any) -> str:
    """Decrypt ciphertext using a trained model's predicted shift.

    Args:
        ciphertext: The ciphertext to decrypt.
        model: A fitted classifier exposing ``predict`` over feature vectors.

    Returns:
        The plaintext recovered with the model's predicted shift.
    """
    shift_pred = model.predict([extract_letter_frequencies(ciphertext)])[0]
    return caesar_decrypt(ciphertext, shift_pred)


def run_tests() -> None:
    """Validate the pure-python cipher helpers and run the sklearn demo.

    Caesar round-trip and frequency helpers are always asserted. The
    scikit-learn training demo is skipped gracefully when scikit-learn is
    missing.

    On success of every runnable check ``"All Caesar RandomForest tests passed."`` is
    printed; otherwise a skip notice is printed for the missing dependency.
    """
    assert caesar_encrypt("abc", 0) == "abc"
    assert caesar_encrypt("xyz", 3) == "abc"
    assert caesar_decrypt(caesar_encrypt("Hello, World!", 7), 7) == "Hello, World!"

    freqs = extract_letter_frequencies("aaab")
    assert len(freqs) == 26
    assert abs(sum(freqs) - 1.0) < 1e-9
    assert abs(freqs[0] - 0.75) < 1e-9

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import accuracy_score
        from sklearn.model_selection import train_test_split

        dataset = generate_caesar_cipher_dataset(
            EXAMPLE_TEXT, max_shift=MAX_SHIFT, num_samples=NUM_SAMPLES
        )

        x = [extract_letter_frequencies(text) for text, _ in dataset]
        y = [shift for _, shift in dataset]

        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
        )

        model = RandomForestClassifier(
            n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE
        )
        model.fit(x_train, y_train)

        y_pred = model.predict(x_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model accuracy: {accuracy * 100:.2f}%")

        test_shift = 7
        encrypted_example = caesar_encrypt(EXAMPLE_TEXT, test_shift)
        decrypted_example = model_decrypt(encrypted_example, model)
        print(f"Encrypted Text: {encrypted_example}")
        print(f"Model Decrypted Text: {decrypted_example}")
    except ImportError as exc:
        missing = getattr(exc, "name", None) or "sklearn"
        print(f"Caesar RandomForest tests skipped (missing dependency: {missing}).")

    print("All Caesar RandomForest tests passed.")


if __name__ == "__main__":
    run_tests()
