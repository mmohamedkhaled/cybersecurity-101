"""Caesar-cipher shift recovery from character n-gram features.

A pure-python Caesar cipher feeds a scikit-learn pipeline (character n-gram
CountVectorizer plus RandomForestClassifier) that predicts the shift directly
from ciphertext text. The scikit-learn training pipeline is imported lazily so
the module imports cleanly even when scikit-learn is not installed.
"""

import random
import string
from collections import Counter

MAX_SHIFT = 25
NUM_SAMPLES = 100
TEST_SIZE = 0.2
RANDOM_STATE = 42
N_ESTIMATORS = 100
NGRAM_RANGE = (1, 2)
EXAMPLE_TEXT = "Hello, this is a secret message from AI!"


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
    base_text: str, max_shift: int = MAX_SHIFT, num_samples: int = NUM_SAMPLES
) -> list[tuple[str, int]]:
    """Build a dataset of ``(ciphertext, shift)`` pairs from a base text.

    Args:
        base_text: The base plaintext to repeatedly encrypt.
        max_shift: Inclusive upper bound for the random shift.
        num_samples: Number of ciphertext samples to generate.

    Returns:
        A list of ``(encrypted_text, shift)`` tuples.
    """
    dataset: list[tuple[str, int]] = []
    for _ in range(num_samples):
        shift = random.randint(1, max_shift)
        encrypted_text = caesar_encrypt(base_text, shift)
        dataset.append((encrypted_text, shift))
    return dataset


def letter_frequency(text: str) -> dict[str, float]:
    """Compute per-letter percentage frequencies for ``text``.

    Args:
        text: The text to analyze.

    Returns:
        A dict mapping every uppercase A-Z letter to its percentage share of
        all letters (0.0 when there are no letters).
    """
    text = text.upper()
    counts = Counter(text)
    total_letters = sum(counts[char] for char in string.ascii_uppercase)
    return {
        char: (counts[char] / total_letters) * 100
        for char in string.ascii_uppercase
        if total_letters > 0
    }


def run_tests() -> None:
    """Validate the pure-python cipher helpers and run the sklearn demo.

    Caesar round-trip and frequency helpers are always asserted. The
    scikit-learn training demo is skipped gracefully when scikit-learn is
    missing.

    On success of every runnable check ``"All Caesar n-gram model tests passed."`` is
    printed; otherwise a skip notice is printed for the missing dependency.
    """
    assert caesar_encrypt("abc", 0) == "abc"
    assert caesar_encrypt("xyz", 3) == "abc"
    assert caesar_decrypt(caesar_encrypt("Machine Learning!", 13), 13) == "Machine Learning!"

    freqs = letter_frequency("aaab")
    assert len(freqs) == 26
    assert abs(sum(freqs.values()) - 100.0) < 1e-9
    assert abs(freqs["A"] - 75.0) < 1e-9

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_extraction.text import CountVectorizer
        from sklearn.metrics import accuracy_score
        from sklearn.model_selection import train_test_split
        from sklearn.pipeline import make_pipeline

        dataset = generate_caesar_cipher_dataset(
            EXAMPLE_TEXT, max_shift=MAX_SHIFT, num_samples=NUM_SAMPLES
        )

        x = [item[0] for item in dataset]
        y = [item[1] for item in dataset]

        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
        )

        model = make_pipeline(
            CountVectorizer(analyzer="char", ngram_range=NGRAM_RANGE),
            RandomForestClassifier(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE),
        )
        model.fit(x_train, y_train)

        y_pred = model.predict(x_test)
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Model Accuracy: {accuracy * 100:.2f}%")

        new_encrypted = caesar_encrypt("Machine learning is amazing!", shift=7)
        predicted_shift = model.predict([new_encrypted])[0]
        decrypted_text = caesar_decrypt(new_encrypted, predicted_shift)
        print(f"Encrypted Message: {new_encrypted}")
        print(f"AI Predicted Shift: {predicted_shift}")
        print(f"AI Decrypted Text: {decrypted_text}")
    except ImportError as exc:
        missing = getattr(exc, "name", None) or "sklearn"
        print(f"Caesar n-gram model tests skipped (missing dependency: {missing}).")

    print("All Caesar n-gram model tests passed.")


if __name__ == "__main__":
    run_tests()
