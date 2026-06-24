"""Password strength evaluator.

Scores a password from 0 to 6 based on length and character-class diversity and
penalises entries found in a small list of common passwords. Pure-stdlib and
side-effect free unless verbose feedback is requested.
"""

import re

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_SCORE = 6
SPECIAL_CHARACTERS = "!@#$%^&*"
COMMON_PASSWORDS = ("password", "123456", "123")

LOWERCASE_RE = re.compile(r"[a-z]")
UPPERCASE_RE = re.compile(r"[A-Z]")
DIGIT_RE = re.compile(r"[0-9]")
SPECIAL_RE = re.compile(f"[{re.escape(SPECIAL_CHARACTERS)}]")


def check_password(password: str, verbose: bool = False) -> int:
    """Score a password's strength on a 0..6 scale.

    One point is awarded for each of: length >= 8, presence of a lowercase
    letter, an uppercase letter, a digit, a special character, and not being in
    the common-passwords list.

    Args:
        password: The password to evaluate.
        verbose: When True, print the reasons for any missed points.

    Returns:
        Strength score between 0 and 6.

    Raises:
        ValueError: If ``password`` is empty.
    """
    if not password:
        raise ValueError("password must not be empty.")

    strength = 0

    if len(password) >= MIN_PASSWORD_LENGTH:
        strength += 1
    elif verbose:
        print(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )

    if LOWERCASE_RE.search(password):
        strength += 1
    elif verbose:
        print("Password must contain at least one lowercase letter.")

    if UPPERCASE_RE.search(password):
        strength += 1
    elif verbose:
        print("Password must contain at least one uppercase letter.")

    if DIGIT_RE.search(password):
        strength += 1
    elif verbose:
        print("Password must contain at least one digit.")

    if SPECIAL_RE.search(password):
        strength += 1
    elif verbose:
        print(
            f"Password must contain at least one special character "
            f"({SPECIAL_CHARACTERS})."
        )

    if password not in COMMON_PASSWORDS:
        strength += 1
    elif verbose:
        print("Password is too common.")

    return strength


def run_tests() -> None:
    """Run inline sanity checks for the password evaluator."""
    assert check_password("Abcdef1!") == MAX_PASSWORD_SCORE
    assert check_password("StrongP@ss1") == MAX_PASSWORD_SCORE

    assert check_password("password") == 2
    assert check_password("123456") == 1
    assert check_password("123") == 1

    assert check_password("PASSWORD1!") == 5
    assert check_password("Ab1!") == 5

    try:
        check_password("")
        raise AssertionError("expected ValueError for empty password")
    except ValueError:
        pass

    print("All password tests passed.")


if __name__ == "__main__":
    try:
        entered = input("Enter a password: ")
        score = check_password(entered, verbose=True)
        print(f"Password strength: {score}/{MAX_PASSWORD_SCORE}")
    except (ValueError, EOFError):
        print("(skipping interactive demo: empty input)")
    print()
    run_tests()
