"""Consolidated review test suite for caesar_cipher and checksum modules.

Run with:  python3 test_suite.py
Exits 0 and prints a success banner only if every assertion holds.
"""

import importlib
import sys

caesar_cipher = importlib.import_module("caesar_cipher")
checksum = importlib.import_module("checksum")

caesar = caesar_cipher.caesar_cipher
ALPHABET_SIZE = caesar_cipher.ALPHABET_SIZE
frequency_analysis_decrypt = caesar_cipher.frequency_analysis_decrypt

compute_checksum = checksum.checksum
validate_checksum = checksum.validate_checksum


def test_caesar_standard_shift() -> None:
    assert caesar("abc", 1) == "bcd"
    assert caesar("Hello", 3) == "Khoor"


def test_caesar_wraparound() -> None:
    assert caesar("xyz", 3) == "abc"
    assert caesar("XYZ", 3) == "ABC"
    assert caesar("z", 1) == "a"
    assert caesar("a", -1) == "z"


def test_caesar_case_and_nonletters_preserved() -> None:
    assert caesar("a b!", 1) == "b c!"
    assert caesar("He's 100% OK.", 5) == "Mj'x 100% TP."


def test_caesar_negative_and_zero_shift() -> None:
    assert caesar("bcd", -1) == "abc"
    assert caesar("Same", 0) == "Same"


def test_caesar_shift_modulo_alphabet() -> None:
    assert caesar("abc", ALPHABET_SIZE) == "abc"
    assert caesar("a", ALPHABET_SIZE + 1) == "b"
    assert caesar("abc", 2 * ALPHABET_SIZE + 3) == "def"


def test_caesar_large_shift() -> None:
    assert caesar("abc", 29) == "def"
    assert caesar("abc", 1000003 % ALPHABET_SIZE) == caesar("abc", 1000003)


def test_caesar_round_trip() -> None:
    original = "The Quick Brown Fox Jumps Over The Lazy Dog!"
    for shift in range(-50, 51):
        assert caesar(caesar(original, shift), -shift) == original


def test_caesar_empty_string() -> None:
    assert caesar("", 5) == ""
    assert caesar("", -3) == ""


def test_caesar_non_alpha_only() -> None:
    assert caesar("123!@#", 4) == "123!@#"
    assert caesar("   \t\n", 7) == "   \t\n"


def test_frequency_analysis_dominant_e() -> None:
    plain = "we need these green trees near the deep sea here please"
    for shift in range(1, ALPHABET_SIZE):
        assert frequency_analysis_decrypt(caesar(plain, shift)) == plain


def test_frequency_analysis_raises_on_no_letters() -> None:
    try:
        frequency_analysis_decrypt("1234 !!!")
        raise AssertionError("expected ValueError when ciphertext has no letters")
    except ValueError:
        pass


def test_checksum_known_4bit() -> None:
    assert compute_checksum("12345", bits=4, verbose=False) == "1"


def test_checksum_known_8bit() -> None:
    assert compute_checksum("C8C093", bits=8, verbose=False) == "E5"


def test_checksum_all_zeros() -> None:
    # Sum of all-zero words is 0; two's complement of 0 (4-bit) is 0.
    assert compute_checksum("0000", bits=4, verbose=False) == "0"


def test_checksum_all_ones_4bit() -> None:
    # 0xF + 0xF = 0x1E -> 0xE mod 0x10; two's complement of 0xE is 0x2.
    assert compute_checksum("FF", bits=4, verbose=False) == "2"


def test_checksum_round_trip_4bit() -> None:
    msg = "9A1F"
    full = msg + compute_checksum(msg, bits=4, verbose=False)
    assert validate_checksum(full, bits=4, verbose=False) is True


def test_checksum_round_trip_8bit() -> None:
    msg = "C8C093"
    full = msg + compute_checksum(msg, bits=8, verbose=False)
    assert validate_checksum(full, bits=8, verbose=False) is True


def test_checksum_detects_corruption() -> None:
    valid4 = "D54B87"
    assert validate_checksum(valid4, bits=4, verbose=False) is True
    assert validate_checksum(valid4[:-1] + "0", bits=4, verbose=False) is False


def test_checksum_single_bit_flip_detected_8bit() -> None:
    msg = "C8C093"
    full = msg + compute_checksum(msg, bits=8, verbose=False)
    assert validate_checksum(full, bits=8, verbose=False) is True
    flipped = full[:-2] + format(int(full[-2:], 16) ^ 0x01, "02X")
    assert validate_checksum(flipped, bits=8, verbose=False) is False


def test_checksum_verbose_does_not_change_result() -> None:
    assert compute_checksum("12345", bits=4, verbose=True) == \
           compute_checksum("12345", bits=4, verbose=False)


def test_checksum_unsupported_bits_raises() -> None:
    for bad_bits in (0, 1, 5, 16, -4):
        try:
            compute_checksum("1234", bits=bad_bits, verbose=False)
            raise AssertionError(f"expected ValueError for bits={bad_bits}")
        except ValueError:
            pass


def test_checksum_empty_message_raises() -> None:
    try:
        compute_checksum("", bits=4)
        raise AssertionError("expected ValueError for empty message")
    except ValueError:
        pass


def test_validate_unsupported_bits_raises() -> None:
    try:
        validate_checksum("1234", bits=7, verbose=False)
        raise AssertionError("expected ValueError for bits=7")
    except ValueError:
        pass


def test_validate_empty_message_raises() -> None:
    try:
        validate_checksum("", bits=4, verbose=False)
        raise AssertionError("expected ValueError for empty message")
    except ValueError:
        pass


def main() -> int:
    tests = [
        ("caesar.standard_shift", test_caesar_standard_shift),
        ("caesar.wraparound", test_caesar_wraparound),
        ("caesar.case_and_nonletters", test_caesar_case_and_nonletters_preserved),
        ("caesar.negative_and_zero_shift", test_caesar_negative_and_zero_shift),
        ("caesar.shift_modulo_alphabet", test_caesar_shift_modulo_alphabet),
        ("caesar.large_shift", test_caesar_large_shift),
        ("caesar.round_trip", test_caesar_round_trip),
        ("caesar.empty_string", test_caesar_empty_string),
        ("caesar.non_alpha_only", test_caesar_non_alpha_only),
        ("caesar.frequency_analysis_dominant_e", test_frequency_analysis_dominant_e),
        ("caesar.frequency_analysis_raises_on_no_letters", test_frequency_analysis_raises_on_no_letters),
        ("checksum.known_4bit", test_checksum_known_4bit),
        ("checksum.known_8bit", test_checksum_known_8bit),
        ("checksum.all_zeros", test_checksum_all_zeros),
        ("checksum.all_ones_4bit", test_checksum_all_ones_4bit),
        ("checksum.round_trip_4bit", test_checksum_round_trip_4bit),
        ("checksum.round_trip_8bit", test_checksum_round_trip_8bit),
        ("checksum.detects_corruption", test_checksum_detects_corruption),
        ("checksum.single_bit_flip_detected_8bit", test_checksum_single_bit_flip_detected_8bit),
        ("checksum.verbose_does_not_change_result", test_checksum_verbose_does_not_change_result),
        ("checksum.unsupported_bits_raises", test_checksum_unsupported_bits_raises),
        ("checksum.empty_message_raises", test_checksum_empty_message_raises),
        ("validate.unsupported_bits_raises", test_validate_unsupported_bits_raises),
        ("validate.empty_message_raises", test_validate_empty_message_raises),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except AssertionError as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1

    total = len(tests)
    print("\n" + "=" * 50)
    if failed == 0:
        print(f"SUCCESS: all {total} tests passed. Safe to upload.")
        return 0
    print(f"FAILURE: {failed}/{total} tests failed. Fix before uploading.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
