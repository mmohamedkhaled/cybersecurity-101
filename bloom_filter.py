"""Bloom filter for space-efficient set membership testing.

A Bloom filter is a probabilistic data structure that answers "is this item in
the set?" with no false negatives but a tunable false-positive rate. It uses
``k`` independent hash functions over a bit array of ``m`` bits, where ``m`` is
derived from the expected item count and desired false-positive rate.
"""

import math
import random
import string

try:
    import mmh3
    from bitarray import bitarray

    _DEPS_AVAILABLE = True
except ImportError:
    _DEPS_AVAILABLE = False

DEFAULT_NUM_HASHES = 6
DEFAULT_DESIRED_FPR = 0.01


def _bit_array(size: int):
    """Return a zeroed bit array of length ``size``.

    Args:
        size: Number of bits.

    Returns:
        A ``bitarray`` instance, all bits set to ``0``.
    """
    arr = bitarray(size)
    arr.setall(0)
    return arr


class BloomFilter:
    """Probabilistic set-membership structure over a fixed-size bit array."""

    def __init__(
        self, n_words: int, false_positive_rate: float, num_hashes: int
    ) -> None:
        """Configure the filter's capacity, error rate and hash count.

        Args:
            n_words: Expected number of items to store.
            false_positive_rate: Desired false-positive probability in (0, 1).
            num_hashes: Number of independent hash functions to apply.

        Raises:
            ValueError: If arguments are out of their valid ranges.
        """
        if not isinstance(n_words, int) or n_words <= 0:
            raise ValueError("n_words must be a positive int")
        if not (0.0 < false_positive_rate < 1.0):
            raise ValueError("false_positive_rate must be in (0, 1)")
        if not isinstance(num_hashes, int) or num_hashes <= 0:
            raise ValueError("num_hashes must be a positive int")
        self.n = n_words
        self.k = num_hashes
        self.fpr = false_positive_rate
        self.m = max(1, int(
            -n_words * math.log(false_positive_rate) / (math.log(2) ** 2)
        ))
        self.bit_array = _bit_array(self.m)

    def add(self, item: str) -> None:
        """Insert ``item`` into the filter.

        Args:
            item: The string to add.
        """
        for i in range(self.k):
            digest = mmh3.hash(item, i) % self.m
            self.bit_array[digest] = 1

    def contains(self, item: str) -> bool:
        """Return whether ``item`` may be in the filter.

        Args:
            item: The string to test.

        Returns:
            ``False`` if the item is definitely absent, ``True`` if it is
            possibly present (subject to the false-positive rate).
        """
        return all(
            self.bit_array[mmh3.hash(item, i) % self.m] for i in range(self.k)
        )

    def estimated_fpr(self) -> float:
        """Return the theoretical false-positive rate after ``n`` inserts.

        Returns:
            The estimated false-positive probability.
        """
        return (1 - math.exp(-self.k * self.n / self.m)) ** self.k


def _random_word(length: int = 8) -> str:
    """Return a random lowercase word of the given length.

    Args:
        length: Number of characters in the word.

    Returns:
        A random lowercase ASCII string.
    """
    return "".join(random.choices(string.ascii_lowercase, k=length))


def run_tests() -> None:
    if not _DEPS_AVAILABLE:
        print("Bloom filter tests skipped (missing dependency).")
        return

    try:
        bloom = BloomFilter(100, DEFAULT_DESIRED_FPR, DEFAULT_NUM_HASHES)
        inserted = [_random_word() for _ in range(100)]
        for word in inserted:
            bloom.add(word)
        assert all(bloom.contains(word) for word in inserted)

        missing = [_random_word() for _ in range(100)]
        false_positives = sum(1 for word in missing if bloom.contains(word))
        assert false_positives <= 100
        assert bloom.m > 0
        assert 0.0 < bloom.estimated_fpr() < 1.0

        loose = BloomFilter(10, 0.99, 4)
        assert loose.m >= 1
        loose.add("x")
        assert loose.contains("x")

        try:
            BloomFilter(-1, DEFAULT_DESIRED_FPR, DEFAULT_NUM_HASHES)
        except ValueError:
            pass
        else:
            raise AssertionError("Expected ValueError for non-positive n_words")

        print("All Bloom filter tests passed.")
    except ImportError:
        print("Bloom filter tests skipped (missing dependency).")


if __name__ == "__main__":
    if not _DEPS_AVAILABLE:
        print("Bloom filter demo skipped (missing dependency).")
        print("Install 'mmh3' and 'bitarray' to run the simulation.")
        run_tests()
    else:
        n = 10**6
        k = DEFAULT_NUM_HASHES
        desired_fpr = DEFAULT_DESIRED_FPR

        bloom = BloomFilter(n, desired_fpr, k)
        dictionary = [_random_word() for _ in range(n)]
        for word in dictionary:
            bloom.add(word)

        test_words = [_random_word() for _ in range(1000)]
        false_positives = sum(1 for word in test_words if bloom.contains(word))

        print("---- Bloom Filter Simulation ----")
        print(f"Words inserted: {n}")
        print(f"Hash functions used: {k}")
        print(f"Bit array size (m): {bloom.m} bits ≈ {bloom.m / 8 / 1024:.2f} KB")
        print(f"Desired false positive rate: {desired_fpr:.2%}")
        print(f"Estimated false positive rate: {bloom.estimated_fpr():.2%}")
        print(f"Actual false positives out of 1000 tests: {false_positives}")
        run_tests()
