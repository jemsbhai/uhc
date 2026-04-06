"""
Tests for uhc.core.compressed_verifier

THE critical test: CDH(LZ77(data)) == H(data) for all inputs.
This is the code-level proof of Theorem 12 (Main Correctness Result).

Every test constructs raw data, encodes it to LZ77 tokens, computes
the hash both ways, and asserts equality.
"""

import os
import pytest

from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61
from uhc.core.lz77 import lz77_encode, lz77_decode, Literal, Reference
from uhc.core.compressed_verifier import compressed_domain_hash


P61 = MERSENNE_61


# ---------------------------------------------------------------------------
# Theorem 12: CDH == H — the main correctness result
# ---------------------------------------------------------------------------

class TestMainCorrectness:
    """CDH(τ) = H(T) for any string T and any valid LZ77 encoding τ of T."""

    def _verify(self, data: bytes, base: int = 131) -> None:
        """Helper: encode, compute both hashes, assert equality."""
        h = PolynomialHash(prime=P61, base=base)
        tokens = lz77_encode(data)

        # Sanity: tokens decode back to original
        assert lz77_decode(tokens) == data

        # THE assertion: Theorem 12
        direct = h.hash(data)
        compressed = compressed_domain_hash(tokens, prime=P61, base=base)
        assert direct == compressed, (
            f"CDH ≠ H for data of length {len(data)}: "
            f"direct={direct}, compressed={compressed}"
        )

    def test_empty(self):
        self._verify(b"")

    def test_single_byte(self):
        self._verify(b"A")

    def test_two_bytes(self):
        self._verify(b"AB")

    def test_short_no_matches(self):
        """All literals, no back-references."""
        self._verify(b"abcde")

    def test_simple_repeat(self):
        """'abcabc' — non-overlapping back-reference."""
        self._verify(b"abcabc")

    def test_triple_repeat(self):
        self._verify(b"abcabcabc")

    def test_run_length_short(self):
        """'AAAA' — overlapping, d=1."""
        self._verify(b"AAAA")

    def test_run_length_long(self):
        """Single byte repeated 200 times — deep overlap."""
        self._verify(b"X" * 200)

    def test_two_byte_pattern(self):
        """'ababababab' — overlapping, d=2."""
        self._verify(b"ab" * 5)

    def test_three_byte_pattern_exact(self):
        """'abcabcabc' — overlapping, d=3, q=2, r=0."""
        self._verify(b"abc" * 3)

    def test_three_byte_pattern_remainder(self):
        """'abcabcab' — overlapping, d=3, q=1, r=2."""
        self._verify(b"abcabcab")

    def test_mixed_literals_and_refs(self):
        """Data with both compressible and incompressible regions."""
        self._verify(b"abcabc" + bytes(range(50)) + b"xyzxyzxyz")

    def test_binary_data(self):
        """Random binary data — mostly literals."""
        self._verify(os.urandom(200))

    def test_highly_compressible(self):
        """Long repeated pattern — many overlapping refs."""
        self._verify(b"hello world! " * 50)

    def test_single_byte_all_values(self):
        """Every byte value 0-255."""
        for b in range(256):
            self._verify(bytes([b]))

    def test_different_bases(self):
        """Correctness holds for different hash bases."""
        data = b"abcdefabcdef" * 10
        for base in [2, 7, 131, 257, 1000003]:
            self._verify(data, base=base)


# ---------------------------------------------------------------------------
# Manually constructed token streams
# ---------------------------------------------------------------------------

class TestManualTokens:
    """Test CDH against hand-crafted token streams."""

    def test_literals_only(self):
        """All literals — CDH should just hash normally."""
        tokens = [Literal(b) for b in b"hello"]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131) == h.hash(b"hello")

    def test_non_overlapping_ref(self):
        """Lit(a,b,c) + Ref(3,3) = 'abcabc'."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=3),
        ]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131) == h.hash(b"abcabc")

    def test_overlapping_rle(self):
        """Lit(A) + Ref(1,9) = 'AAAAAAAAAA'."""
        tokens = [
            Literal(ord("A")),
            Reference(distance=1, length=9),
        ]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131) == h.hash(b"A" * 10)

    def test_overlapping_pattern(self):
        """Lit(a,b) + Ref(2,8) = 'ababababab'."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")),
            Reference(distance=2, length=8),
        ]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131) == h.hash(b"ab" * 5)

    def test_overlapping_with_remainder(self):
        """Lit(a,b,c) + Ref(3,7) = 'abcabcabcab' — q=2, r=1."""
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=7),
        ]
        h = PolynomialHash(prime=P61, base=131)
        expected = b"abc" + b"abc" * 2 + b"a"  # abcabcabca
        assert lz77_decode(tokens) == expected
        assert compressed_domain_hash(tokens, P61, 131) == h.hash(expected)

    def test_chained_references(self):
        """Multiple references chaining off each other."""
        tokens = [
            Literal(ord("x")), Literal(ord("y")),
            Reference(distance=2, length=2),   # 'xyxy'
            Reference(distance=4, length=4),   # 'xyxyxyxy'
        ]
        h = PolynomialHash(prime=P61, base=131)
        expected = b"xy" * 4
        assert lz77_decode(tokens) == expected
        assert compressed_domain_hash(tokens, P61, 131) == h.hash(expected)


# ---------------------------------------------------------------------------
# Stress tests
# ---------------------------------------------------------------------------

class TestStress:
    """Larger inputs to build confidence."""

    def test_1kb_repeated(self):
        data = b"The quick brown fox jumps. " * 40  # ~1KB
        self._verify_roundtrip(data)

    def test_10kb_random(self):
        data = os.urandom(10_000)
        self._verify_roundtrip(data)

    def test_10kb_compressible(self):
        data = (b"compress this data please! " * 400)[:10_000]
        self._verify_roundtrip(data)

    def test_alternating_compressible_random(self):
        """Alternating compressible and random blocks."""
        data = b""
        for _ in range(20):
            data += b"pattern!" * 10
            data += os.urandom(30)
        self._verify_roundtrip(data)

    def _verify_roundtrip(self, data: bytes) -> None:
        h = PolynomialHash(prime=P61, base=131)
        tokens = lz77_encode(data)
        assert lz77_decode(tokens) == data
        direct = h.hash(data)
        compressed = compressed_domain_hash(tokens, P61, 131)
        assert direct == compressed
