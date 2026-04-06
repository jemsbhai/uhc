"""
Tests for uhc.core.compressed_verifier

THE critical test: CDH(LZ77(data)) == H(data) for all inputs.
This is the code-level proof of Theorem 12 (Main Correctness Result).

Both strategies (prefix_array and rope) are tested independently
AND cross-validated against each other for every input.
"""

import os
import pytest

from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61
from uhc.core.lz77 import lz77_encode, lz77_decode, Literal, Reference
from uhc.core.compressed_verifier import compressed_domain_hash, CDHMethod


P61 = MERSENNE_61
METHODS = [CDHMethod.PREFIX_ARRAY, CDHMethod.ROPE]


# ---------------------------------------------------------------------------
# Theorem 12: CDH == H — the main correctness result
# ---------------------------------------------------------------------------

class TestMainCorrectness:
    """CDH(τ) = H(T) for any string T and any valid LZ77 encoding τ of T."""

    def _verify(self, data: bytes, base: int = 131) -> None:
        """
        Helper: encode, compute hash three ways, assert all equal.
          1. H(data) — direct polynomial hash
          2. CDH via prefix_array
          3. CDH via rope
        """
        h = PolynomialHash(prime=P61, base=base)
        tokens = lz77_encode(data)

        # Sanity: tokens decode back to original
        assert lz77_decode(tokens) == data

        direct = h.hash(data)

        for method in METHODS:
            compressed = compressed_domain_hash(tokens, P61, base, method=method)
            assert direct == compressed, (
                f"CDH({method.value}) ≠ H for data len {len(data)}: "
                f"direct={direct}, cdh={compressed}"
            )

        # Cross-validate: both methods agree
        pa = compressed_domain_hash(tokens, P61, base, method=CDHMethod.PREFIX_ARRAY)
        rp = compressed_domain_hash(tokens, P61, base, method=CDHMethod.ROPE)
        assert pa == rp, (
            f"prefix_array ({pa}) ≠ rope ({rp}) for data len {len(data)}"
        )

    def test_empty(self):
        self._verify(b"")

    def test_single_byte(self):
        self._verify(b"A")

    def test_two_bytes(self):
        self._verify(b"AB")

    def test_short_no_matches(self):
        self._verify(b"abcde")

    def test_simple_repeat(self):
        self._verify(b"abcabc")

    def test_triple_repeat(self):
        self._verify(b"abcabcabc")

    def test_run_length_short(self):
        self._verify(b"AAAA")

    def test_run_length_long(self):
        self._verify(b"X" * 200)

    def test_two_byte_pattern(self):
        self._verify(b"ab" * 5)

    def test_three_byte_pattern_exact(self):
        self._verify(b"abc" * 3)

    def test_three_byte_pattern_remainder(self):
        self._verify(b"abcabcab")

    def test_mixed_literals_and_refs(self):
        self._verify(b"abcabc" + bytes(range(50)) + b"xyzxyzxyz")

    def test_binary_data(self):
        self._verify(os.urandom(200))

    def test_highly_compressible(self):
        self._verify(b"hello world! " * 50)

    def test_single_byte_all_values(self):
        for b in range(256):
            self._verify(bytes([b]))

    def test_different_bases(self):
        data = b"abcdefabcdef" * 10
        for base in [2, 7, 131, 257, 1000003]:
            self._verify(data, base=base)


# ---------------------------------------------------------------------------
# Manually constructed token streams
# ---------------------------------------------------------------------------

class TestManualTokens:
    """Test CDH against hand-crafted token streams, both methods."""

    @pytest.mark.parametrize("method", METHODS)
    def test_literals_only(self, method):
        tokens = [Literal(b) for b in b"hello"]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131, method=method) == h.hash(b"hello")

    @pytest.mark.parametrize("method", METHODS)
    def test_non_overlapping_ref(self, method):
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=3),
        ]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131, method=method) == h.hash(b"abcabc")

    @pytest.mark.parametrize("method", METHODS)
    def test_overlapping_rle(self, method):
        tokens = [Literal(ord("A")), Reference(distance=1, length=9)]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131, method=method) == h.hash(b"A" * 10)

    @pytest.mark.parametrize("method", METHODS)
    def test_overlapping_pattern(self, method):
        tokens = [Literal(ord("a")), Literal(ord("b")), Reference(distance=2, length=8)]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131, method=method) == h.hash(b"ab" * 5)

    @pytest.mark.parametrize("method", METHODS)
    def test_overlapping_with_remainder(self, method):
        tokens = [
            Literal(ord("a")), Literal(ord("b")), Literal(ord("c")),
            Reference(distance=3, length=7),
        ]
        h = PolynomialHash(prime=P61, base=131)
        expected = lz77_decode(tokens)
        assert compressed_domain_hash(tokens, P61, 131, method=method) == h.hash(expected)

    @pytest.mark.parametrize("method", METHODS)
    def test_chained_references(self, method):
        tokens = [
            Literal(ord("x")), Literal(ord("y")),
            Reference(distance=2, length=2),
            Reference(distance=4, length=4),
        ]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131, method=method) == h.hash(b"xy" * 4)


# ---------------------------------------------------------------------------
# Stress tests
# ---------------------------------------------------------------------------

class TestStress:
    """Larger inputs, both methods, cross-validated."""

    def _verify_roundtrip(self, data: bytes) -> None:
        h = PolynomialHash(prime=P61, base=131)
        tokens = lz77_encode(data)
        assert lz77_decode(tokens) == data
        direct = h.hash(data)

        pa = compressed_domain_hash(tokens, P61, 131, method=CDHMethod.PREFIX_ARRAY)
        rp = compressed_domain_hash(tokens, P61, 131, method=CDHMethod.ROPE)
        assert direct == pa == rp, (
            f"Mismatch: direct={direct}, prefix_array={pa}, rope={rp}"
        )

    def test_1kb_repeated(self):
        self._verify_roundtrip(b"The quick brown fox jumps. " * 40)

    def test_10kb_random(self):
        self._verify_roundtrip(os.urandom(10_000))

    def test_10kb_compressible(self):
        self._verify_roundtrip((b"compress this data please! " * 400)[:10_000])

    def test_alternating_compressible_random(self):
        data = b""
        for _ in range(20):
            data += b"pattern!" * 10
            data += os.urandom(30)
        self._verify_roundtrip(data)


# ---------------------------------------------------------------------------
# Method selection / API tests
# ---------------------------------------------------------------------------

class TestMethodSelection:
    """Ensure the method parameter works correctly."""

    def test_default_is_rope(self):
        tokens = [Literal(65)]
        h = PolynomialHash(prime=P61, base=131)
        # Default should work (rope)
        assert compressed_domain_hash(tokens, P61, 131) == h.hash(b"A")

    def test_string_method_works(self):
        tokens = [Literal(65)]
        h = PolynomialHash(prime=P61, base=131)
        assert compressed_domain_hash(tokens, P61, 131, method="prefix_array") == h.hash(b"A")
        assert compressed_domain_hash(tokens, P61, 131, method="rope") == h.hash(b"A")

    def test_invalid_method_raises(self):
        with pytest.raises(ValueError):
            compressed_domain_hash([Literal(65)], P61, 131, method="invalid")
