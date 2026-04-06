"""
Compressed-domain hash verifier.

Computes H(T) from an LZ77 token stream using algebraic composition
(Theorems 1, 2, 5) rather than byte-by-byte hashing. This is the
code-level proof of Theorem 12: CDH(τ) = H(T).

This initial implementation uses a prefix hash array for substring
queries (Corollary 2), which requires O(N) space. The rope-based
implementation (Part III of the framework) will replace this to
achieve sub-linear space.
"""

from __future__ import annotations

from typing import Sequence

from uhc.core.polynomial_hash import (
    PolynomialHash,
    phi,
    mersenne_mod,
    mersenne_mul,
    MERSENNE_61,
)
from uhc.core.lz77 import Token, Literal, Reference


def compressed_domain_hash(
    tokens: Sequence[Token],
    prime: int = MERSENNE_61,
    base: int = 131,
) -> int:
    """
    Compute the polynomial hash of the decoded data directly from
    an LZ77 token stream, using algebraic composition.

    This implements the algorithm from Theorem 11 and proves
    Theorem 12: CDH(τ) = H(T).

    The hash is built incrementally using three rules:

    1. Literal(c):
       h = h · x + (c + 1)                              [Definition 2]

    2. Ref(d, l) with d ≥ l (non-overlapping):
       h = h · x^l + H(source)                           [Theorem 1]

    3. Ref(d, l) with d < l (overlapping):
       h = h · x^l + H(P)·Φ(q, x^d)·x^r + H(P[0..r-1]) [Theorem 5]
       where q = ⌊l/d⌋, r = l mod d

    Parameters
    ----------
    tokens : sequence of Token
        LZ77 token stream.
    prime : int
        Mersenne prime for the hash ring.
    base : int
        Hash base x.

    Returns
    -------
    int
        H(decoded data), computed without full decompression.
    """
    h = PolynomialHash(prime=prime, base=base)
    p = prime

    # Running hash of T[0..pos-1], built algebraically
    h_running = 0

    # Prefix hash array for substring queries (Corollary 2).
    # prefix_hashes[k] = H(T[0..k-1]), with prefix_hashes[0] = 0.
    # This will be replaced by the rope data structure in the
    # production implementation.
    prefix_hashes: list[int] = [0]

    # Current decoded position
    pos = 0

    for tok in tokens:
        if isinstance(tok, Literal):
            # Rule 1: h = h · x + (c + 1)
            c = tok.byte
            h_running = mersenne_mod(h_running * base + c + 1, p)
            pos += 1
            prefix_hashes.append(h_running)

        elif isinstance(tok, Reference):
            d, l = tok.distance, tok.length

            if d >= l:
                # Rule 2: Non-overlapping (Theorem 1)
                # Source: T[pos-d .. pos-d+l-1]
                # H(source) via Corollary 2:
                #   H(T[a..b]) = P[b+1] - P[a] · x^(b-a+1)
                a = pos - d
                h_source = _substr_hash(prefix_hashes, a, l, h, p)

                # h_running = h_running · x^l + H(source)
                x_l = h.power(l)
                h_running = mersenne_mod(h_running * x_l + h_source, p)

            else:
                # Rule 3: Overlapping (Theorem 5)
                # Pattern P = T[pos-d .. pos-1], length d
                # W = P^q ‖ P[0..r-1]
                q, r = divmod(l, d)

                # H(P) via Corollary 2
                a = pos - d
                h_pattern = _substr_hash(prefix_hashes, a, d, h, p)

                # H(P[0..r-1]) via Corollary 2 (if r > 0)
                if r > 0:
                    h_prefix = _substr_hash(prefix_hashes, a, r, h, p)
                else:
                    h_prefix = 0

                # Theorem 5: H(W) = H(P)·Φ(q, x^d)·x^r + H(P[0..r-1])
                x_d = h.power(d)
                x_r = h.power(r)
                phi_val = phi(q, x_d, p)

                h_w = mersenne_mod(
                    mersenne_mul(mersenne_mul(h_pattern, phi_val, p), x_r, p)
                    + h_prefix,
                    p,
                )

                # h_running = h_running · x^l + H(W)    [Theorem 1]
                x_l = h.power(l)
                h_running = mersenne_mod(h_running * x_l + h_w, p)

            # Update prefix hashes for the decoded bytes.
            # We must fill in prefix_hashes[pos+1] through prefix_hashes[pos+l].
            # These are computed from h_running and the intermediate positions.
            #
            # For intermediate positions, we decode byte-by-byte (needed for
            # future substring queries). This is the part the rope replaces.
            _fill_prefix_hashes(prefix_hashes, pos, d, l, p, base)
            pos += l

    return h_running


def _substr_hash(
    prefix_hashes: list[int],
    start: int,
    length: int,
    h: PolynomialHash,
    p: int,
) -> int:
    """
    Compute H(T[start..start+length-1]) from prefix hashes (Corollary 2).

    H(T[a..b]) = P[b+1] - P[a] · x^(b-a+1) (mod p)
    """
    if length == 0:
        return 0
    a = start
    b = start + length - 1
    x_pow = h.power(b - a + 1)
    result = (prefix_hashes[b + 1] - mersenne_mul(prefix_hashes[a], x_pow, p)) % p
    if result < 0:
        result += p
    return result


def _fill_prefix_hashes(
    prefix_hashes: list[int],
    pos: int,
    d: int,
    l: int,
    p: int,
    base: int,
) -> None:
    """
    Fill prefix_hashes[pos+1] through prefix_hashes[pos+l] for a
    back-reference Ref(d, l) at position pos.

    The decoded bytes are T[pos+k] = T[pos - d + (k mod d)] for k=0..l-1.
    We look up each byte's contribution from earlier prefix hashes and
    extend incrementally.

    This is the O(l) auxiliary work that the rope data structure eliminates.
    """
    for k in range(l):
        # The byte at position pos+k equals the byte at pos - d + (k mod d)
        # We recover its value from the prefix hash difference at that position
        source_pos = pos - d + (k % d)

        # Recover byte value: H(T[source_pos]) = P[source_pos+1] - P[source_pos] · x
        byte_hash = (
            prefix_hashes[source_pos + 1]
            - mersenne_mul(prefix_hashes[source_pos], base, p)
        ) % p
        if byte_hash < 0:
            byte_hash += p
        # byte_hash = byte_value + 1 (by Definition 2)
        # So the byte value is byte_hash - 1
        # But we don't need the byte value — we need the prefix hash.
        # P[pos+k+1] = P[pos+k] · x + (byte_value + 1) = P[pos+k] · x + byte_hash
        prev = prefix_hashes[pos + k]
        prefix_hashes.append(mersenne_mod(prev * base + byte_hash, p))
