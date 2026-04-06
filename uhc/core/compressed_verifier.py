"""
Compressed-domain hash verifier.

Computes H(T) from an LZ77 token stream using algebraic composition
(Theorems 1, 2, 5) rather than byte-by-byte hashing. This is the
code-level proof of Theorem 12: CDH(τ) = H(T).

Two back-end strategies are provided:

  - "prefix_array" (Corollary 2): O(N) space prefix hash array.
    Simple, fast per-token, but requires space linear in decoded size.

  - "rope" (Part III, Theorems 6-10): O(n·log N) hash rope.
    Sub-linear space — never materializes the decoded stream.

Both must produce identical results for all inputs. The `method`
parameter selects which strategy to use.
"""

from __future__ import annotations

from enum import Enum
from typing import Sequence

from uhc.core.polynomial_hash import (
    PolynomialHash,
    phi,
    mersenne_mod,
    mersenne_mul,
    MERSENNE_61,
)
from uhc.core.lz77 import Token, Literal, Reference
from uhc.core.rope import (
    Leaf,
    rope_concat,
    rope_split,
    rope_repeat,
    rope_substr_hash,
    rope_len,
    rope_hash,
    Node,
)


class CDHMethod(str, Enum):
    """Strategy for substring queries during compressed-domain hashing."""
    PREFIX_ARRAY = "prefix_array"
    ROPE = "rope"


def compressed_domain_hash(
    tokens: Sequence[Token],
    prime: int = MERSENNE_61,
    base: int = 131,
    method: str | CDHMethod = CDHMethod.ROPE,
) -> int:
    """
    Compute the polynomial hash of the decoded data directly from
    an LZ77 token stream, using algebraic composition.

    Implements the algorithm from Theorem 11 and proves
    Theorem 12: CDH(τ) = H(T).

    Parameters
    ----------
    tokens : sequence of Token
        LZ77 token stream.
    prime : int
        Mersenne prime for the hash ring.
    base : int
        Hash base x.
    method : str or CDHMethod
        "prefix_array" — O(N) space, prefix hash array (Corollary 2).
        "rope" — O(n·log N) space, hash rope (Part III).

    Returns
    -------
    int
        H(decoded data), computed without full decompression.
    """
    method = CDHMethod(method)
    if method == CDHMethod.PREFIX_ARRAY:
        return _cdh_prefix_array(tokens, prime, base)
    elif method == CDHMethod.ROPE:
        return _cdh_rope(tokens, prime, base)
    else:
        raise ValueError(f"Unknown method: {method}")


# ---------------------------------------------------------------------------
# Strategy 1: Prefix hash array (Corollary 2) — O(N) space
# ---------------------------------------------------------------------------


def _cdh_prefix_array(
    tokens: Sequence[Token],
    prime: int,
    base: int,
) -> int:
    """Original implementation using prefix hash array."""
    h = PolynomialHash(prime=prime, base=base)
    p = prime

    h_running = 0
    prefix_hashes: list[int] = [0]
    pos = 0

    for tok in tokens:
        if isinstance(tok, Literal):
            c = tok.byte
            h_running = mersenne_mod(h_running * base + c + 1, p)
            pos += 1
            prefix_hashes.append(h_running)

        elif isinstance(tok, Reference):
            d, l = tok.distance, tok.length

            if d >= l:
                a = pos - d
                h_source = _substr_hash_prefix(prefix_hashes, a, l, h, p)
                x_l = h.power(l)
                h_running = mersenne_mod(h_running * x_l + h_source, p)
            else:
                q, r = divmod(l, d)
                a = pos - d
                h_pattern = _substr_hash_prefix(prefix_hashes, a, d, h, p)
                h_prefix = (
                    _substr_hash_prefix(prefix_hashes, a, r, h, p) if r > 0 else 0
                )
                x_d = h.power(d)
                x_r = h.power(r)
                phi_val = phi(q, x_d, p)
                h_w = mersenne_mod(
                    mersenne_mul(mersenne_mul(h_pattern, phi_val, p), x_r, p)
                    + h_prefix,
                    p,
                )
                x_l = h.power(l)
                h_running = mersenne_mod(h_running * x_l + h_w, p)

            _fill_prefix_hashes(prefix_hashes, pos, d, l, p, base)
            pos += l

    return h_running


def _substr_hash_prefix(
    prefix_hashes: list[int],
    start: int,
    length: int,
    h: PolynomialHash,
    p: int,
) -> int:
    """H(T[start..start+length-1]) from prefix hashes (Corollary 2)."""
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
    """Fill prefix_hashes for a back-reference. O(l) auxiliary work."""
    for k in range(l):
        source_pos = pos - d + (k % d)
        byte_hash = (
            prefix_hashes[source_pos + 1]
            - mersenne_mul(prefix_hashes[source_pos], base, p)
        ) % p
        if byte_hash < 0:
            byte_hash += p
        prev = prefix_hashes[pos + k]
        prefix_hashes.append(mersenne_mod(prev * base + byte_hash, p))


# ---------------------------------------------------------------------------
# Strategy 2: Hash rope (Part III, Theorems 6-10) — O(n·log N) space
# ---------------------------------------------------------------------------


def _cdh_rope(
    tokens: Sequence[Token],
    prime: int,
    base: int,
) -> int:
    """
    Compute CDH using the hash rope for all substring queries.

    This never materializes the decoded byte stream. Back-references
    are resolved by extracting subtrees from the rope (Split) and
    constructing RepeatNodes for overlapping copies (Theorem 8).

    Space: O(n · log N) for the rope (no prefix array, no decoded buffer).
    """
    h = PolynomialHash(prime=prime, base=base)
    rope: Node = None

    for tok in tokens:
        if isinstance(tok, Literal):
            leaf = Leaf(bytes([tok.byte]), h)
            rope = rope_concat(rope, leaf, h)

        elif isinstance(tok, Reference):
            d, l = tok.distance, tok.length
            pos = rope_len(rope)

            if d >= l:
                # Non-overlapping: extract source subtree from rope
                start = pos - d
                _, tmp = rope_split(rope, start, h)
                source, _ = rope_split(tmp, l, h)
                rope = rope_concat(rope, source, h)
            else:
                # Overlapping: extract pattern of length d, repeat
                start = pos - d
                _, tmp = rope_split(rope, start, h)
                pattern, _ = rope_split(tmp, d, h)

                q, r = divmod(l, d)
                rep: Node = rope_repeat(pattern, q, h) if q >= 1 else None
                if r > 0:
                    partial, _ = rope_split(pattern, r, h)
                    rep = rope_concat(rep, partial, h)
                rope = rope_concat(rope, rep, h)

    return rope_hash(rope) if rope else 0
