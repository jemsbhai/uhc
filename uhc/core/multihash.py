"""
k-tuple multi-hash extension for compressed-domain hashing.

Implements:
- Theorem 20: k-wise collision bound — Pr[collision] ≤ (N/p)^k
- Theorem 21: k-hash rope correctness — all k components maintained independently
- Corollary 5: Concrete security parameters

MultiHash wraps k independent PolynomialHash instances. All operations
return k-tuples, with each component computed independently (Theorem 21).
The rope-based CDH functions operate on k-tuples throughout.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uhc.core.compressed_verifier import CDHMethod

from uhc.core.polynomial_hash import (
    PolynomialHash,
    mersenne_mod,
    MERSENNE_61,
)
from uhc.core.lz77 import Token
from uhc.core.resources import DEFAULT_LIMITS, ResourceLimits


# ---------------------------------------------------------------------------
# MultiHash: k-tuple polynomial hash (Theorem 21)
# ---------------------------------------------------------------------------


class MultiHash:
    """
    k-tuple polynomial hash over Z/pZ.

    Each component is an independent PolynomialHash with a distinct base.
    All operations return tuples of length k.

    Parameters
    ----------
    bases : list[int]
        k hash bases, each in {2, ..., p-1}. Must be non-empty.
    prime : int
        Mersenne prime. Default: 2^61 - 1.
    """

    __slots__ = ("_hashes", "_k", "_p")

    def __init__(self, bases: list[int], prime: int = MERSENNE_61) -> None:
        if not bases:
            raise ValueError("bases must be non-empty (k ≥ 1)")
        if len(set(bases)) != len(bases):
            raise ValueError("bases must be distinct; duplicate bases add no independent check")
        self._k = len(bases)
        self._p = prime
        self._hashes = tuple(PolynomialHash(prime=prime, base=b) for b in bases)

    @property
    def k(self) -> int:
        return self._k

    @property
    def prime(self) -> int:
        return self._p

    def hash(self, data: bytes) -> tuple[int, ...]:
        """H^(k)(data) — k-tuple of independent hashes."""
        return self.hash_iter((data,))

    def hash_iter(self, chunks: Iterable[bytes]) -> tuple[int, ...]:
        """Hash byte chunks in one pass across all tuple components."""
        values = [0] * self._k
        for chunk in chunks:
            for byte in memoryview(chunk).cast("B"):
                for index, hasher in enumerate(self._hashes):
                    values[index] = mersenne_mod(
                        values[index] * hasher.base + byte + 1, self._p
                    )
        return tuple(values)

    def hash_concat(
        self, h_a: tuple[int, ...], len_b: int, h_b: tuple[int, ...]
    ) -> tuple[int, ...]:
        """H^(k)(A‖B) from H^(k)(A), |B|, H^(k)(B) via Theorem 1, component-wise."""
        return tuple(
            self._hashes[i].hash_concat(h_a[i], len_b, h_b[i])
            for i in range(self._k)
        )

    def hash_repeat(
        self, h_s: tuple[int, ...], d: int, q: int
    ) -> tuple[int, ...]:
        """H^(k)(S^q) from H^(k)(S) and |S|=d via Theorem 2, component-wise."""
        return tuple(
            self._hashes[i].hash_repeat(h_s[i], d, q)
            for i in range(self._k)
        )

    def hash_overlap(
        self,
        h_p: tuple[int, ...],
        d: int,
        l: int,
        h_prefix: tuple[int, ...],
    ) -> tuple[int, ...]:
        """H^(k)(W) for overlapping back-reference via Theorem 5, component-wise."""
        return tuple(
            self._hashes[i].hash_overlap(h_p[i], d, l, h_prefix[i])
            for i in range(self._k)
        )

    def zero(self) -> tuple[int, ...]:
        """The k-tuple of zeros (hash of empty string)."""
        return tuple(0 for _ in range(self._k))


# ---------------------------------------------------------------------------
# k-tuple CDH via unbounded rope (Theorem 12 + 21)
# ---------------------------------------------------------------------------


def multi_cdh(
    tokens: Iterable[Token],
    mh: MultiHash,
    *,
    method: str | CDHMethod = "rope",
    d_max: int = 32768,
    m_max: int = 258,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> tuple[int, ...]:
    """
    Compute each CDH component with the requested strategy.

    Each component is an independent CDH computation. By Theorem 21,
    all k components are maintained independently through the rope
    operations, and by Theorem 12, each equals the corresponding
    component of H^(k)(T).

    Implementation: we run k independent single-hash rope CDH
    computations. This is correct because Theorem 21 proves that
    structural operations (traversal, rotation, weight) depend only
    on len and weight (shared across components), while hash
    arithmetic is per-component.
    """
    from uhc.core.compressed_verifier import make_cdh_state
    from uhc.core.lz77 import iter_validated_tokens

    states = [
        make_cdh_state(method, mh._p, hasher.base, d_max, m_max, limits)
        for hasher in mh._hashes
    ]
    for token in iter_validated_tokens(tokens, limits=limits):
        for state in states:
            state.process_token(token)
    return tuple(state.final_hash() for state in states)


# ---------------------------------------------------------------------------
# k-tuple CDH via sliding rope (Theorem 11 + 21)
# ---------------------------------------------------------------------------


def multi_cdh_sliding(
    tokens: Iterable[Token],
    mh: MultiHash,
    d_max: int,
    m_max: int,
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> tuple[int, ...]:
    """
    Compute CDH^(k)(τ) using k independent sliding rope states.

    By Theorem 21, each component is independent. By Theorem 12,
    each equals the corresponding component of H^(k)(T).
    """
    from uhc.core.compressed_verifier import SlidingRopeState
    from uhc.core.lz77 import iter_validated_tokens

    states = [
        SlidingRopeState(
            prime=mh._p,
            base=hasher.base,
            d_max=d_max,
            m_max=m_max,
            limits=limits,
        )
        for hasher in mh._hashes
    ]
    for tok in iter_validated_tokens(
        tokens, limits=limits, max_distance=d_max, max_length=m_max
    ):
        for state in states:
            state.process_token(tok)
    return tuple(state.final_hash() for state in states)
