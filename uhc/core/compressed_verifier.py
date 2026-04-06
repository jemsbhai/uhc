"""
Compressed-domain hash verifier.

Computes H(T) from an LZ77 token stream using algebraic composition
(Theorems 1, 2, 5) rather than byte-by-byte hashing. This is the
code-level proof of Theorem 12: CDH(τ) = H(T).

Three back-end strategies are provided:

  - "prefix_array" (Corollary 2): O(N) space prefix hash array.
    Simple, fast per-token, but requires space linear in decoded size.

  - "rope" (Part III, Theorems 6-10): O(n·log N) hash rope.
    Sub-linear space — never materializes the decoded stream.
    Rope grows unboundedly with the token stream.

  - "sliding_rope" (Definition 10, Theorem 11): O(W) hash rope.
    Bounded memory: maintains a window of at most W = d_max + m_max
    bytes. Bytes older than the window are folded into a running
    prefix hash H_prefix. Memory independent of decoded size N.

All three must produce identical results for all inputs.
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
    rope_to_bytes,
    Node,
)


# Default format parameters (DEFLATE — Definition 8)
_DEFLATE_D_MAX = 32768
_DEFLATE_M_MAX = 258


class CDHMethod(str, Enum):
    """Strategy for substring queries during compressed-domain hashing."""
    PREFIX_ARRAY = "prefix_array"
    ROPE = "rope"
    SLIDING_ROPE = "sliding_rope"


def compressed_domain_hash(
    tokens: Sequence[Token],
    prime: int = MERSENNE_61,
    base: int = 131,
    method: str | CDHMethod = CDHMethod.ROPE,
    *,
    d_max: int = _DEFLATE_D_MAX,
    m_max: int = _DEFLATE_M_MAX,
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
        "rope" — O(n·log N) space, unbounded hash rope (Part III).
        "sliding_rope" — O(W) space, bounded sliding window (Definition 10).
    d_max : int
        Maximum back-reference distance (for sliding_rope window sizing).
    m_max : int
        Maximum match length (for sliding_rope window sizing).

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
    elif method == CDHMethod.SLIDING_ROPE:
        state = SlidingRopeState(prime, base, d_max, m_max)
        for tok in tokens:
            state.process_token(tok)
        return state.final_hash()
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
                start = pos - d
                _, tmp = rope_split(rope, start, h)
                source, _ = rope_split(tmp, l, h)
                rope = rope_concat(rope, source, h)
            else:
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


# ---------------------------------------------------------------------------
# Strategy 3: Sliding rope (Definition 10, Theorem 11) — O(W) space
# ---------------------------------------------------------------------------


class SlidingRopeState:
    """
    Sliding window rope state (Definition 10).

    Exposes internal state for invariant verification in tests.

    State variables:
        h_prefix : int    — H(T[0 .. l_prefix - 1])
        l_prefix : int    — count of evicted bytes
        r_window : Node   — rope covering T[l_prefix .. pos - 1]
        pos      : int    — total decoded bytes so far
        W        : int    — maximum window extent = d_max + m_max

    Invariant I_slide (must hold after every token):
        (1) h_prefix = H(T[0 .. l_prefix - 1])
        (2) r_window represents T[l_prefix .. pos - 1]
        (3) rope_len(r_window) = pos - l_prefix ≤ W
        (4) H(T[0..pos-1]) = h_prefix · x^(pos - l_prefix) + rope_hash(r_window)
    """

    __slots__ = ("h", "d_max", "m_max", "W", "h_prefix", "l_prefix",
                 "r_window", "pos")

    def __init__(
        self,
        prime: int = MERSENNE_61,
        base: int = 131,
        d_max: int = _DEFLATE_D_MAX,
        m_max: int = _DEFLATE_M_MAX,
    ) -> None:
        if d_max < 1:
            raise ValueError(f"d_max must be ≥ 1, got {d_max}")
        if m_max < 1:
            raise ValueError(f"m_max must be ≥ 1, got {m_max}")

        self.h = PolynomialHash(prime=prime, base=base)
        self.d_max = d_max
        self.m_max = m_max
        self.W = d_max + m_max

        # State (Definition 10)
        self.h_prefix: int = 0      # H(T[0..l_prefix-1])
        self.l_prefix: int = 0      # evicted byte count
        self.r_window: Node = None  # rope for T[l_prefix..pos-1]
        self.pos: int = 0           # total decoded bytes

    @property
    def window_len(self) -> int:
        """Current window size in bytes."""
        return rope_len(self.r_window)

    def current_hash(self) -> int:
        """
        Compute H(T[0..pos-1]) from sliding state via Theorem 1:
            H(T) = H_prefix · x^(window_len) + H(window)
        """
        wl = self.window_len
        wh = rope_hash(self.r_window) if self.r_window else 0
        return self.h.hash_concat(self.h_prefix, wl, wh)

    def process_token(self, tok: Token) -> None:
        """Process a single token, maintaining I_slide."""
        if isinstance(tok, Literal):
            self._process_literal(tok.byte)
        elif isinstance(tok, Reference):
            self._process_ref(tok.distance, tok.length)

    def _process_literal(self, c: int) -> None:
        """ProcessLiteral(c) — Theorem 11."""
        leaf = Leaf(bytes([c]), self.h)
        self.r_window = rope_concat(self.r_window, leaf, self.h)
        self.pos += 1
        self._evict()

    def _process_ref(self, d: int, l: int) -> None:
        """ProcessRef(d, l) — Theorem 11."""
        win_len = self.window_len

        # Validity check (Definition 5): d ≤ pos
        if d > self.pos:
            raise ValueError(
                f"Invalid back-reference: distance {d} exceeds "
                f"decoded length {self.pos}"
            )

        # Window sufficiency check: the source must be within the window.
        # After eviction the window covers the last d_max bytes.
        # If d > win_len, the source extends before the window — this
        # means d_max was set too small for the token stream.
        if d > win_len:
            raise ValueError(
                f"Back-reference distance {d} exceeds window size {win_len}. "
                f"Increase d_max (currently {self.d_max}) to at least {d}."
            )

        start = win_len - d

        if d >= l:
            # Non-overlapping
            _, tmp = rope_split(self.r_window, start, self.h)
            source, _ = rope_split(tmp, l, self.h)
            self.r_window = rope_concat(self.r_window, source, self.h)
        else:
            # Overlapping: extract pattern of length d, repeat
            _, tmp = rope_split(self.r_window, start, self.h)
            pattern, _ = rope_split(tmp, d, self.h)

            q, r = divmod(l, d)
            rep: Node = rope_repeat(pattern, q, self.h) if q >= 1 else None
            if r > 0:
                partial, _ = rope_split(pattern, r, self.h)
                rep = rope_concat(rep, partial, self.h)
            self.r_window = rope_concat(self.r_window, rep, self.h)

        self.pos += l
        self._evict()

    def _evict(self) -> None:
        """
        Evict excess bytes from the window (Theorem 11, Evict()).

        After eviction: rope_len(r_window) ≤ d_max, ensuring that
        future back-references of distance ≤ d_max find their source.

        Correctness (Lemma 12): The prefix hash update follows from
        Theorem 1 (concatenation composability):
            H(A ‖ B) = H(A) · x^|B| + H(B)
        so:
            H_prefix_new = H(T[0..l_prefix_old-1] ‖ T[l_prefix_old..l_prefix_new-1])
                         = H_prefix_old · x^excess + H(evicted)
        """
        win_len = rope_len(self.r_window)
        if win_len <= self.W:
            return

        # Evict down to d_max bytes remaining
        excess = win_len - self.d_max
        r_old, r_keep = rope_split(self.r_window, excess, self.h)

        # Fold evicted bytes into h_prefix via Theorem 1
        old_len = rope_len(r_old)
        old_hash = rope_hash(r_old)
        self.h_prefix = self.h.hash_concat(self.h_prefix, old_len, old_hash)

        self.l_prefix += excess
        self.r_window = r_keep

    def final_hash(self) -> int:
        """
        FinalHash() — Theorem 11.

        H(T[0..N-1]) = H_prefix · x^(R_window.len) + R_window.hash

        Proof: By Theorem 1, H(A ‖ B) = H(A) · x^|B| + H(B), where
        A = T[0..l_prefix-1] and B = T[l_prefix..N-1].
        """
        return self.current_hash()
