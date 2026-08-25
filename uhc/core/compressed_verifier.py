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
from collections.abc import Iterable

from uhc.core.polynomial_hash import (
    PolynomialHash,
    phi,
    mersenne_mod,
    mersenne_mul,
    MERSENNE_61,
)
from uhc.core.lz77 import Token, Literal, Reference, iter_validated_tokens
from uhc.core.resources import DEFAULT_LIMITS, ResourceLimitError, ResourceLimits
from uhc.core.rope import (
    Leaf,
    rope_concat,
    rope_split,
    rope_repeat,
    rope_len,
    rope_hash,
    rope_height,
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
    tokens: Iterable[Token],
    prime: int = MERSENNE_61,
    base: int = 131,
    method: str | CDHMethod = CDHMethod.ROPE,
    *,
    d_max: int = _DEFLATE_D_MAX,
    m_max: int = _DEFLATE_M_MAX,
    limits: ResourceLimits = DEFAULT_LIMITS,
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
    state = make_cdh_state(method, prime, base, d_max, m_max, limits)
    for tok in iter_validated_tokens(tokens, limits=limits):
        state.process_token(tok)
    return state.final_hash()


def make_cdh_state(
    method: str | CDHMethod,
    prime: int,
    base: int,
    d_max: int,
    m_max: int,
    limits: ResourceLimits,
):
    """Create an incremental state for one CDH component."""
    method = CDHMethod(method)
    if method == CDHMethod.PREFIX_ARRAY:
        return PrefixArrayState(prime, base)
    if method == CDHMethod.ROPE:
        return RopeHashState(prime, base, limits.max_depth)
    if method == CDHMethod.SLIDING_ROPE:
        return SlidingRopeState(prime, base, d_max, m_max, limits=limits)
    raise ValueError(f"Unknown method: {method}")


# ---------------------------------------------------------------------------
# Strategy 1: Prefix hash array (Corollary 2) — O(N) space
# ---------------------------------------------------------------------------


class PrefixArrayState:
    """Incremental prefix-array CDH state for one hash component."""

    __slots__ = ("h", "p", "base", "h_running", "prefix_hashes", "pos")

    def __init__(self, prime: int, base: int) -> None:
        self.h = PolynomialHash(prime=prime, base=base)
        self.p = prime
        self.base = base
        self.h_running = 0
        self.prefix_hashes: list[int] = [0]
        self.pos = 0

    def process_token(self, tok: Token) -> None:
        if isinstance(tok, Literal):
            self.h_running = mersenne_mod(
                self.h_running * self.base + tok.byte + 1, self.p
            )
            self.pos += 1
            self.prefix_hashes.append(self.h_running)
            return

        d, length = tok.distance, tok.length
        start = self.pos - d
        if d >= length:
            copied_hash = _substr_hash_prefix(
                self.prefix_hashes, start, length, self.h, self.p
            )
        else:
            repetitions, remainder = divmod(length, d)
            pattern_hash = _substr_hash_prefix(
                self.prefix_hashes, start, d, self.h, self.p
            )
            prefix_hash = (
                _substr_hash_prefix(
                    self.prefix_hashes, start, remainder, self.h, self.p
                )
                if remainder
                else 0
            )
            repeated_hash = mersenne_mul(
                mersenne_mul(
                    pattern_hash,
                    phi(repetitions, self.h.power(d), self.p),
                    self.p,
                ),
                self.h.power(remainder),
                self.p,
            )
            copied_hash = mersenne_mod(repeated_hash + prefix_hash, self.p)

        self.h_running = mersenne_mod(
            self.h_running * self.h.power(length) + copied_hash, self.p
        )
        _fill_prefix_hashes(
            self.prefix_hashes, self.pos, d, length, self.p, self.base
        )
        self.pos += length

    def final_hash(self) -> int:
        return self.h_running


def _cdh_prefix_array(
    tokens: Iterable[Token],
    prime: int,
    base: int,
) -> int:
    """Original implementation using prefix hash array."""
    state = PrefixArrayState(prime, base)
    for token in tokens:
        state.process_token(token)
    return state.final_hash()


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


class RopeHashState:
    """Incremental persistent-rope CDH state with a depth budget."""

    __slots__ = ("h", "rope", "max_depth")

    def __init__(self, prime: int, base: int, max_depth: int) -> None:
        self.h = PolynomialHash(prime=prime, base=base)
        self.rope: Node = None
        self.max_depth = max_depth

    def process_token(self, tok: Token) -> None:
        if isinstance(tok, Literal):
            self.rope = rope_concat(
                self.rope, Leaf(bytes([tok.byte]), self.h), self.h
            )
        else:
            d, length = tok.distance, tok.length
            start = rope_len(self.rope) - d
            _, suffix = rope_split(self.rope, start, self.h)
            if d >= length:
                copied, _ = rope_split(suffix, length, self.h)
                assert copied is not None
            else:
                pattern, _ = rope_split(suffix, d, self.h)
                assert pattern is not None
                repetitions, remainder = divmod(length, d)
                copied = rope_repeat(pattern, repetitions, self.h)
                if remainder:
                    partial, _ = rope_split(pattern, remainder, self.h)
                    copied = rope_concat(copied, partial, self.h)
            self.rope = rope_concat(self.rope, copied, self.h)

        depth = rope_height(self.rope)
        if depth > self.max_depth:
            raise ResourceLimitError(
                f"Rope depth {depth} exceeds max_depth={self.max_depth}"
            )

    def final_hash(self) -> int:
        return rope_hash(self.rope) if self.rope else 0


def _cdh_rope(
    tokens: Iterable[Token],
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
    state = RopeHashState(prime, base, DEFAULT_LIMITS.max_depth)
    for token in tokens:
        state.process_token(token)
    return state.final_hash()


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
                 "r_window", "pos", "limits", "token_count")

    def __init__(
        self,
        prime: int = MERSENNE_61,
        base: int = 131,
        d_max: int = _DEFLATE_D_MAX,
        m_max: int = _DEFLATE_M_MAX,
        *,
        limits: ResourceLimits = DEFAULT_LIMITS,
    ) -> None:
        if d_max < 1:
            raise ValueError(f"d_max must be ≥ 1, got {d_max}")
        if m_max < 1:
            raise ValueError(f"m_max must be ≥ 1, got {m_max}")

        self.h = PolynomialHash(prime=prime, base=base)
        self.d_max = d_max
        self.m_max = m_max
        self.W = d_max + m_max
        self.limits = limits
        self.token_count = 0

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
        if self.token_count >= self.limits.max_tokens:
            raise ResourceLimitError(
                f"Token count exceeds max_tokens={self.limits.max_tokens}"
            )
        if isinstance(tok, Literal):
            self.limits.check_output(self.pos + 1)
            self._process_literal(tok.byte)
        elif isinstance(tok, Reference):
            if tok.distance > self.limits.max_reference_distance:
                raise ResourceLimitError(
                    f"Reference distance {tok.distance} exceeds "
                    f"max_reference_distance={self.limits.max_reference_distance}"
                )
            if tok.length > self.limits.max_reference_length:
                raise ResourceLimitError(
                    f"Reference length {tok.length} exceeds "
                    f"max_reference_length={self.limits.max_reference_length}"
                )
            self.limits.check_output(self.pos + tok.length)
            self._process_ref(tok.distance, tok.length)
        else:
            raise TypeError(f"Unsupported token type {type(tok).__name__}")
        self.token_count += 1
        depth = rope_height(self.r_window)
        if depth > self.limits.max_depth:
            raise ResourceLimitError(
                f"Rope depth {depth} exceeds max_depth={self.limits.max_depth}"
            )

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
            assert pattern is not None

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
