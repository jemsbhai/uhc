"""
Theorem 23: Composition with Cryptographic Hash (BLAKE3).

Provides a dual-mode integrity scheme:

    (a) Fast path — CDH^(k) only.
        Cost: O(k · c_F · n). Collision bound: (N/p)^k.
        Sufficient for non-adversarial integrity (bit rot, accidental corruption).

    (b) Full path — CDH^(k) + BLAKE3(T).
        Cost: O(k · c_F · n) + O(N). Security: BLAKE3 collision resistance.
        Required when hash bases are public or adversary controls input.

    (c) Incremental update — two modes:
        - List mode: CDH via Corollary 1 composition, O(k) add, O(k·m) remove.
        - Rope mode: CDH via rope operations (Theorems 6-7), O(k·log m) add/remove.
        BLAKE3 recomputed from stored chunk data on removal.

The CDH hash provides fast probabilistic screening; BLAKE3 provides
cryptographic collision resistance for adversarial settings (Theorem 22).

Requires: blake3 package (pip install blake3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from uhc.core.lz77 import Token, Literal, Reference, lz77_decode
from uhc.core.multihash import MultiHash, multi_cdh
from uhc.core.polynomial_hash import PolynomialHash, MERSENNE_61


# ---------------------------------------------------------------------------
# Lazy import of blake3 (optional dependency)
# ---------------------------------------------------------------------------

def _import_blake3():
    """Import blake3, raising a clear error if not installed."""
    try:
        import blake3
        return blake3
    except ImportError:
        raise ImportError(
            "blake3 package required for full-path integrity (Theorem 23b). "
            "Install via: pip install blake3"
        )


# ---------------------------------------------------------------------------
# IntegrityResult
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IntegrityResult:
    """
    Result of an integrity computation (Theorem 23).

    Attributes
    ----------
    cdh_hash : tuple[int, ...]
        k-tuple polynomial CDH hash. Always present.
    blake3_digest : bytes or None
        32-byte BLAKE3 digest. Present only in full-path mode.
    mode : str
        "fast" (CDH only) or "full" (CDH + BLAKE3).
    """
    cdh_hash: tuple[int, ...]
    blake3_digest: bytes | None
    mode: str


# ---------------------------------------------------------------------------
# Theorem 23(a): Fast path — CDH only
# ---------------------------------------------------------------------------

def integrity_fast(
    tokens: Sequence[Token],
    mh: MultiHash,
) -> IntegrityResult:
    """
    Fast-path integrity: CDH^(k) only (Theorem 23a).

    Computes the k-tuple compressed-domain hash without decompression.
    Collision bound: (N/p)^k (Theorem 20).

    Parameters
    ----------
    tokens : sequence of Token
        LZ77 token stream extracted from compressed data.
    mh : MultiHash
        k-tuple hash configuration.

    Returns
    -------
    IntegrityResult
        With cdh_hash set, blake3_digest = None, mode = "fast".
    """
    cdh = multi_cdh(tokens, mh)
    return IntegrityResult(cdh_hash=cdh, blake3_digest=None, mode="fast")


# ---------------------------------------------------------------------------
# Theorem 23(b): Full path — CDH + BLAKE3
# ---------------------------------------------------------------------------

def integrity_full(
    data: bytes,
    fmt: "Format",
    mh: MultiHash,
) -> IntegrityResult:
    """
    Full-path integrity: CDH^(k) + BLAKE3(T) (Theorem 23b).

    Computes CDH from the compressed token stream (no decompression for
    the hash), then separately decompresses and computes BLAKE3 for
    cryptographic collision resistance.

    Cost: O(k · c_F · n) for CDH + O(N) for BLAKE3.
    Security: collision resistance of BLAKE3 (Theorem 22).

    Parameters
    ----------
    data : bytes
        Compressed data.
    fmt : Format
        Compression format.
    mh : MultiHash
        k-tuple hash configuration.

    Returns
    -------
    IntegrityResult
        With both cdh_hash and blake3_digest set, mode = "full".
    """
    blake3_mod = _import_blake3()

    # Import here to avoid circular dependency
    from uhc.engine.pipeline import extract_tokens

    # Step 1: Extract tokens (shared between CDH and decompression)
    tokens = extract_tokens(data, fmt)

    # Step 2: CDH^(k) — no decompression needed (Theorem 12)
    cdh = multi_cdh(tokens, mh)

    # Step 3: Decompress and compute BLAKE3(T)
    decompressed = lz77_decode(tokens)
    digest = blake3_mod.blake3(decompressed).digest()

    return IntegrityResult(cdh_hash=cdh, blake3_digest=digest, mode="full")


# ---------------------------------------------------------------------------
# Theorem 23(c): List-based incremental integrity — O(k) add, O(k·m) remove
# ---------------------------------------------------------------------------

class IncrementalIntegrity:
    """
    List-based incremental integrity (Theorem 23c).

    Maintains both CDH and BLAKE3 state as chunks are added or removed.

    CDH updates use hash composition (Theorem 1 / Corollary 1):
        H(A ‖ B) = H(A) · x^|B| + H(B)
    Adding a chunk is O(k) via hash_concat. Removing the last chunk
    requires recomposition from stored per-chunk hashes in O(k · m)
    where m is the remaining chunk count.

    BLAKE3 updates use streaming for additions. Removal requires
    recomputation from stored chunk data (BLAKE3's internal Merkle
    tree is not exposed for branch-level updates in the Python API).

    Parameters
    ----------
    bases : list[int]
        Hash bases for k-tuple multi-hash.
    prime : int
        Mersenne prime.
    """

    def __init__(
        self,
        bases: list[int],
        prime: int = MERSENNE_61,
    ) -> None:
        self._mh = MultiHash(bases=bases, prime=prime)
        self._blake3_mod = _import_blake3()

        # Per-chunk state for incremental CDH (Corollary 1)
        self._chunk_hashes: list[tuple[int, ...]] = []  # H^(k)(chunk_i)
        self._chunk_lengths: list[int] = []               # |chunk_i|

        # Per-chunk data for BLAKE3 recomputation on removal
        self._chunk_data: list[bytes] = []

        # Running CDH state (composed via Theorem 1)
        self._running_cdh: tuple[int, ...] = self._mh.zero()
        self._total_len: int = 0

        # Running BLAKE3 hasher
        self._blake3_hasher = self._blake3_mod.blake3()

    def add_chunk(self, chunk: bytes) -> None:
        """
        Add a chunk to the archive.

        CDH: O(k) via Theorem 1 composition.
        BLAKE3: O(|chunk|) via streaming update.
        """
        chunk_hash = self._mh.hash(chunk)
        chunk_len = len(chunk)

        # CDH: H(existing ‖ chunk) = H(existing) · x^|chunk| + H(chunk)
        self._running_cdh = self._mh.hash_concat(
            self._running_cdh, chunk_len, chunk_hash
        )
        self._total_len += chunk_len

        # BLAKE3: streaming update
        self._blake3_hasher.update(chunk)

        # Store for removal support
        self._chunk_hashes.append(chunk_hash)
        self._chunk_lengths.append(chunk_len)
        self._chunk_data.append(chunk)

    def remove_last_chunk(self) -> None:
        """
        Remove the last chunk from the archive.

        CDH: Recompose from remaining per-chunk hashes via Corollary 1.
        BLAKE3: Recompute from remaining chunk data.
        """
        if not self._chunk_hashes:
            raise IndexError("No chunks to remove")

        self._chunk_hashes.pop()
        self._chunk_lengths.pop()
        self._chunk_data.pop()

        # Recompose CDH from remaining chunks via Corollary 1
        self._running_cdh = self._mh.zero()
        self._total_len = 0
        for ch, cl in zip(self._chunk_hashes, self._chunk_lengths):
            self._running_cdh = self._mh.hash_concat(
                self._running_cdh, cl, ch
            )
            self._total_len += cl

        # Recompute BLAKE3 from remaining chunks
        self._blake3_hasher = self._blake3_mod.blake3()
        for cd in self._chunk_data:
            self._blake3_hasher.update(cd)

    def cdh_hash(self) -> tuple[int, ...]:
        """Current CDH^(k) of all chunks concatenated."""
        return self._running_cdh

    def blake3_digest(self) -> bytes:
        """Current BLAKE3 digest of all chunks concatenated."""
        return self._blake3_hasher.copy().digest()

    def chunk_count(self) -> int:
        """Number of chunks currently in the archive."""
        return len(self._chunk_hashes)

    def total_length(self) -> int:
        """Total byte length of all chunks."""
        return self._total_len


# ---------------------------------------------------------------------------
# Theorem 23(c): Rope-based incremental integrity — O(k·log m) add/remove
# ---------------------------------------------------------------------------

class RopeIncrementalIntegrity:
    """
    Rope-based incremental integrity (Theorem 23c, O(k·log m) operations).

    Maintains k independent hash ropes (Theorem 21), one per base.
    Each rope's root hash gives H_{x_i}(chunk_1 ‖ ... ‖ chunk_m)
    by Lemma 4 (hash correctness).

    Operations and their complexity:
        add_chunk:    O(k · log m) CDH via rope_concat (Theorem 6)
                      + O(|chunk|) BLAKE3 streaming update
        remove_last:  O(k · log m) CDH via rope_split (Theorem 7)
                      + O(N_remaining) BLAKE3 recomputation
        cdh_hash:     O(k) — read root hash of each rope
        blake3_digest: O(1) — copy of streaming hasher

    Correctness:
        Lemma 4 → rope_i.hash_val = H_{x_i}(T) at all times
        Theorem 6 → rope_concat preserves I1–I9
        Theorem 7 → rope_split preserves I1–I9
        Theorem 21 → k components are independent

    Parameters
    ----------
    bases : list[int]
        Hash bases for k-tuple multi-hash.
    prime : int
        Mersenne prime.
    """

    def __init__(
        self,
        bases: list[int],
        prime: int = MERSENNE_61,
    ) -> None:
        self._blake3_mod = _import_blake3()
        self._k = len(bases)
        self._hashes = [PolynomialHash(prime=prime, base=b) for b in bases]

        # k ropes, one per hash base (Theorem 21)
        self._ropes: list = [None] * self._k

        # Per-chunk lengths for split position computation
        self._chunk_lengths: list[int] = []
        self._total_len: int = 0

        # Per-chunk data for BLAKE3 recomputation on removal
        self._chunk_data: list[bytes] = []

        # Streaming BLAKE3 hasher
        self._blake3_hasher = self._blake3_mod.blake3()

    def add_chunk(self, chunk: bytes) -> None:
        """
        Add a chunk via rope_concat (Theorem 6).

        For each base i: rope_i = rope_concat(rope_i, Leaf(chunk, h_i), h_i).
        Time: O(k · log m) where m is the chunk count.
        """
        from uhc.core.rope import Leaf, rope_concat

        for i in range(self._k):
            leaf = Leaf(chunk, self._hashes[i])
            self._ropes[i] = rope_concat(self._ropes[i], leaf, self._hashes[i])

        self._chunk_lengths.append(len(chunk))
        self._total_len += len(chunk)
        self._chunk_data.append(chunk)
        self._blake3_hasher.update(chunk)

    def remove_last_chunk(self) -> None:
        """
        Remove the last chunk via rope_split (Theorem 7).

        For each base i: rope_i, _ = rope_split(rope_i, split_pos, h_i).
        Time: O(k · log m).
        """
        from uhc.core.rope import rope_split

        if not self._chunk_lengths:
            raise IndexError("No chunks to remove")

        last_len = self._chunk_lengths.pop()
        self._chunk_data.pop()
        self._total_len -= last_len

        # Split each rope at the new total length (Theorem 7)
        split_pos = self._total_len
        for i in range(self._k):
            left, _ = rope_split(self._ropes[i], split_pos, self._hashes[i])
            self._ropes[i] = left

        # Recompute BLAKE3 from remaining chunks
        self._blake3_hasher = self._blake3_mod.blake3()
        for cd in self._chunk_data:
            self._blake3_hasher.update(cd)

    def cdh_hash(self) -> tuple[int, ...]:
        """Current CDH^(k) — root hash of each rope (Lemma 4)."""
        from uhc.core.rope import rope_hash
        return tuple(rope_hash(self._ropes[i]) for i in range(self._k))

    def blake3_digest(self) -> bytes:
        """Current BLAKE3 digest of all chunks concatenated."""
        return self._blake3_hasher.copy().digest()

    def chunk_count(self) -> int:
        """Number of chunks currently in the archive."""
        return len(self._chunk_lengths)

    def total_length(self) -> int:
        """Total byte length of all chunks."""
        return self._total_len
