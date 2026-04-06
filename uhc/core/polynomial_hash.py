"""
Polynomial hash over Z/pZ with Mersenne prime arithmetic.

Implements Definitions 1-3, Lemmas 1-2, 13-14, Theorems 1-3, 5
from the compressed-domain hashing framework.

All arithmetic is performed modulo a Mersenne prime p = 2^61 - 1
using bit-shift reduction (Lemma 14) to avoid expensive division.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MERSENNE_61: int = (1 << 61) - 1  # 2^61 - 1
MERSENNE_127: int = (1 << 127) - 1  # 2^127 - 1 (recommended for high security, Corollary 5)


# ---------------------------------------------------------------------------
# Mersenne prime arithmetic (Lemma 14)
# ---------------------------------------------------------------------------

def mersenne_mod(a: int, p: int = MERSENNE_61) -> int:
    """
    Reduce a non-negative integer a modulo a Mersenne prime p = 2^k - 1.

    Uses the identity: a mod (2^k - 1) = (a >> k) + (a & ((1 << k) - 1))
    with at most one conditional subtraction.

    Proof (Lemma 14): Write a = q·2^k + r. Then a = q·(p+1) + r = q·p + (q+r),
    so a ≡ q + r (mod p). Since q + r < 2^(k+1), at most one subtraction suffices.
    """
    # Determine k from p: p = 2^k - 1, so k = p.bit_length()
    k = p.bit_length()
    # Repeated folding for very large values
    while a >= (1 << (2 * k)):
        a = (a >> k) + (a & p)
    # Final fold
    a = (a >> k) + (a & p)
    # At most one more fold needed
    a = (a >> k) + (a & p)
    # Conditional subtraction
    if a >= p:
        a -= p
    return a


def mersenne_mul(a: int, b: int, p: int = MERSENNE_61) -> int:
    """
    Compute (a * b) mod p for Mersenne prime p.

    Python's arbitrary-precision integers make this straightforward:
    multiply natively, then reduce via mersenne_mod.
    """
    return mersenne_mod(a * b, p)


# ---------------------------------------------------------------------------
# Geometric accumulator Φ (Definition 3, Theorem 3)
# ---------------------------------------------------------------------------

def phi(q: int, alpha: int, p: int = MERSENNE_61) -> int:
    """
    Compute Φ(q, α) = Σ_{i=0}^{q-1} α^i (mod p) via inverse-free
    repeated doubling.

    Recurrence (Theorem 3):
        Φ(0, α) = 0
        Φ(1, α) = 1
        Φ(2k, α)   = Φ(k, α) · (1 + α^k)
        Φ(2k+1, α) = Φ(2k, α) · α + 1

    Handles the degenerate case α ≡ 1 (mod p) correctly,
    yielding Φ(q, 1) = q (mod p) (Lemma 3).

    Time: O(log q) multiplications in Z/pZ.

    Implementation note: We scan q's bits left-to-right (MSB to LSB).
    We maintain alpha_power = α^n where n is the current accumulated
    value of q built so far. At each step:
      - Doubling (n → 2n): alpha_power squares (α^n → α^(2n))
      - Odd step (n → n+1): alpha_power multiplies by α (α^n → α^(n+1))
    This ensures the correct α^k is used in each doubling step.
    """
    if q == 0:
        return 0
    if q == 1:
        return 1

    bits = q.bit_length()

    phi_val = 1           # Φ(1, α) = 1
    alpha_power = alpha   # α^1 — tracks α^(current n)

    # Scan from the second-most-significant bit down to bit 0
    for i in range(bits - 2, -1, -1):
        # Even step: Φ(2k, α) = Φ(k, α) · (1 + α^k)
        # alpha_power currently holds α^k
        phi_val = mersenne_mul(phi_val, (1 + alpha_power) % p, p)
        # α^k → α^(2k)
        alpha_power = mersenne_mul(alpha_power, alpha_power, p)

        # If current bit is 1: odd step (2k → 2k+1)
        if (q >> i) & 1:
            # Φ(2k+1, α) = Φ(2k, α) · α + 1
            phi_val = (mersenne_mul(phi_val, alpha, p) + 1) % p
            # α^(2k) → α^(2k+1)
            alpha_power = mersenne_mul(alpha_power, alpha, p)

    return phi_val


# ---------------------------------------------------------------------------
# Polynomial Hash (Definition 2, Theorems 1-2, 5)
# ---------------------------------------------------------------------------

class PolynomialHash:
    """
    Polynomial hash function over Z/pZ.

    H(s) = Σ_{i=0}^{n-1} (s_i + 1) · x^(n-1-i) (mod p)

    The +1 offset (Definition 2) ensures no byte maps to zero in Z/pZ,
    preventing the zero-padding collision (Lemma 1).

    Parameters
    ----------
    prime : int
        A Mersenne prime. Default: 2^61 - 1.
    base : int
        The hash base x, chosen from {2, ..., p-1}.
    """

    __slots__ = ("_p", "_x", "_power_cache")

    def __init__(self, prime: int = MERSENNE_61, base: int = 131) -> None:
        if base < 2 or base >= prime:
            raise ValueError(f"Base must be in [2, p-1], got {base}")
        self._p = prime
        self._x = base
        self._power_cache: dict[int, int] = {0: 1, 1: base}

    @property
    def prime(self) -> int:
        return self._p

    @property
    def base(self) -> int:
        return self._x

    def power(self, n: int) -> int:
        """
        Compute x^n mod p with caching.

        Uses Python's built-in pow(x, n, p) which implements
        binary exponentiation (Lemma 13).
        """
        if n in self._power_cache:
            return self._power_cache[n]
        result = pow(self._x, n, self._p)
        self._power_cache[n] = result
        return result

    def hash(self, data: bytes) -> int:
        """
        Compute H(data) = Σ (data[i] + 1) · x^(n-1-i) (mod p).

        For the empty string, returns 0 (Definition 2).

        Parameters
        ----------
        data : bytes
            The byte string to hash.

        Returns
        -------
        int
            Hash value in [0, p-1].
        """
        if len(data) == 0:
            return 0

        p = self._p
        x = self._x
        h = 0
        for byte in data:
            # h = h · x + (byte + 1)
            h = mersenne_mod(h * x + byte + 1, p)
        return h

    def hash_concat(self, h_a: int, len_b: int, h_b: int) -> int:
        """
        Compute H(A ‖ B) from H(A), |B|, H(B) via Theorem 1.

        H(A ‖ B) = H(A) · x^|B| + H(B) (mod p)
        """
        x_pow = self.power(len_b)
        return mersenne_mod(h_a * x_pow + h_b, self._p)

    def hash_repeat(self, h_s: int, d: int, q: int) -> int:
        """
        Compute H(S^q) from H(S) and |S| = d via Theorem 2.

        H(S^q) = H(S) · Φ(q, x^d) (mod p)
        """
        x_d = self.power(d)
        phi_val = phi(q, x_d, self._p)
        return mersenne_mul(h_s, phi_val, self._p)

    def hash_overlap(self, h_p: int, d: int, l: int, h_prefix: int) -> int:
        """
        Compute H(W) for overlapping back-reference via Theorem 5.

        W = P^q ‖ P[0..r-1] where q = ⌊l/d⌋, r = l mod d.

        H(W) = H(P) · Φ(q, x^d) · x^r + H(P[0..r-1]) (mod p)

        Parameters
        ----------
        h_p : int
            H(P), hash of the pattern of length d.
        d : int
            Pattern length.
        l : int
            Total back-reference length (d < l for overlapping).
        h_prefix : int
            H(P[0..r-1]) where r = l mod d. Pass 0 if r = 0.
        """
        q, r = divmod(l, d)
        x_d = self.power(d)
        x_r = self.power(r)

        # H(P) · Φ(q, x^d)
        phi_val = phi(q, x_d, self._p)
        h_repeated = mersenne_mul(h_p, phi_val, self._p)

        # · x^r + H(P[0..r-1])
        result = mersenne_mod(h_repeated * x_r + h_prefix, self._p)
        return result
