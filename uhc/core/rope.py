"""
Hash rope data structure for compressed-domain hashing.

Implements Part III of the framework:
- Definition 6: Leaf, Internal, RepeatNode
- Definition 7: Invariants I1-I9 (BB[2/7] weight balance)
- Lemma 4: Hash correctness (structural induction)
- Lemma 5: Height bound O(log w)
- Lemma 6: Rotations preserve hash invariant
- Lemma 7: RepeatNode splittability
- Lemma 8: Join complexity O(k · |h_L - h_R|)
- Lemma 8': RepeatNode bisection for rebalancing
- Theorem 6: Join (full specification)
- Theorem 7: Split in O(k · log w)
- Theorem 8: Repeat via RepeatNode in O(k · log q), O(1) space
- Theorem 9: Allocation-free SubstrHash in O(k · log w)
- Theorem 10: Concat = Join

All nodes are immutable (Invariant I9). Operations return new trees
with structural sharing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from uhc.core.polynomial_hash import (
    PolynomialHash,
    phi,
    mersenne_mod,
    mersenne_mul,
    MERSENNE_61,
)

# ---------------------------------------------------------------------------
# Balance parameter (Definition 7, Invariant I8)
# ---------------------------------------------------------------------------

# BB[α] with α = 2/7 (Nievergelt-Reingold condition).
# A node is balanced if each child's weight is at least α * parent weight.
ALPHA_NUM = 2
ALPHA_DEN = 7

# Type alias
Node = Optional["Leaf | Internal | RepeatNode"]


# ---------------------------------------------------------------------------
# Definition 6: Node types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Leaf:
    """
    Leaf node storing a byte sequence (Definition 6a).

    Invariant I1: hash_val = H(data).
    Weight is always 1.
    """

    data: bytes
    hash_val: int
    len: int
    weight: int

    def __init__(self, data: bytes, h: PolynomialHash) -> None:
        if len(data) == 0:
            raise ValueError("Leaf cannot be empty")
        object.__setattr__(self, "data", bytes(data))
        object.__setattr__(self, "len", len(data))
        object.__setattr__(self, "hash_val", h.hash(data))
        object.__setattr__(self, "weight", 1)


@dataclass(frozen=True, slots=True)
class Internal:
    """
    Internal node joining two subtrees (Definition 6b).

    Invariant I2: len = left.len + right.len
    Invariant I3: hash_val = left.hash_val · x^(right.len) + right.hash_val
    Invariant I4: weight = left.weight + right.weight
    """

    left: Leaf | Internal | RepeatNode
    right: Leaf | Internal | RepeatNode
    hash_val: int
    len: int
    weight: int

    def __init__(
        self,
        left: Leaf | Internal | RepeatNode,
        right: Leaf | Internal | RepeatNode,
        h: PolynomialHash,
    ) -> None:
        object.__setattr__(self, "left", left)
        object.__setattr__(self, "right", right)
        object.__setattr__(self, "len", left.len + right.len)
        object.__setattr__(self, "weight", left.weight + right.weight)
        # I3: hash = left.hash · x^(right.len) + right.hash
        hv = h.hash_concat(left.hash_val, right.len, right.hash_val)
        object.__setattr__(self, "hash_val", hv)


@dataclass(frozen=True, slots=True)
class RepeatNode:
    """
    Repeat node representing child^reps (Definition 6c).

    Invariant I5: len = child.len * reps
    Invariant I6: hash_val = child.hash_val · Φ(reps, x^(child.len))
    Invariant I7: weight = child.weight * reps
    """

    child: Leaf | Internal | RepeatNode
    reps: int
    hash_val: int
    len: int
    weight: int

    def __init__(
        self,
        child: Leaf | Internal | RepeatNode,
        reps: int,
        h: PolynomialHash,
    ) -> None:
        if reps < 2:
            raise ValueError(f"RepeatNode reps must be >= 2, got {reps}")
        object.__setattr__(self, "child", child)
        object.__setattr__(self, "reps", reps)
        object.__setattr__(self, "len", child.len * reps)
        object.__setattr__(self, "weight", child.weight * reps)
        # I6: hash = child.hash · Φ(reps, x^d)
        x_d = h.power(child.len)
        phi_val = phi(reps, x_d, h.prime)
        hv = mersenne_mul(child.hash_val, phi_val, h.prime)
        object.__setattr__(self, "hash_val", hv)


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------


def rope_len(node: Node) -> int:
    """Total byte length of the string represented by node."""
    return 0 if node is None else node.len


def rope_hash(node: Node) -> int:
    """Hash of the string represented by node."""
    return 0 if node is None else node.hash_val


def _weight(node: Node) -> int:
    return 0 if node is None else node.weight


def _height(node: Node) -> int:
    """Approximate height for join decisions."""
    if node is None:
        return 0
    if isinstance(node, Leaf):
        return 1
    if isinstance(node, RepeatNode):
        return _height(node.child) + 1
    # Internal
    return 1 + max(_height(node.left), _height(node.right))


# ---------------------------------------------------------------------------
# Balance helpers (Invariant I8)
# ---------------------------------------------------------------------------


def _is_balanced(left: Node, right: Node) -> bool:
    """Check BB[2/7] condition for a potential Internal(left, right)."""
    total = _weight(left) + _weight(right)
    if total <= 2:
        return True
    wl = _weight(left)
    # α ≤ wl/total ≤ 1-α  ⟺  α·total ≤ wl ≤ (1-α)·total
    # With α = 2/7: 2·total ≤ 7·wl and 7·wl ≤ 5·total
    return ALPHA_NUM * total <= ALPHA_DEN * wl <= (ALPHA_DEN - ALPHA_NUM) * total


def _rotate_right(node: Internal, h: PolynomialHash) -> Leaf | Internal | RepeatNode:
    """Right rotation: Internal(Internal(A, B), C) → Internal(A, Internal(B, C))."""
    u = node.left
    if not isinstance(u, Internal):
        return node  # can't rotate
    a, b, c = u.left, u.right, node.right
    new_right = Internal(b, c, h)
    return Internal(a, new_right, h)


def _rotate_left(node: Internal, h: PolynomialHash) -> Leaf | Internal | RepeatNode:
    """Left rotation: Internal(A, Internal(B, C)) → Internal(Internal(A, B), C)."""
    u = node.right
    if not isinstance(u, Internal):
        return node
    a, b, c = node.left, u.left, u.right
    new_left = Internal(a, b, h)
    return Internal(new_left, c, h)


def _rebalance(left: Leaf | Internal | RepeatNode,
               right: Leaf | Internal | RepeatNode,
               h: PolynomialHash) -> Leaf | Internal | RepeatNode:
    """
    Create a balanced Internal node from left and right.
    Applies single or double rotations as needed (Lemma 6).
    """
    node = Internal(left, right, h)
    wl, wr = _weight(left), _weight(right)
    total = wl + wr

    if total <= 2 or _is_balanced(left, right):
        return node

    if wl * ALPHA_DEN < ALPHA_NUM * total:
        # Left too light → rotate left
        if isinstance(right, Internal):
            # Check if double rotation needed
            if _weight(right.left) * ALPHA_DEN > (ALPHA_DEN - ALPHA_NUM) * wr:
                # Double: rotate right child right, then rotate left
                new_right = _rotate_right(right, h)
                node = Internal(left, new_right, h)
            return _rotate_left(node, h)
        return node

    if wr * ALPHA_DEN < ALPHA_NUM * total:
        # Right too light → rotate right
        if isinstance(left, Internal):
            if _weight(left.right) * ALPHA_DEN > (ALPHA_DEN - ALPHA_NUM) * wl:
                new_left = _rotate_left(left, h)
                node = Internal(new_left, right, h)
            return _rotate_right(node, h)
        return node

    return node


# ---------------------------------------------------------------------------
# Theorem 6 / Lemma 8: Join (Concat)
# ---------------------------------------------------------------------------


def rope_concat(
    left: Node, right: Node, h: PolynomialHash
) -> Node:
    """
    Join two ropes (Theorem 6, Theorem 10).

    Returns a valid hash rope representing left's string ‖ right's string.
    Time: O(k · |h_L - h_R|).
    """
    if left is None:
        return right
    if right is None:
        return left
    return _join(left, right, h)


def _join(
    left: Leaf | Internal | RepeatNode,
    right: Leaf | Internal | RepeatNode,
    h: PolynomialHash,
) -> Leaf | Internal | RepeatNode:
    """Core join with rebalancing."""
    if _is_balanced(left, right):
        return Internal(left, right, h)

    wl, wr = _weight(left), _weight(right)

    if wl > wr:
        # Left is heavier — descend right spine of left
        if isinstance(left, Internal):
            new_right = _join(left.right, right, h)
            return _rebalance(left.left, new_right, h)
        elif isinstance(left, RepeatNode):
            # Split the repeat node in half, join right half with right
            mid = left.len // 2
            ll, lr = rope_split(left, mid, h)
            new_right = _join(lr, right, h)
            return _join(ll, new_right, h)
        else:
            # Leaf — just make Internal
            return Internal(left, right, h)
    else:
        # Right is heavier — descend left spine of right
        if isinstance(right, Internal):
            new_left = _join(left, right.left, h)
            return _rebalance(new_left, right.right, h)
        elif isinstance(right, RepeatNode):
            mid = right.len // 2
            rl, rr = rope_split(right, mid, h)
            new_left = _join(left, rl, h)
            return _join(new_left, rr, h)
        else:
            return Internal(left, right, h)


# ---------------------------------------------------------------------------
# Theorem 7: Split
# ---------------------------------------------------------------------------


def rope_split(
    node: Node, pos: int, h: PolynomialHash
) -> tuple[Node, Node]:
    """
    Split rope at byte position pos (Theorem 7).

    Returns (left, right) where left has pos bytes, right has the rest.
    Time: O(k · log w).
    """
    if node is None:
        return None, None
    if pos <= 0:
        return None, node
    if pos >= node.len:
        return node, None
    return _split(node, pos, h)


def _split(
    node: Leaf | Internal | RepeatNode,
    pos: int,
    h: PolynomialHash,
) -> tuple[Node, Node]:
    """Core split. 0 < pos < node.len guaranteed."""

    if isinstance(node, Leaf):
        left = Leaf(node.data[:pos], h)
        right = Leaf(node.data[pos:], h)
        return left, right

    if isinstance(node, Internal):
        ll = node.left.len
        if pos == ll:
            return node.left, node.right
        if pos < ll:
            l1, l2 = _split(node.left, pos, h)
            return l1, rope_concat(l2, node.right, h)
        else:
            r1, r2 = _split(node.right, pos - ll, h)
            return rope_concat(node.left, r1, h), r2

    if isinstance(node, RepeatNode):
        return _split_repeat(node, pos, h)

    raise TypeError(f"Unknown node type: {type(node)}")


def _split_repeat(
    node: RepeatNode, pos: int, h: PolynomialHash
) -> tuple[Node, Node]:
    """
    Split a RepeatNode at byte position pos (Lemma 7).

    Let d = child.len, m = pos // d, r = pos % d.
    """
    d = node.child.len
    m, r = divmod(pos, d)
    q = node.reps

    if r == 0:
        # Split falls on repetition boundary
        left = _make_repeat(node.child, m, h)
        right = _make_repeat(node.child, q - m, h)
        return left, right
    else:
        # Split falls within a repetition
        child_left, child_right = _split(node.child, r, h)

        # Left = Repeat(child, m) ‖ child_left
        left_rep = _make_repeat(node.child, m, h)
        left = rope_concat(left_rep, child_left, h)

        # Right = child_right ‖ Repeat(child, q - m - 1)
        right_rep = _make_repeat(node.child, q - m - 1, h)
        right = rope_concat(child_right, right_rep, h)

        return left, right


def _make_repeat(
    child: Leaf | Internal | RepeatNode, reps: int, h: PolynomialHash
) -> Node:
    """Create a Repeat with proper handling of reps 0 and 1."""
    if reps == 0:
        return None
    if reps == 1:
        return child
    return RepeatNode(child, reps, h)


# ---------------------------------------------------------------------------
# Theorem 8: Repeat
# ---------------------------------------------------------------------------


def rope_repeat(
    node: Leaf | Internal | RepeatNode,
    q: int,
    h: PolynomialHash,
) -> Node:
    """
    Create a RepeatNode representing node^q (Theorem 8).

    Time: O(k · log q) for the Φ computation. O(1) new nodes.
    """
    if q == 0:
        return None
    if q == 1:
        return node
    return RepeatNode(node, q, h)


# ---------------------------------------------------------------------------
# Theorem 9: SubstrHash (allocation-free)
# ---------------------------------------------------------------------------


def rope_substr_hash(
    node: Node,
    start: int,
    length: int,
    h: PolynomialHash,
) -> int:
    """
    Compute H(S[start..start+length-1]) without allocating nodes (Theorem 9).

    Time: O(k · log w). Space: O(log w) stack.
    """
    if node is None or length == 0:
        return 0
    return _hash_range(node, start, length, h)


def _hash_range(
    node: Leaf | Internal | RepeatNode,
    start: int,
    length: int,
    h: PolynomialHash,
) -> int:
    """Recursive hash range query."""
    p = h.prime

    if isinstance(node, Leaf):
        return h.hash(node.data[start:start + length])

    if isinstance(node, Internal):
        ll = node.left.len
        if start + length <= ll:
            # Entirely in left
            return _hash_range(node.left, start, length, h)
        if start >= ll:
            # Entirely in right
            return _hash_range(node.right, start - ll, length, h)
        # Spanning
        l_len = ll - start
        r_len = length - l_len
        h_l = _hash_range(node.left, start, l_len, h)
        h_r = _hash_range(node.right, 0, r_len, h)
        return h.hash_concat(h_l, r_len, h_r)

    if isinstance(node, RepeatNode):
        d = node.child.len
        # Map into the repeating pattern
        first_copy = start // d
        start_in_copy = start % d

        end = start + length - 1
        last_copy = end // d
        end_in_copy = end % d

        if first_copy == last_copy:
            # Entirely within one copy
            return _hash_range(node.child, start_in_copy, length, h)

        # Three parts: tail of first copy, full copies, head of last copy
        # 1. Tail of first copy: child[start_in_copy .. d-1]
        tail_len = d - start_in_copy
        h_tail = _hash_range(node.child, start_in_copy, tail_len, h)

        # 2. Full copies in the middle
        full_copies = last_copy - first_copy - 1
        if full_copies > 0:
            x_d = h.power(d)
            phi_val = phi(full_copies, x_d, p)
            h_full = mersenne_mul(node.child.hash_val, phi_val, p)
        else:
            h_full = 0
        full_len = full_copies * d

        # 3. Head of last copy: child[0 .. end_in_copy]
        head_len = end_in_copy + 1
        h_head = _hash_range(node.child, 0, head_len, h)

        # Combine: tail ‖ full ‖ head
        # H(tail ‖ full ‖ head) = H(tail) · x^(full_len + head_len) + H(full) · x^(head_len) + H(head)
        result = mersenne_mod(
            h.power(full_len + head_len) * h_tail
            + h.power(head_len) * h_full
            + h_head,
            p,
        )
        return result

    raise TypeError(f"Unknown node type: {type(node)}")


# ---------------------------------------------------------------------------
# Reconstruction: rope → bytes
# ---------------------------------------------------------------------------


def rope_to_bytes(node: Node) -> bytes:
    """Reconstruct the byte string from a rope (for testing)."""
    if node is None:
        return b""
    parts: list[bytes] = []
    _collect_bytes(node, parts)
    return b"".join(parts)


def _collect_bytes(node: Leaf | Internal | RepeatNode, parts: list[bytes]) -> None:
    if isinstance(node, Leaf):
        parts.append(node.data)
    elif isinstance(node, Internal):
        _collect_bytes(node.left, parts)
        _collect_bytes(node.right, parts)
    elif isinstance(node, RepeatNode):
        for _ in range(node.reps):
            _collect_bytes(node.child, parts)


# ---------------------------------------------------------------------------
# Construction helper
# ---------------------------------------------------------------------------


def rope_from_bytes(data: bytes, h: PolynomialHash) -> Node:
    """Create a rope from a byte string. Returns None for empty."""
    if len(data) == 0:
        return None
    return Leaf(data, h)


# ---------------------------------------------------------------------------
# Validation (for testing)
# ---------------------------------------------------------------------------


def validate_rope(node: Node, h: PolynomialHash | None = None) -> None:
    """
    Validate all rope invariants (Definition 7). Raises AssertionError on violation.
    """
    if node is None:
        return

    if isinstance(node, Leaf):
        assert node.weight == 1, f"Leaf weight must be 1, got {node.weight}"
        assert node.len == len(node.data), "Leaf len mismatch"
        return

    if isinstance(node, Internal):
        # I2
        assert node.len == node.left.len + node.right.len, "Internal len mismatch"
        # I4
        assert node.weight == node.left.weight + node.right.weight, "Internal weight mismatch"
        # I8: balance
        total = node.weight
        wl = node.left.weight
        if total > 2:
            assert ALPHA_NUM * total <= ALPHA_DEN * wl, (
                f"Left child too light: {wl}/{total}"
            )
            assert ALPHA_DEN * wl <= (ALPHA_DEN - ALPHA_NUM) * total, (
                f"Left child too heavy: {wl}/{total}"
            )
        # Recurse
        validate_rope(node.left, h)
        validate_rope(node.right, h)
        return

    if isinstance(node, RepeatNode):
        # I5
        assert node.len == node.child.len * node.reps, "RepeatNode len mismatch"
        # I7
        assert node.weight == node.child.weight * node.reps, "RepeatNode weight mismatch"
        assert node.reps >= 2, f"RepeatNode reps must be >= 2, got {node.reps}"
        validate_rope(node.child, h)
        return

    raise TypeError(f"Unknown node type: {type(node)}")
