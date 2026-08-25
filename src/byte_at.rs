//! ByteAt: extract the byte at a given position via structural traversal (Theorem 32).
//!
//! O(log t) time, no hash computation needed. This is the key primitive
//! that enables CD-Radix sort to operate with ZERO polynomial hash evaluations.

use hashrope::{Arena, Node, NodeInner};
use std::error::Error;
use std::fmt;

/// Recoverable violations of the public rope access contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RopeAccessError {
    EmptyRope,
    InvalidNode {
        node_id: u32,
        node_count: usize,
    },
    PositionOutOfBounds {
        pos: u64,
        len: u64,
    },
    RangeOutOfBounds {
        start: u64,
        length: u64,
        len: u64,
    },
    RangeOverflow {
        start: u64,
        length: u64,
    },
    HasherMismatch {
        expected_prime: u64,
        expected_base: u64,
        actual_prime: u64,
        actual_base: u64,
    },
}

impl fmt::Display for RopeAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRope => write!(f, "cannot access a byte in an empty rope"),
            Self::InvalidNode {
                node_id,
                node_count,
            } => write!(
                f,
                "rope node id {node_id} is outside arena node count {node_count}"
            ),
            Self::PositionOutOfBounds { pos, len } => {
                write!(f, "rope byte position {pos} is outside [0, {len})")
            }
            Self::RangeOutOfBounds { start, length, len } => write!(
                f,
                "rope range [{start}, {start}+{length}) is outside [0, {len})"
            ),
            Self::RangeOverflow { start, length } => write!(
                f,
                "rope range start {start} plus length {length} overflows u64"
            ),
            Self::HasherMismatch {
                expected_prime,
                expected_base,
                actual_prime,
                actual_base,
            } => write!(
                f,
                "rope hasher mismatch: expected prime={expected_prime}, base={expected_base}; \
                 arena uses prime={actual_prime}, base={actual_base}"
            ),
        }
    }
}

impl Error for RopeAccessError {}

fn checked_node(arena: &Arena, node: Node) -> Result<u32, RopeAccessError> {
    let id = node.ok_or(RopeAccessError::EmptyRope)?;
    if id as usize >= arena.node_count() {
        return Err(RopeAccessError::InvalidNode {
            node_id: id,
            node_count: arena.node_count(),
        });
    }
    Ok(id)
}

/// Return the byte at position `pos` in the string represented by `node`.
///
/// Navigates the rope tree structurally — no hash computation is performed.
/// RepeatNodes are folded via `pos % child_len`.
///
/// Returns a structured error for an empty rope, a foreign/invalid node id,
/// or an out-of-bounds position.
pub fn byte_at(arena: &Arena, node: Node, pos: u64) -> Result<u8, RopeAccessError> {
    let mut id = checked_node(arena, node)?;
    let len = arena.len(Some(id));
    if pos >= len {
        return Err(RopeAccessError::PositionOutOfBounds { pos, len });
    }
    let mut pos = pos;

    loop {
        match arena.node(id) {
            NodeInner::Leaf { data, .. } => {
                return Ok(data[pos as usize]);
            }
            NodeInner::Internal { left, right, .. } => {
                let left_len = arena.len(Some(*left));
                if pos < left_len {
                    id = *left;
                } else {
                    pos -= left_len;
                    id = *right;
                }
            }
            NodeInner::Repeat { child, .. } => {
                let child_len = arena.len(Some(*child));
                pos %= child_len;
                id = *child;
            }
        }
    }
}

/// Validate a half-open rope range before calling an upstream range operation.
pub fn validate_range(
    arena: &Arena,
    node: Node,
    start: u64,
    length: u64,
) -> Result<(), RopeAccessError> {
    let len = match node {
        None => 0,
        Some(_) => {
            let id = checked_node(arena, node)?;
            arena.len(Some(id))
        }
    };
    let end = start
        .checked_add(length)
        .ok_or(RopeAccessError::RangeOverflow { start, length })?;
    if start > len || end > len {
        return Err(RopeAccessError::RangeOutOfBounds { start, length, len });
    }
    Ok(())
}

/// Compute a substring hash only after enforcing the public range contract.
pub fn substr_hash_checked(
    arena: &mut Arena,
    node: Node,
    start: u64,
    length: u64,
) -> Result<u64, RopeAccessError> {
    validate_range(arena, node, start, length)?;
    Ok(arena.substr_hash(node, start, length))
}

/// Split only at a position in the closed range `[0, len]`.
pub fn split_checked(
    arena: &mut Arena,
    node: Node,
    pos: u64,
) -> Result<(Node, Node), RopeAccessError> {
    validate_range(arena, node, pos, 0)?;
    Ok(arena.split(node, pos))
}

/// Confirm that an arena uses the hash parameters required by its caller.
pub fn validate_hasher(
    arena: &Arena,
    expected_prime: u64,
    expected_base: u64,
) -> Result<(), RopeAccessError> {
    let actual_prime = arena.hasher().prime();
    let actual_base = arena.hasher().base();
    if actual_prime != expected_prime || actual_base != expected_base {
        return Err(RopeAccessError::HasherMismatch {
            expected_prime,
            expected_base,
            actual_prime,
            actual_base,
        });
    }
    Ok(())
}

/// Internal fast path for algorithms that have already checked `pos < len`.
pub(crate) fn byte_at_in_bounds(arena: &Arena, node: Node, pos: u64) -> u8 {
    byte_at(arena, node, pos).expect("internal rope position must be in bounds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_at_leaf() {
        let mut arena = Arena::new();
        let node = arena.from_bytes(b"hello");
        assert_eq!(byte_at(&arena, node, 0).unwrap(), b'h');
        assert_eq!(byte_at(&arena, node, 4).unwrap(), b'o');
    }

    #[test]
    fn test_byte_at_concat() {
        let mut arena = Arena::new();
        let left = arena.from_bytes(b"hel");
        let right = arena.from_bytes(b"lo");
        let node = arena.concat(left, right);
        for (i, &expected) in b"hello".iter().enumerate() {
            assert_eq!(byte_at(&arena, node, i as u64).unwrap(), expected);
        }
    }

    #[test]
    fn test_byte_at_repeat() {
        let mut arena = Arena::new();
        let child = arena.from_bytes(b"abc");
        let node = arena.repeat(child, 4); // "abcabcabcabc"
        let expected = b"abcabcabcabc";
        for (i, &exp) in expected.iter().enumerate() {
            assert_eq!(
                byte_at(&arena, node, i as u64).unwrap(),
                exp,
                "mismatch at pos {i}"
            );
        }
    }

    #[test]
    fn test_byte_at_complex_tree() {
        let mut arena = Arena::new();
        // Build: "abc" repeated 3x = "abcabcabc", then concat "XY"
        let pat = arena.from_bytes(b"abc");
        let rep = arena.repeat(pat, 3);
        let suffix = arena.from_bytes(b"XY");
        let node = arena.concat(rep, suffix);
        let expected = b"abcabcabcXY";
        for (i, &exp) in expected.iter().enumerate() {
            assert_eq!(
                byte_at(&arena, node, i as u64).unwrap(),
                exp,
                "mismatch at pos {i}"
            );
        }
    }

    #[test]
    fn test_byte_at_matches_to_bytes() {
        // Property: byte_at at every position matches to_bytes
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"foo");
        let b = arena.from_bytes(b"bar");
        let c = arena.from_bytes(b"baz");
        let ab = arena.concat(a, b);
        let abc = arena.concat(ab, c);
        let rep = arena.repeat(abc, 5);

        let materialized = arena.to_bytes(rep);
        for (i, &expected) in materialized.iter().enumerate() {
            assert_eq!(
                byte_at(&arena, rep, i as u64).unwrap(),
                expected,
                "mismatch at pos {i}"
            );
        }
    }

    #[test]
    fn test_byte_at_rejects_empty_invalid_and_out_of_bounds() {
        let mut arena = Arena::new();
        let node = arena.from_bytes(b"abc");
        assert_eq!(byte_at(&arena, None, 0), Err(RopeAccessError::EmptyRope));
        assert_eq!(
            byte_at(&arena, node, 3),
            Err(RopeAccessError::PositionOutOfBounds { pos: 3, len: 3 })
        );
        assert_eq!(
            byte_at(&arena, Some(99), 0),
            Err(RopeAccessError::InvalidNode {
                node_id: 99,
                node_count: 1
            })
        );
    }

    #[test]
    fn test_checked_range_split_and_substr_hash_contracts() {
        let mut arena = Arena::new();
        let node = arena.from_bytes(b"abcdef");
        assert!(validate_range(&arena, node, 6, 0).is_ok());
        assert!(matches!(
            validate_range(&arena, node, 5, 2),
            Err(RopeAccessError::RangeOutOfBounds { .. })
        ));
        assert!(matches!(
            validate_range(&arena, node, u64::MAX, 1),
            Err(RopeAccessError::RangeOverflow { .. })
        ));

        let expected = arena.hash_bytes(b"bcd");
        assert_eq!(
            substr_hash_checked(&mut arena, node, 1, 3).unwrap(),
            expected
        );
        let (left, right) = split_checked(&mut arena, node, 2).unwrap();
        assert_eq!(arena.to_bytes(left), b"ab");
        assert_eq!(arena.to_bytes(right), b"cdef");
    }

    #[test]
    fn test_validate_hasher_reports_mismatch() {
        let arena = Arena::with_hash(2_305_843_009_213_693_951, 257);
        assert!(validate_hasher(&arena, 2_305_843_009_213_693_951, 257).is_ok());
        assert!(matches!(
            validate_hasher(&arena, 2_305_843_009_213_693_951, 131),
            Err(RopeAccessError::HasherMismatch { .. })
        ));
    }
}
