//! Compressed-domain LCP and comparison primitives (Theorems 25-26).
//!
//! CD-LCP: exact bytewise longest-common-prefix traversal over ropes.
//! O(L · log w) worst case, with no hash-equality decisions.
//!
//! CD-Compare: lexicographic comparison using CD-LCP + ByteAt for
//! the first differing byte.
//!
//! Polynomial hashes are intentionally not consulted: chosen collisions must
//! not affect LCP or ordering.

use crate::byte_at::byte_at_in_bounds;
use core::cmp::Ordering;
use hashrope::{Arena, Node};

/// Compute the exact LCP(A, B) via structural byte traversal.
///
/// # Returns
/// The length of the longest common prefix.
pub fn cd_lcp(arena: &Arena, a: Node, b: Node) -> u64 {
    let len_a = arena.len(a);
    let len_b = arena.len(b);
    let max_lcp = len_a.min(len_b);

    let mut offset = 0;
    while offset < max_lcp {
        if byte_at_in_bounds(arena, a, offset) != byte_at_in_bounds(arena, b, offset) {
            break;
        }
        offset += 1;
    }
    offset
}

/// Lexicographic comparison via CD-LCP + ByteAt (Theorem 26).
///
/// 1. Compute ℓ = CD-LCP(A, B).
/// 2. If ℓ = |A| = |B|, strings are equal.
/// 3. If ℓ = |A| < |B|, A is a proper prefix of B → A < B.
/// 4. If ℓ = |B| < |A|, B is a proper prefix of A → A > B.
/// 5. Otherwise, compare `A[ℓ]` vs `B[ℓ]` (the first differing byte).
pub fn cd_compare(arena: &Arena, a: Node, b: Node) -> Ordering {
    let len_a = arena.len(a);
    let len_b = arena.len(b);
    let lcp = cd_lcp(arena, a, b);

    if lcp == len_a && lcp == len_b {
        Ordering::Equal
    } else if lcp == len_a {
        Ordering::Less // A is proper prefix of B
    } else if lcp == len_b {
        Ordering::Greater // B is proper prefix of A
    } else {
        let byte_a = byte_at_in_bounds(arena, a, lcp);
        let byte_b = byte_at_in_bounds(arena, b, lcp);
        byte_a.cmp(&byte_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- CD-LCP tests ----

    #[test]
    fn test_lcp_identical() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"hello");
        let b = arena.from_bytes(b"hello");
        assert_eq!(cd_lcp(&arena, a, b), 5);
    }

    #[test]
    fn test_lcp_no_common_prefix() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"abc");
        let b = arena.from_bytes(b"xyz");
        assert_eq!(cd_lcp(&arena, a, b), 0);
    }

    #[test]
    fn test_lcp_partial() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"abcdef");
        let b = arena.from_bytes(b"abcxyz");
        assert_eq!(cd_lcp(&arena, a, b), 3);
    }

    #[test]
    fn test_lcp_prefix_relation() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"abc");
        let b = arena.from_bytes(b"abcdef");
        assert_eq!(cd_lcp(&arena, a, b), 3); // min(|A|,|B|)
    }

    #[test]
    fn test_lcp_empty_string() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"");
        let b = arena.from_bytes(b"hello");
        assert_eq!(cd_lcp(&arena, a, b), 0);
    }

    #[test]
    fn test_lcp_both_empty() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"");
        let b = arena.from_bytes(b"");
        assert_eq!(cd_lcp(&arena, a, b), 0);
    }

    #[test]
    fn test_lcp_single_byte_match() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"ax");
        let b = arena.from_bytes(b"ay");
        assert_eq!(cd_lcp(&arena, a, b), 1);
    }

    #[test]
    fn test_lcp_single_byte_no_match() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"x");
        let b = arena.from_bytes(b"y");
        assert_eq!(cd_lcp(&arena, a, b), 0);
    }

    #[test]
    fn test_lcp_with_concat_ropes() {
        let mut arena = Arena::new();
        // Build "abcdef" as "abc" + "def"
        let left = arena.from_bytes(b"abc");
        let right = arena.from_bytes(b"def");
        let a = arena.concat(left, right);
        // Build "abcxyz" as leaf
        let b = arena.from_bytes(b"abcxyz");
        assert_eq!(cd_lcp(&arena, a, b), 3);
    }

    #[test]
    fn test_lcp_with_repeat_ropes() {
        let mut arena = Arena::new();
        // "ababab" via repeat
        let pat = arena.from_bytes(b"ab");
        let a = arena.repeat(pat, 3);
        // "ababxy" as leaf
        let b = arena.from_bytes(b"ababxy");
        assert_eq!(cd_lcp(&arena, a, b), 4);
    }

    #[test]
    fn test_lcp_matches_brute_force() {
        // Property: cd_lcp matches brute-force byte-by-byte LCP
        let mut arena = Arena::new();
        let pairs: Vec<(&[u8], &[u8])> = vec![
            (b"", b""),
            (b"a", b""),
            (b"abc", b"abc"),
            (b"abc", b"abd"),
            (b"abc", b"abcdef"),
            (b"xyzxyz", b"xyzabc"),
            (b"aaaa", b"aaab"),
        ];
        for (sa, sb) in &pairs {
            let a = arena.from_bytes(sa);
            let b = arena.from_bytes(sb);
            let expected = brute_force_lcp(sa, sb);
            let got = cd_lcp(&arena, a, b);
            assert_eq!(got, expected, "LCP mismatch for {:?} vs {:?}", sa, sb);
        }
    }

    // ---- CD-Compare tests ----

    #[test]
    fn test_compare_equal() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"hello");
        let b = arena.from_bytes(b"hello");
        assert_eq!(cd_compare(&arena, a, b), Ordering::Equal);
    }

    #[test]
    fn test_compare_less() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"abc");
        let b = arena.from_bytes(b"abd");
        assert_eq!(cd_compare(&arena, a, b), Ordering::Less);
    }

    #[test]
    fn test_compare_greater() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"abd");
        let b = arena.from_bytes(b"abc");
        assert_eq!(cd_compare(&arena, a, b), Ordering::Greater);
    }

    #[test]
    fn test_compare_prefix_less() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"abc");
        let b = arena.from_bytes(b"abcdef");
        assert_eq!(cd_compare(&arena, a, b), Ordering::Less);
    }

    #[test]
    fn test_compare_prefix_greater() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"abcdef");
        let b = arena.from_bytes(b"abc");
        assert_eq!(cd_compare(&arena, a, b), Ordering::Greater);
    }

    #[test]
    fn test_compare_empty_vs_nonempty() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"");
        let b = arena.from_bytes(b"a");
        assert_eq!(cd_compare(&arena, a, b), Ordering::Less);
        assert_eq!(cd_compare(&arena, b, a), Ordering::Greater);
    }

    #[test]
    fn test_compare_both_empty() {
        let mut arena = Arena::new();
        let a = arena.from_bytes(b"");
        let b = arena.from_bytes(b"");
        assert_eq!(cd_compare(&arena, a, b), Ordering::Equal);
    }

    #[test]
    fn test_compare_matches_std_cmp() {
        // Property: cd_compare matches standard byte-slice comparison
        let mut arena = Arena::new();
        let strings: Vec<&[u8]> = vec![
            b"", b"a", b"b", b"aa", b"ab", b"ba", b"abc", b"abd", b"abcdef", b"xyz",
        ];
        for sa in &strings {
            for sb in &strings {
                let a = arena.from_bytes(sa);
                let b = arena.from_bytes(sb);
                let expected = sa.cmp(sb);
                let got = cd_compare(&arena, a, b);
                assert_eq!(
                    got, expected,
                    "Compare mismatch for {:?} vs {:?}: got {:?}, expected {:?}",
                    sa, sb, got, expected
                );
            }
        }
    }

    #[test]
    fn test_compare_with_complex_ropes() {
        let mut arena = Arena::new();
        // Build "ababab" via repeat, "ababac" via concat
        let pat = arena.from_bytes(b"ab");
        let a = arena.repeat(pat, 3); // "ababab"
        let prefix = arena.from_bytes(b"abab");
        let suffix = arena.from_bytes(b"ac");
        let b = arena.concat(prefix, suffix); // "ababac"
                                              // "ababab" vs "ababac": LCP=4, then 'a' < 'a'... wait, position 4: 'a' vs 'a', position 5: 'b' vs 'c'
                                              // Actually: "ababab"[4]='a', "ababac"[4]='a', "ababab"[5]='b', "ababac"[5]='c'
                                              // LCP = 5, then 'b' < 'c' → Less
        assert_eq!(cd_compare(&arena, a, b), Ordering::Less);
    }

    #[test]
    fn test_known_hash_collision_is_compared_exactly() {
        // Audit repro: ordering must be exact for this adversarial pair,
        // regardless of the configured hash implementation.
        let mut arena = Arena::new();
        let left_bytes = [0u8, 131, 255];
        let right_bytes = [1u8, 0, 0];
        let left = arena.from_bytes(&left_bytes);
        let right = arena.from_bytes(&right_bytes);

        assert_eq!(cd_lcp(&arena, left, right), 0);
        assert_eq!(cd_compare(&arena, left, right), Ordering::Less);

        // Under hashrope 0.2's byte+1/base-131 polynomial, this nearby pair
        // is an actual collision. Exact traversal still distinguishes it.
        let collision_left = arena.from_bytes(&[0u8, 131, 0]);
        let collision_right = arena.from_bytes(&right_bytes);
        assert_eq!(
            arena.substr_hash(collision_left, 0, 3),
            arena.substr_hash(collision_right, 0, 3),
        );
        assert_eq!(cd_lcp(&arena, collision_left, collision_right), 0);
        assert_eq!(
            cd_compare(&arena, collision_left, collision_right),
            Ordering::Less
        );
    }

    // ---- Helper ----

    #[test]
    fn test_composability_with_cd_radix() {
        // Verify that cd_compare (&mut Arena) and cd_radix_sort (&Arena)
        // can operate on the same arena. This tests that the &mut/& signature
        // difference doesn't prevent integration (Rust auto-coerces &mut T → &T).
        use crate::sort::cd_radix::cd_radix_sort;

        let mut arena = Arena::new();
        let data: Vec<&[u8]> = vec![b"cherry", b"apple", b"banana"];
        let strings: Vec<(Node, usize)> = data
            .iter()
            .enumerate()
            .map(|(i, bytes)| (arena.from_bytes(bytes), i))
            .collect();

        // cd_radix_sort takes &Arena
        let radix_perm = cd_radix_sort(&arena, &strings);

        // cd_compare takes &mut Arena — same arena, after radix sort
        let cmp_01 = cd_compare(&arena, strings[radix_perm[0]].0, strings[radix_perm[1]].0);
        let cmp_12 = cd_compare(&arena, strings[radix_perm[1]].0, strings[radix_perm[2]].0);

        // Sorted order should be apple < banana < cherry
        assert_eq!(cmp_01, Ordering::Less);
        assert_eq!(cmp_12, Ordering::Less);
    }

    fn brute_force_lcp(a: &[u8], b: &[u8]) -> u64 {
        let mut i = 0;
        while i < a.len() && i < b.len() && a[i] == b[i] {
            i += 1;
        }
        i as u64
    }
}
