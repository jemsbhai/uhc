//! CD-Mergesort: stable mergesort using CD-Compare (Theorems 27-28).
//!
//! Sorts compressed strings by lexicographic order without decompression.
//! Uses `cd_compare` (Theorem 26) as the comparison operator within a
//! standard bottom-up mergesort.
//!
//! `cd_compare` traverses bytes exactly; polynomial-hash collisions do not
//! affect ordering.
//!
//! Complexity (Theorem 28):
//!   Time:  O(n · log n · k · log w · log L)
//!   Space: O(n) auxiliary for merge buffer
//!
//! Stability: Yes — equal elements preserve their original order.
//!
//! **Design note:** Takes `&Arena`; exact comparison performs structural byte
//! traversal and does not mutate a hash power cache.
//!
//! **Future optimization (Theorem 35):** LCP-aware mergesort tracks LCP
//! values between elements and the merge frontier, skipping known-equal
//! prefixes via CD-LCP-From (Theorem 33). This reduces per-comparison
//! cost from O(k · log w · log L) to O(k · log w · log(L − start)).
//! The current implementation does not yet include this optimization.

use crate::sort::cd_lcp::cd_compare;
use core::cmp::Ordering;
use hashrope::{Arena, Node};

/// Sort string indices by lexicographic order using bottom-up mergesort
/// with CD-Compare.
///
/// # Arguments
/// * `arena` - The rope arena
/// * `strings` - Slice of (Node, original_index) pairs
///
/// # Returns
/// An exact lexicographically sorted permutation.
pub fn cd_merge_sort(arena: &Arena, strings: &[(Node, usize)]) -> Vec<usize> {
    let n = strings.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![strings[0].1];
    }

    // Working array of indices into `strings`
    let mut indices: Vec<usize> = (0..n).collect();
    let mut buffer: Vec<usize> = vec![0; n];

    // Bottom-up mergesort: merge runs of width 1, 2, 4, ...
    let mut width = 1;
    while width < n {
        let mut i = 0;
        while i < n {
            let left_start = i;
            let mid = (i + width).min(n);
            let right_end = (i + 2 * width).min(n);

            merge(
                arena,
                strings,
                &indices,
                &mut buffer,
                left_start,
                mid,
                right_end,
            );
            i += 2 * width;
        }
        // Copy buffer back to indices
        indices.copy_from_slice(&buffer[..n]);
        width *= 2;
    }

    indices.iter().map(|&i| strings[i].1).collect()
}

/// Merge two sorted runs: indices[left..mid] and indices[mid..right]
/// into buffer[left..right].
fn merge(
    arena: &Arena,
    strings: &[(Node, usize)],
    indices: &[usize],
    buffer: &mut [usize],
    left_start: usize,
    mid: usize,
    right_end: usize,
) {
    let mut l = left_start;
    let mut r = mid;
    let mut out = left_start;

    while l < mid && r < right_end {
        let node_l = strings[indices[l]].0;
        let node_r = strings[indices[r]].0;
        let cmp = cd_compare(arena, node_l, node_r);
        // Stable: take left on Equal
        if cmp == Ordering::Less || cmp == Ordering::Equal {
            buffer[out] = indices[l];
            l += 1;
        } else {
            buffer[out] = indices[r];
            r += 1;
        }
        out += 1;
    }
    // Copy remaining
    while l < mid {
        buffer[out] = indices[l];
        l += 1;
        out += 1;
    }
    while r < right_end {
        buffer[out] = indices[r];
        r += 1;
        out += 1;
    }
}

/// Convenience: sort byte slices via CD-Mergesort.
pub fn sort_byte_slices(data: &[&[u8]]) -> Vec<usize> {
    let mut arena = Arena::new();
    let strings: Vec<(Node, usize)> = data
        .iter()
        .enumerate()
        .map(|(i, bytes)| (arena.from_bytes(bytes), i))
        .collect();
    cd_merge_sort(&arena, &strings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_perm<'a>(data: &[&'a [u8]], perm: &[usize]) -> Vec<&'a [u8]> {
        perm.iter().map(|&i| data[i]).collect()
    }

    #[test]
    fn test_empty() {
        let perm = sort_byte_slices(&[]);
        assert!(perm.is_empty());
    }

    #[test]
    fn test_single() {
        let perm = sort_byte_slices(&[b"hello"]);
        assert_eq!(perm, vec![0]);
    }

    #[test]
    fn test_two_elements() {
        let data: Vec<&[u8]> = vec![b"banana", b"apple"];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        assert_eq!(sorted, vec![&b"apple"[..], &b"banana"[..]]);
    }

    #[test]
    fn test_already_sorted() {
        let data: Vec<&[u8]> = vec![b"apple", b"banana", b"cherry"];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        assert_eq!(sorted, vec![&b"apple"[..], &b"banana"[..], &b"cherry"[..]]);
    }

    #[test]
    fn test_reverse_sorted() {
        let data: Vec<&[u8]> = vec![b"cherry", b"banana", b"apple"];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        assert_eq!(sorted, vec![&b"apple"[..], &b"banana"[..], &b"cherry"[..]]);
    }

    #[test]
    fn test_prefix_ordering() {
        let data: Vec<&[u8]> = vec![b"abd", b"b", b"ab", b"abc"];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        assert_eq!(
            sorted,
            vec![&b"ab"[..], &b"abc"[..], &b"abd"[..], &b"b"[..]]
        );
    }

    #[test]
    fn test_duplicates() {
        let data: Vec<&[u8]> = vec![b"bb", b"aa", b"bb", b"aa"];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        assert_eq!(sorted, vec![&b"aa"[..], &b"aa"[..], &b"bb"[..], &b"bb"[..]]);
    }

    #[test]
    fn test_empty_strings() {
        let data: Vec<&[u8]> = vec![b"b", b"", b"a", b""];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        assert_eq!(sorted, vec![&b""[..], &b""[..], &b"a"[..], &b"b"[..]]);
    }

    #[test]
    fn test_stability() {
        // Mergesort must be stable: equal elements preserve original order.
        // "aa" appears at indices 1 and 3. In sorted output, index 1 should
        // precede index 3.
        let data: Vec<&[u8]> = vec![b"bb", b"aa", b"cc", b"aa"];
        let perm = sort_byte_slices(&data);
        // Sorted: aa(1), aa(3), bb(0), cc(2)
        assert_eq!(perm, vec![1, 3, 0, 2]);
    }

    #[test]
    fn test_matches_std_sort() {
        let data: Vec<&[u8]> = vec![
            b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"the", b"lazy", b"dog",
        ];
        let perm = sort_byte_slices(&data);
        let cd_sorted = apply_perm(&data, &perm);

        let mut std_sorted = data.clone();
        std_sorted.sort();

        assert_eq!(cd_sorted, std_sorted);
    }

    #[test]
    fn test_matches_cd_radix() {
        // Property: cd_merge_sort and cd_radix_sort produce the same sorted order
        use crate::sort::cd_radix;

        let data: Vec<&[u8]> = vec![
            b"cherry",
            b"apple",
            b"banana",
            b"apricot",
            b"avocado",
            b"blueberry",
            b"",
            b"banana",
            b"ap",
        ];
        let merge_perm = sort_byte_slices(&data);
        let radix_perm = cd_radix::sort_byte_slices(&data);

        let merge_sorted = apply_perm(&data, &merge_perm);
        let radix_sorted = apply_perm(&data, &radix_perm);

        assert_eq!(merge_sorted, radix_sorted);
    }

    #[test]
    fn test_with_rope_concat() {
        let mut arena = Arena::new();
        // "hello" = "hel" + "lo"
        let h = {
            let a = arena.from_bytes(b"hel");
            let b = arena.from_bytes(b"lo");
            arena.concat(a, b)
        };
        // "help"
        let p = {
            let a = arena.from_bytes(b"hel");
            let b = arena.from_bytes(b"p");
            arena.concat(a, b)
        };
        // "he"
        let e = arena.from_bytes(b"he");

        let strings = vec![(h, 0), (p, 1), (e, 2)];
        let perm = cd_merge_sort(&arena, &strings);
        // "he" < "hello" < "help"
        assert_eq!(perm, vec![2, 0, 1]);
    }

    #[test]
    fn test_with_repeat_nodes() {
        let mut arena = Arena::new();
        let ab3 = {
            let pat = arena.from_bytes(b"ab");
            arena.repeat(pat, 3) // "ababab"
        };
        let ac2 = {
            let pat = arena.from_bytes(b"ac");
            arena.repeat(pat, 2) // "acac"
        };
        let ab2 = {
            let pat = arena.from_bytes(b"ab");
            arena.repeat(pat, 2) // "abab"
        };

        let strings = vec![(ab3, 0), (ac2, 1), (ab2, 2)];
        let perm = cd_merge_sort(&arena, &strings);
        // "abab" < "ababab" < "acac"
        assert_eq!(perm, vec![2, 0, 1]);
    }

    #[test]
    fn test_power_of_two_length() {
        // n = 8 — exact power of two, all merge levels fully balanced
        let data: Vec<&[u8]> = vec![b"h", b"g", b"f", b"e", b"d", b"c", b"b", b"a"];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        let mut expected = data.clone();
        expected.sort();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn test_non_power_of_two_length() {
        // n = 7 — non-power-of-two, last merge has uneven runs
        let data: Vec<&[u8]> = vec![b"g", b"f", b"e", b"d", b"c", b"b", b"a"];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        let mut expected = data.clone();
        expected.sort();
        assert_eq!(sorted, expected);
    }
}
