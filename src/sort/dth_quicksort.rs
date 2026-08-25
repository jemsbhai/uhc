//! Baseline: decompress then quicksort (Definition 15).
//!
//! Materializes all strings via `arena.to_bytes()`, then sorts using
//! Rust's `sort()` (Timsort — a hybrid mergesort/insertion sort).
//!
//! This is the standard decompress-then-sort approach for benchmarking
//! against the compressed-domain algorithms.
//!
//! Complexity:
//!   Time:  O(M + n log n)  where M = total uncompressed size
//!   Space: O(M + n)

use hashrope::{Arena, Node};

/// Decompress all ropes, then sort using std Timsort.
///
/// # Returns
/// A permutation of original indices in sorted lexicographic order.
pub fn dth_quicksort(arena: &Arena, strings: &[(Node, usize)]) -> Vec<usize> {
    if strings.is_empty() {
        return Vec::new();
    }

    // Phase 1: Decompress all strings
    let decompressed: Vec<Vec<u8>> = strings
        .iter()
        .map(|(node, _)| arena.to_bytes(*node))
        .collect();

    // Phase 2: Sort indices by decompressed content
    let mut indices: Vec<usize> = (0..strings.len()).collect();
    indices.sort_by(|&a, &b| decompressed[a].cmp(&decompressed[b]));

    indices.iter().map(|&i| strings[i].1).collect()
}

/// Convenience: sort byte slices via DTH-quicksort.
pub fn sort_byte_slices(data: &[&[u8]]) -> Vec<usize> {
    let mut arena = Arena::new();
    let strings: Vec<(Node, usize)> = data
        .iter()
        .enumerate()
        .map(|(i, bytes)| (arena.from_bytes(bytes), i))
        .collect();
    dth_quicksort(&arena, &strings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_perm<'a>(data: &[&'a [u8]], perm: &[usize]) -> Vec<&'a [u8]> {
        perm.iter().map(|&i| data[i]).collect()
    }

    #[test]
    fn test_empty() {
        assert!(sort_byte_slices(&[]).is_empty());
    }

    #[test]
    fn test_single() {
        assert_eq!(sort_byte_slices(&[b"x"]), vec![0]);
    }

    #[test]
    fn test_basic_sort() {
        let data: Vec<&[u8]> = vec![b"cherry", b"apple", b"banana"];
        let sorted = apply_perm(&data, &sort_byte_slices(&data));
        assert_eq!(sorted, vec![&b"apple"[..], &b"banana"[..], &b"cherry"[..]]);
    }

    #[test]
    fn test_prefix_ordering() {
        let data: Vec<&[u8]> = vec![b"abd", b"b", b"ab", b"abc"];
        let sorted = apply_perm(&data, &sort_byte_slices(&data));
        assert_eq!(
            sorted,
            vec![&b"ab"[..], &b"abc"[..], &b"abd"[..], &b"b"[..]]
        );
    }

    #[test]
    fn test_empty_strings() {
        let data: Vec<&[u8]> = vec![b"b", b"", b"a", b""];
        let sorted = apply_perm(&data, &sort_byte_slices(&data));
        assert_eq!(sorted, vec![&b""[..], &b""[..], &b"a"[..], &b"b"[..]]);
    }

    #[test]
    fn test_with_repeat_ropes() {
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
        let perm = dth_quicksort(&arena, &strings);
        assert_eq!(perm, vec![2, 0, 1]);
    }

    #[test]
    fn test_matches_std_sort() {
        let data: Vec<&[u8]> = vec![
            b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"the", b"lazy", b"dog",
        ];
        let perm = sort_byte_slices(&data);
        let dth_sorted = apply_perm(&data, &perm);
        let mut expected = data.clone();
        expected.sort();
        assert_eq!(dth_sorted, expected);
    }

    #[test]
    fn test_cross_validate_cd_radix() {
        use crate::sort::cd_radix;
        let data: Vec<&[u8]> = vec![b"cherry", b"apple", b"banana", b"", b"ap", b"banana"];
        let dth = apply_perm(&data, &sort_byte_slices(&data));
        let cdr = apply_perm(&data, &cd_radix::sort_byte_slices(&data));
        assert_eq!(dth, cdr);
    }
}
