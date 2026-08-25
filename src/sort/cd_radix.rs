//! CD-Radix sort: MSD radix sort using ByteAt on ropes (Theorem 36).
//!
//! Sorts compressed strings without decompression and without any
//! polynomial hash evaluation. Uses only structural rope traversal
//! via ByteAt (Theorem 32).
//!
//! Time:  O((T + n·D) · log t_max)
//! Space: O(T + n) auxiliary; an explicit work stack bounds call-stack use.
//!
//! **Design note (Corollary 8):** This function takes `&Arena` (not `&mut Arena`)
//! because CD-Radix uses only structural traversal via ByteAt — zero polynomial
//! hash evaluations. This is deliberate and encodes the zero-hashing property
//! at the type level. The hybrid sort (Theorem 38) holds `&mut Arena` and passes
//! it here via Rust's auto-coercion (`&mut T` → `&T`).

use crate::byte_at::byte_at_in_bounds;
use hashrope::{Arena, Node};

/// Sort string indices by lexicographic order using MSD radix sort
/// over rope representations.
///
/// # Arguments
/// * `arena` - The rope arena containing all string ropes
/// * `strings` - Slice of (Node, index) pairs; Node is the rope, index is the original position
///
/// # Returns
/// A permutation of the original indices in sorted order.
pub fn cd_radix_sort(arena: &Arena, strings: &[(Node, usize)]) -> Vec<usize> {
    if strings.is_empty() {
        return Vec::new();
    }
    // Collect (node, original_index) into working array
    let mut indices: Vec<usize> = (0..strings.len()).collect();
    cd_radix_iterative(arena, strings, &mut indices);
    indices.iter().map(|&i| strings[i].1).collect()
}

/// Internal iterative MSD radix sort.
fn cd_radix_iterative(arena: &Arena, strings: &[(Node, usize)], indices: &mut [usize]) {
    const END_OF_STRING: usize = 256;
    let mut work = vec![(0usize, indices.len(), 0u64)];

    while let Some((range_start, range_len, depth)) = work.pop() {
        if range_len <= 1 {
            continue;
        }
        let range_end = range_start + range_len;
        let range = &mut indices[range_start..range_end];
        let mut bucket_counts = [0usize; 257];

        for &idx in range.iter() {
            let (node, _) = strings[idx];
            let bucket = if depth >= arena.len(node) {
                END_OF_STRING
            } else {
                byte_at_in_bounds(arena, node, depth) as usize
            };
            bucket_counts[bucket] += 1;
        }

        let mut offsets = [0usize; 257];
        offsets[0] = bucket_counts[END_OF_STRING];
        for bucket in 1..256 {
            offsets[bucket] = offsets[bucket - 1] + bucket_counts[bucket - 1];
        }

        let mut positions = offsets;
        positions[END_OF_STRING] = 0;
        let mut sorted = vec![0usize; range_len];
        for &idx in range.iter() {
            let (node, _) = strings[idx];
            let bucket = if depth >= arena.len(node) {
                END_OF_STRING
            } else {
                byte_at_in_bounds(arena, node, depth) as usize
            };
            sorted[positions[bucket]] = idx;
            positions[bucket] += 1;
        }
        range.copy_from_slice(&sorted);

        let mut child_start = range_start + bucket_counts[END_OF_STRING];
        for &count in &bucket_counts[..256] {
            if count > 1 {
                work.push((child_start, count, depth + 1));
            }
            child_start += count;
        }
    }
}

/// Convenience: sort byte slices via CD-Radix.
/// Builds ropes, sorts, returns the sorted permutation.
pub fn sort_byte_slices(data: &[&[u8]]) -> Vec<usize> {
    let mut arena = Arena::new();
    let strings: Vec<(Node, usize)> = data
        .iter()
        .enumerate()
        .map(|(i, bytes)| (arena.from_bytes(bytes), i))
        .collect();
    cd_radix_sort(&arena, &strings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_perm<'a>(data: &[&'a [u8]], perm: &[usize]) -> Vec<&'a [u8]> {
        perm.iter().map(|&i| data[i]).collect()
    }

    #[test]
    fn test_empty() {
        let data: Vec<&[u8]> = vec![];
        let perm = sort_byte_slices(&data);
        assert!(perm.is_empty());
    }

    #[test]
    fn test_single() {
        let data: Vec<&[u8]> = vec![b"hello"];
        let perm = sort_byte_slices(&data);
        assert_eq!(perm, vec![0]);
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
        // "ab" < "abc" < "abd" < "b"
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
        // Empty string sorts before everything
        let data: Vec<&[u8]> = vec![b"b", b"", b"a", b""];
        let perm = sort_byte_slices(&data);
        let sorted = apply_perm(&data, &perm);
        assert_eq!(sorted, vec![&b""[..], &b""[..], &b"a"[..], &b"b"[..]]);
    }

    #[test]
    fn test_matches_std_sort() {
        // Property: CD-Radix output matches std sort
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
    fn test_sort_with_ropes_from_concat() {
        // Build ropes via concat (not just from_bytes) and sort
        let mut arena = Arena::new();
        // "hello" = "hel" + "lo"
        let h = {
            let a = arena.from_bytes(b"hel");
            let b = arena.from_bytes(b"lo");
            arena.concat(a, b)
        };
        // "help" = "hel" + "p"
        let p = {
            let a = arena.from_bytes(b"hel");
            let b = arena.from_bytes(b"p");
            arena.concat(a, b)
        };
        // "he" (just a leaf)
        let e = arena.from_bytes(b"he");

        let strings = vec![(h, 0), (p, 1), (e, 2)];
        let perm = cd_radix_sort(&arena, &strings);
        // "he" < "hello" < "help"
        assert_eq!(perm, vec![2, 0, 1]);
    }

    #[test]
    fn test_sort_with_repeat_nodes() {
        // Sort strings built with RepeatNode
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
        let perm = cd_radix_sort(&arena, &strings);
        // "abab" < "ababab" < "acac"
        assert_eq!(perm, vec![2, 0, 1]);
    }

    #[test]
    fn test_large_alphabet() {
        // All 256 byte values as single-byte strings
        let data: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let perm = sort_byte_slices(&refs);
        // Should be identity permutation (already sorted by byte value)
        let expected: Vec<usize> = (0..256).collect();
        assert_eq!(perm, expected);
    }

    #[test]
    fn test_long_shared_prefix_does_not_use_call_stack() {
        let prefix = vec![b'a'; 100_000];
        let mut left = prefix.clone();
        let mut right = prefix;
        left.push(b'b');
        right.push(b'c');
        let data = vec![right.as_slice(), left.as_slice()];
        assert_eq!(sort_byte_slices(&data), vec![1, 0]);
    }
}
