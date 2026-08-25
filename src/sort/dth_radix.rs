//! Baseline: decompress then MSD radix sort (Definition 15 variant).
//!
//! Materializes all strings via `arena.to_bytes()`, then applies
//! MSD radix sort on the decompressed byte arrays.
//!
//! Complexity:
//!   Time:  O(M + n · D)  where D = distinguishing depth
//!   Space: O(M + n), with an explicit work stack instead of recursion.

use hashrope::{Arena, Node};

/// Decompress all ropes, then MSD radix sort on raw bytes.
///
/// # Returns
/// A permutation of original indices in sorted lexicographic order.
pub fn dth_radix_sort(arena: &Arena, strings: &[(Node, usize)]) -> Vec<usize> {
    if strings.is_empty() {
        return Vec::new();
    }

    let decompressed: Vec<Vec<u8>> = strings
        .iter()
        .map(|(node, _)| arena.to_bytes(*node))
        .collect();

    let mut indices: Vec<usize> = (0..strings.len()).collect();
    msd_radix_iterative(&decompressed, &mut indices);

    indices.iter().map(|&i| strings[i].1).collect()
}

fn msd_radix_iterative(data: &[Vec<u8>], indices: &mut [usize]) {
    const EOS: usize = 256;
    let mut work = vec![(0usize, indices.len(), 0usize)];
    while let Some((range_start, range_len, depth)) = work.pop() {
        if range_len <= 1 {
            continue;
        }
        let range_end = range_start + range_len;
        let range = &mut indices[range_start..range_end];
        let mut counts = [0usize; 257];
        for &idx in range.iter() {
            let bucket = if depth >= data[idx].len() {
                EOS
            } else {
                data[idx][depth] as usize
            };
            counts[bucket] += 1;
        }

        let mut offsets = [0usize; 257];
        offsets[0] = counts[EOS];
        for bucket in 1..256 {
            offsets[bucket] = offsets[bucket - 1] + counts[bucket - 1];
        }
        let mut positions = offsets;
        positions[EOS] = 0;
        let mut sorted = vec![0usize; range_len];
        for &idx in range.iter() {
            let bucket = if depth >= data[idx].len() {
                EOS
            } else {
                data[idx][depth] as usize
            };
            sorted[positions[bucket]] = idx;
            positions[bucket] += 1;
        }
        range.copy_from_slice(&sorted);

        let mut child_start = range_start + counts[EOS];
        for &count in &counts[..256] {
            if count > 1 {
                work.push((child_start, count, depth + 1));
            }
            child_start += count;
        }
    }
}

/// Convenience: sort byte slices via DTH-radix.
pub fn sort_byte_slices(data: &[&[u8]]) -> Vec<usize> {
    let mut arena = Arena::new();
    let strings: Vec<(Node, usize)> = data
        .iter()
        .enumerate()
        .map(|(i, bytes)| (arena.from_bytes(bytes), i))
        .collect();
    dth_radix_sort(&arena, &strings)
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
    fn test_matches_std_sort() {
        let data: Vec<&[u8]> = vec![
            b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"the", b"lazy", b"dog",
        ];
        let sorted = apply_perm(&data, &sort_byte_slices(&data));
        let mut expected = data.clone();
        expected.sort();
        assert_eq!(sorted, expected);
    }

    #[test]
    fn test_large_alphabet() {
        let data: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
        let refs: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let perm = sort_byte_slices(&refs);
        let expected: Vec<usize> = (0..256).collect();
        assert_eq!(perm, expected);
    }

    #[test]
    fn test_cross_validate_all_algorithms() {
        // Ultimate cross-validation: all 4 sorting algorithms must agree.
        use crate::sort::{cd_merge, cd_radix, dth_quicksort};

        let data: Vec<&[u8]> = vec![
            b"cherry", b"apple", b"banana", b"", b"ap", b"banana", b"z", b"aa", b"aaa", b"a",
        ];

        let r1 = apply_perm(&data, &cd_radix::sort_byte_slices(&data));
        let r2 = apply_perm(&data, &cd_merge::sort_byte_slices(&data));
        let r3 = apply_perm(&data, &dth_quicksort::sort_byte_slices(&data));
        let r4 = apply_perm(&data, &sort_byte_slices(&data));

        assert_eq!(r1, r2, "cd_radix vs cd_merge disagree");
        assert_eq!(r2, r3, "cd_merge vs dth_quicksort disagree");
        assert_eq!(r3, r4, "dth_quicksort vs dth_radix disagree");
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
