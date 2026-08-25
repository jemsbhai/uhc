//! Deterministic UHC 05 proptest and permanent adversarial regressions.

use crate::sort::{cd_lcp, cd_merge, cd_radix};
use hashrope::{Arena, Node};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

const UHC05_SEED: u64 = 20_260_819;

fn chunked_node(arena: &mut Arena, data: &[u8]) -> Node {
    if data.is_empty() {
        return arena.from_bytes(data);
    }
    let mut root: Node = None;
    for chunk in data.chunks(7) {
        let leaf = arena.from_bytes(chunk);
        root = if root.is_none() {
            leaf
        } else {
            arena.concat(root, leaf)
        };
    }
    root
}

fn native_lcp(left: &[u8], right: &[u8]) -> u64 {
    left.iter().zip(right).take_while(|(a, b)| a == b).count() as u64
}

fn sorted_bytes<'a>(data: &'a [Vec<u8>], permutation: &[usize]) -> Vec<&'a [u8]> {
    permutation
        .iter()
        .map(|&index| data[index].as_slice())
        .collect()
}

fn assert_is_permutation(permutation: &[usize], length: usize) {
    let mut actual = permutation.to_vec();
    actual.sort_unstable();
    assert_eq!(actual, (0..length).collect::<Vec<_>>());
}

proptest! {
    #![proptest_config(Config {
        cases: 128,
        rng_seed: RngSeed::Fixed(UHC05_SEED),
        failure_persistence: None,
        ..Config::default()
    })]

    #[test]
    fn exact_lcp_and_compare_match_native(
        left in proptest::collection::vec(any::<u8>(), 0..256),
        right in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut arena = Arena::new();
        let left_node = chunked_node(&mut arena, &left);
        let right_node = chunked_node(&mut arena, &right);

        prop_assert_eq!(
            cd_lcp::cd_lcp(&arena, left_node, right_node),
            native_lcp(&left, &right),
        );
        prop_assert_eq!(
            cd_lcp::cd_compare(&arena, left_node, right_node),
            left.cmp(&right),
        );
    }

    #[test]
    fn exact_sorters_match_native(
        data in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..96),
            0..24,
        ),
    ) {
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let merge = cd_merge::sort_byte_slices(&refs);
        let radix = cd_radix::sort_byte_slices(&refs);
        assert_is_permutation(&merge, data.len());
        assert_is_permutation(&radix, data.len());

        let mut expected = refs.clone();
        expected.sort();
        prop_assert_eq!(sorted_bytes(&data, &merge), expected.clone());
        prop_assert_eq!(sorted_bytes(&data, &radix), expected);
    }

    #[test]
    fn exact_sorters_handle_generated_shared_prefixes(
        prefix in proptest::collection::vec(any::<u8>(), 0..384),
        suffixes in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 0..32),
            1..20,
        ),
    ) {
        let data: Vec<Vec<u8>> = suffixes
            .into_iter()
            .map(|suffix| {
                let mut value = prefix.clone();
                value.extend(suffix);
                value
            })
            .collect();
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let mut expected = refs.clone();
        expected.sort();
        let merge = cd_merge::sort_byte_slices(&refs);
        let radix = cd_radix::sort_byte_slices(&refs);
        prop_assert_eq!(sorted_bytes(&data, &merge), expected.clone());
        prop_assert_eq!(sorted_bytes(&data, &radix), expected);
    }
}

#[test]
fn audit_collision_pairs_are_compared_exactly() {
    let mut arena = Arena::new();
    let roadmap_left = arena.from_bytes(&[0, 131, 255]);
    let roadmap_right = arena.from_bytes(&[1, 0, 0]);
    assert_eq!(cd_lcp::cd_lcp(&arena, roadmap_left, roadmap_right), 0);
    assert!(cd_lcp::cd_compare(&arena, roadmap_left, roadmap_right).is_lt());

    let actual_collision_left = arena.from_bytes(&[0, 131, 0]);
    assert_eq!(
        arena.substr_hash(actual_collision_left, 0, 3),
        arena.substr_hash(roadmap_right, 0, 3),
    );
    assert_eq!(
        cd_lcp::cd_lcp(&arena, actual_collision_left, roadmap_right),
        0,
    );
    assert!(cd_lcp::cd_compare(&arena, actual_collision_left, roadmap_right).is_lt());
}

#[test]
fn audit_long_shared_prefix_uses_bounded_sort_work() {
    let prefix = vec![b'x'; 100_000];
    let mut left = prefix.clone();
    left.push(0);
    let mut right = prefix;
    right.push(1);
    let data = [right, left];
    let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();

    assert_eq!(cd_merge::sort_byte_slices(&refs), vec![1, 0]);
    assert_eq!(cd_radix::sort_byte_slices(&refs), vec![1, 0]);

    let mut arena = Arena::new();
    let a = chunked_node(&mut arena, &data[0]);
    let b = chunked_node(&mut arena, &data[1]);
    assert_eq!(cd_lcp::cd_lcp(&arena, a, b), 100_000);
}
