#![no_main]

use cdh_sort::sort::{cd_lcp, cd_merge, cd_radix};
use hashrope::Arena;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let bounded = &input[..input.len().min(4096)];
    let strings: Vec<Vec<u8>> = bounded
        .split(|byte| *byte == b'\n')
        .take(64)
        .map(|part| part.to_vec())
        .collect();
    let refs: Vec<&[u8]> = strings.iter().map(Vec::as_slice).collect();

    let mut expected = refs.clone();
    expected.sort();
    for permutation in [
        cd_merge::sort_byte_slices(&refs),
        cd_radix::sort_byte_slices(&refs),
    ] {
        let mut indices = permutation.clone();
        indices.sort_unstable();
        assert_eq!(indices, (0..strings.len()).collect::<Vec<_>>());
        let actual: Vec<&[u8]> = permutation.iter().map(|&i| strings[i].as_slice()).collect();
        assert_eq!(actual, expected);
    }

    if strings.len() >= 2 {
        let mut arena = Arena::new();
        let left = arena.from_bytes(&strings[0]);
        let right = arena.from_bytes(&strings[1]);
        let native_lcp = strings[0]
            .iter()
            .zip(&strings[1])
            .take_while(|(a, b)| a == b)
            .count() as u64;
        assert_eq!(cd_lcp::cd_lcp(&arena, left, right), native_lcp);
        assert_eq!(
            cd_lcp::cd_compare(&arena, left, right),
            strings[0].cmp(&strings[1]),
        );
    }
});
