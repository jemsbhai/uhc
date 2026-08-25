# Audit reproduction manifest

Permanent byte seeds:

- `python-polynomial-collision-{left,right}.hex`: the known fixed-base
  polynomial collision (`002900da1a0032db003000b40000` versus
  `0e005a0000d8000041007900f8d8`). Exact verification must reject equality.
- `rust-roadmap-collision-{left,right}.hex`: the roadmap ordering pair
  `[0, 131, 255]` versus `[1, 0, 0]`.
- `rust-hashrope-collision-left.hex` plus the roadmap right seed: the actual
  hashrope-0.2 base-131 collision `[0, 131, 0]` versus `[1, 0, 0]`.
- `gzip-concatenated.hex` and `zstd-concatenated.hex`: two-member/frame seeds
  that must decode to `leftright` rather than silently stopping after `left`.

Non-byte audit cases remain permanent focused tests:

- invalid moduli, duplicate bases, and invalid token/reference fields:
  `tests/test_p0_correctness.py`;
- 100,000-byte shared-prefix stack regression and both Rust collision pairs:
  `src/adversarial_tests.rs` and the original focused module tests;
- malformed/trailing stream boundaries: `tests/corpus/malformed/` and
  `tests/test_adversarial_differential.py`.
