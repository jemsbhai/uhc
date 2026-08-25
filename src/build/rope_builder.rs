//! Token stream → rope construction (Theorem 11, without eviction).
//!
//! Processes a token stream and builds a complete rope in the arena.
//! Each Literal byte is accumulated and flushed as a single leaf node.
//! Each Reference is resolved via Split + Repeat + Concat on the
//! current rope.
//!
//! **No eviction:** The full rope is retained for subsequent sorting.
//! This differs from the streaming CDH framework (SlidingWindow) which
//! evicts data outside the window.
//!
//! Complexity (Theorem 13, without eviction):
//!   Time:  O(k · c_F · T) where T = token count, c_F = format constant
//!   Space: O(T · k · C_node) — one leaf per literal batch, structural
//!          sharing for references

use crate::tokens::types::{Token, TokenStream};
use core::fmt;
use hashrope::{Arena, Node};

/// Default maximum bytes retained by one literal leaf.
pub const DEFAULT_MAX_LEAF_BYTES: usize = 4096;

/// Finite construction budgets for public token streams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildLimits {
    pub max_leaf_bytes: usize,
    pub max_tokens: usize,
    pub max_decoded_bytes: u64,
    pub max_arena_nodes: usize,
    pub max_depth: u64,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_leaf_bytes: DEFAULT_MAX_LEAF_BYTES,
            max_tokens: 10_000_000,
            max_decoded_bytes: 1 << 30,
            max_arena_nodes: 10_000_000,
            max_depth: 256,
        }
    }
}

/// Recoverable validation failures while consuming a public token stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    ZeroDistance {
        token_index: usize,
    },
    ZeroLength {
        token_index: usize,
    },
    DistanceExceedsPosition {
        token_index: usize,
        distance: u32,
        position: u64,
    },
    DistanceExceedsFormat {
        token_index: usize,
        distance: u32,
        maximum: u32,
    },
    LengthOutsideFormat {
        token_index: usize,
        length: u32,
        minimum: u32,
        maximum: u32,
    },
    InvalidLimit {
        name: &'static str,
    },
    TokenLimitExceeded {
        maximum: usize,
    },
    DecodedSizeLimitExceeded {
        maximum: u64,
    },
    ArenaNodeLimitExceeded {
        current: usize,
        maximum: usize,
    },
    RopeDepthLimitExceeded {
        depth: u64,
        maximum: u64,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDistance { token_index } => {
                write!(formatter, "token {token_index} has zero reference distance")
            }
            Self::ZeroLength { token_index } => {
                write!(formatter, "token {token_index} has zero reference length")
            }
            Self::DistanceExceedsPosition {
                token_index,
                distance,
                position,
            } => write!(
                formatter,
                "token {token_index} distance {distance} exceeds decoded position {position}",
            ),
            Self::DistanceExceedsFormat {
                token_index,
                distance,
                maximum,
            } => write!(
                formatter,
                "token {token_index} distance {distance} exceeds format maximum {maximum}",
            ),
            Self::LengthOutsideFormat {
                token_index,
                length,
                minimum,
                maximum,
            } => write!(
                formatter,
                "token {token_index} length {length} is outside format range {minimum}..={maximum}",
            ),
            Self::InvalidLimit { name } => write!(formatter, "build limit {name} must be positive"),
            Self::TokenLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "token count exceeds configured maximum {maximum}"
                )
            }
            Self::DecodedSizeLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "decoded size exceeds configured maximum {maximum}"
                )
            }
            Self::ArenaNodeLimitExceeded { current, maximum } => write!(
                formatter,
                "arena node count {current} cannot stay within configured maximum {maximum}",
            ),
            Self::RopeDepthLimitExceeded { depth, maximum } => write!(
                formatter,
                "rope depth {depth} exceeds configured maximum {maximum}",
            ),
        }
    }
}

impl std::error::Error for BuildError {}

/// Build a rope from a token stream.
///
/// Processes all tokens, building the rope incrementally in the arena.
/// Consecutive literals are batched into a single leaf node.
///
/// # Arguments
/// * `arena` — The rope arena (mutable; nodes are allocated here)
/// * `stream` — The token stream to consume
///
/// # Returns
/// The root `Node` of the constructed rope, or `None` if the stream is empty.
/// Invalid public tokens return a structured [`BuildError`].
pub fn build_rope(arena: &mut Arena, stream: &mut dyn TokenStream) -> Result<Node, BuildError> {
    build_rope_with_limits(arena, stream, &BuildLimits::default())
}

/// Build a rope while enforcing finite token, output, leaf, depth, and node budgets.
pub fn build_rope_with_limits(
    arena: &mut Arena,
    stream: &mut dyn TokenStream,
    limits: &BuildLimits,
) -> Result<Node, BuildError> {
    validate_limits(limits)?;
    let mut current: Node = None;
    let mut literal_buf: Vec<u8> = Vec::with_capacity(limits.max_leaf_bytes);
    let params = stream.format_params().clone();
    let mut token_index = 0usize;

    while let Some(token) = stream.next_token() {
        if token_index >= limits.max_tokens {
            return Err(BuildError::TokenLimitExceeded {
                maximum: limits.max_tokens,
            });
        }
        match token {
            Token::Literal { byte } => {
                ensure_decoded_budget(arena.len(current), literal_buf.len() as u64 + 1, limits)?;
                literal_buf.push(byte);
                if literal_buf.len() == limits.max_leaf_bytes {
                    flush_literals(arena, &mut current, &mut literal_buf, limits, token_index)?;
                }
            }
            Token::Reference { distance, length } => {
                if distance == 0 {
                    return Err(BuildError::ZeroDistance { token_index });
                }
                if length == 0 {
                    return Err(BuildError::ZeroLength { token_index });
                }
                if distance > params.d_max {
                    return Err(BuildError::DistanceExceedsFormat {
                        token_index,
                        distance,
                        maximum: params.d_max,
                    });
                }
                if length < params.m_min || length > params.m_max {
                    return Err(BuildError::LengthOutsideFormat {
                        token_index,
                        length,
                        minimum: params.m_min,
                        maximum: params.m_max,
                    });
                }
                // Flush pending literals
                flush_literals(arena, &mut current, &mut literal_buf, limits, token_index)?;

                let cur_len = arena.len(current);
                ensure_decoded_budget(cur_len, length as u64, limits)?;
                if (distance as u64) > cur_len {
                    return Err(BuildError::DistanceExceedsPosition {
                        token_index,
                        distance,
                        position: cur_len,
                    });
                }

                let d = distance as u64;
                let l = length as u64;
                reserve_token_nodes(arena, current, limits)?;

                // Extract the source pattern: last `d` bytes of current rope
                let start = cur_len - d;
                let (_, source) = arena.split(current, start);
                // source has length = d

                let copied = if l <= d {
                    // Non-overlapping: take first `l` bytes of source
                    let (copied, _) = arena.split(source, l);
                    copied
                } else {
                    // Overlapping: repeat source pattern to cover `l` bytes
                    let full_reps = l / d;
                    let remainder = l % d;
                    let mut result = arena.repeat(source, full_reps);
                    if remainder > 0 {
                        let (partial, _) = arena.split(source, remainder);
                        result = arena.concat(result, partial);
                    }
                    result
                };

                current = arena.concat(current, copied);
                check_structure(arena, current, limits)?;
            }
        }
        token_index += 1;
    }

    // Flush remaining literals
    flush_literals(arena, &mut current, &mut literal_buf, limits, token_index)?;

    Ok(current)
}

fn validate_limits(limits: &BuildLimits) -> Result<(), BuildError> {
    for (name, valid) in [
        ("max_leaf_bytes", limits.max_leaf_bytes > 0),
        ("max_tokens", limits.max_tokens > 0),
        ("max_decoded_bytes", limits.max_decoded_bytes > 0),
        ("max_arena_nodes", limits.max_arena_nodes > 0),
        ("max_depth", limits.max_depth > 0),
    ] {
        if !valid {
            return Err(BuildError::InvalidLimit { name });
        }
    }
    Ok(())
}

fn ensure_decoded_budget(
    current: u64,
    additional: u64,
    limits: &BuildLimits,
) -> Result<(), BuildError> {
    if current
        .checked_add(additional)
        .is_none_or(|size| size > limits.max_decoded_bytes)
    {
        return Err(BuildError::DecodedSizeLimitExceeded {
            maximum: limits.max_decoded_bytes,
        });
    }
    Ok(())
}

fn reserve_token_nodes(
    arena: &Arena,
    current: Node,
    limits: &BuildLimits,
) -> Result<(), BuildError> {
    // One reference performs at most four split/join paths.  Each path has
    // length bounded by the configured rope depth.  The factor 64 includes
    // repeat bisection and double-rotation allocations with ample headroom.
    let reserve = 64usize
        .saturating_mul(arena.height(current) as usize + 1)
        .saturating_add(16);
    let required = arena.node_count().saturating_add(reserve);
    if required > limits.max_arena_nodes {
        return Err(BuildError::ArenaNodeLimitExceeded {
            current: arena.node_count(),
            maximum: limits.max_arena_nodes,
        });
    }
    Ok(())
}

fn check_structure(arena: &Arena, current: Node, limits: &BuildLimits) -> Result<(), BuildError> {
    if arena.node_count() > limits.max_arena_nodes {
        return Err(BuildError::ArenaNodeLimitExceeded {
            current: arena.node_count(),
            maximum: limits.max_arena_nodes,
        });
    }
    let depth = arena.height(current);
    if depth > limits.max_depth {
        return Err(BuildError::RopeDepthLimitExceeded {
            depth,
            maximum: limits.max_depth,
        });
    }
    Ok(())
}

fn flush_literals(
    arena: &mut Arena,
    current: &mut Node,
    literal_buf: &mut Vec<u8>,
    limits: &BuildLimits,
    _token_index: usize,
) -> Result<(), BuildError> {
    if literal_buf.is_empty() {
        return Ok(());
    }
    reserve_token_nodes(arena, *current, limits)?;
    let leaf = arena.from_bytes(literal_buf);
    *current = arena.concat(*current, leaf);
    literal_buf.clear();
    check_structure(arena, *current, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::synthetic::{
        collect_tokens, decode_tokens, GenomeLikeGenerator, LogLikeGenerator, RandomGenerator,
        SharedPrefixGenerator,
    };
    use crate::tokens::types::FormatParams;

    /// Build a rope from a token slice (convenience for testing).
    fn build_from_tokens(arena: &mut Arena, tokens: &[Token]) -> Node {
        let params = FormatParams::synthetic();
        let mut stream = SliceStream {
            tokens,
            pos: 0,
            params,
        };
        build_rope(arena, &mut stream).expect("valid test token stream")
    }

    /// TokenStream adapter over a borrowed slice.
    struct SliceStream<'a> {
        tokens: &'a [Token],
        pos: usize,
        params: FormatParams,
    }

    impl<'a> TokenStream for SliceStream<'a> {
        fn next_token(&mut self) -> Option<Token> {
            if self.pos < self.tokens.len() {
                let tok = self.tokens[self.pos].clone();
                self.pos += 1;
                Some(tok)
            } else {
                None
            }
        }
        fn format_params(&self) -> &FormatParams {
            &self.params
        }
    }

    // ---- Basic tests ----

    #[test]
    fn test_empty_stream() {
        let mut arena = Arena::new();
        let tokens: Vec<Token> = vec![];
        let node = build_from_tokens(&mut arena, &tokens);
        assert_eq!(arena.len(node), 0);
    }

    #[test]
    fn test_invalid_reference_returns_structured_error() {
        let mut arena = Arena::new();
        let tokens = vec![Token::Reference {
            distance: 1,
            length: 3,
        }];
        let params = FormatParams::synthetic();
        let mut stream = SliceStream {
            tokens: &tokens,
            pos: 0,
            params,
        };

        assert_eq!(
            build_rope(&mut arena, &mut stream),
            Err(BuildError::DistanceExceedsPosition {
                token_index: 0,
                distance: 1,
                position: 0,
            }),
        );
    }

    #[test]
    fn test_zero_reference_fields_return_structured_errors() {
        let params = FormatParams::synthetic();
        let zero_distance = vec![Token::Reference {
            distance: 0,
            length: 3,
        }];
        let mut distance_stream = SliceStream {
            tokens: &zero_distance,
            pos: 0,
            params: params.clone(),
        };
        assert_eq!(
            build_rope(&mut Arena::new(), &mut distance_stream),
            Err(BuildError::ZeroDistance { token_index: 0 }),
        );

        let zero_length = vec![Token::Reference {
            distance: 1,
            length: 0,
        }];
        let mut length_stream = SliceStream {
            tokens: &zero_length,
            pos: 0,
            params,
        };
        assert_eq!(
            build_rope(&mut Arena::new(), &mut length_stream),
            Err(BuildError::ZeroLength { token_index: 0 }),
        );
    }

    #[test]
    fn test_literals_only() {
        let mut arena = Arena::new();
        let tokens = vec![
            Token::Literal { byte: b'h' },
            Token::Literal { byte: b'e' },
            Token::Literal { byte: b'l' },
            Token::Literal { byte: b'l' },
            Token::Literal { byte: b'o' },
        ];
        let node = build_from_tokens(&mut arena, &tokens);
        assert_eq!(arena.to_bytes(node), b"hello");
    }

    #[test]
    fn test_simple_reference() {
        // "abc" then copy 3 bytes from distance 3 → "abcabc"
        let mut arena = Arena::new();
        let tokens = vec![
            Token::Literal { byte: b'a' },
            Token::Literal { byte: b'b' },
            Token::Literal { byte: b'c' },
            Token::Reference {
                distance: 3,
                length: 3,
            },
        ];
        let node = build_from_tokens(&mut arena, &tokens);
        assert_eq!(arena.to_bytes(node), b"abcabc");
    }

    #[test]
    fn test_overlapping_reference() {
        // "ab" then copy from distance 2, length 6 → "abababab"
        let mut arena = Arena::new();
        let tokens = vec![
            Token::Literal { byte: b'a' },
            Token::Literal { byte: b'b' },
            Token::Reference {
                distance: 2,
                length: 6,
            },
        ];
        let node = build_from_tokens(&mut arena, &tokens);
        assert_eq!(arena.to_bytes(node), b"abababab");
    }

    #[test]
    fn test_run_length_reference() {
        // "a" then copy from distance 1, length 4 → "aaaaa"
        let mut arena = Arena::new();
        let tokens = vec![
            Token::Literal { byte: b'a' },
            Token::Reference {
                distance: 1,
                length: 4,
            },
        ];
        let node = build_from_tokens(&mut arena, &tokens);
        assert_eq!(arena.to_bytes(node), b"aaaaa");
    }

    #[test]
    fn test_partial_overlap() {
        // "abc" then copy from distance 2, length 5
        // Source pattern = "bc", repeated: "bcbcb"
        // Result: "abcbcbcb"
        let mut arena = Arena::new();
        let tokens = vec![
            Token::Literal { byte: b'a' },
            Token::Literal { byte: b'b' },
            Token::Literal { byte: b'c' },
            Token::Reference {
                distance: 2,
                length: 5,
            },
        ];
        let node = build_from_tokens(&mut arena, &tokens);
        let expected = decode_tokens(&tokens);
        assert_eq!(arena.to_bytes(node), expected);
    }

    #[test]
    fn test_multiple_references() {
        // Build: "ab" + ref(d=2,l=4) → "ababab" + ref(d=3,l=3) → "ababababab"
        // Wait: ref(d=3,l=3) from "ababab" → copies "bab" → "abababab"...
        // Let me use decode_tokens as oracle
        let mut arena = Arena::new();
        let tokens = vec![
            Token::Literal { byte: b'a' },
            Token::Literal { byte: b'b' },
            Token::Reference {
                distance: 2,
                length: 4,
            },
            Token::Reference {
                distance: 3,
                length: 3,
            },
        ];
        let node = build_from_tokens(&mut arena, &tokens);
        let expected = decode_tokens(&tokens);
        assert_eq!(arena.to_bytes(node), expected);
    }

    #[test]
    fn test_interleaved_literals_and_references() {
        let mut arena = Arena::new();
        let tokens = vec![
            Token::Literal { byte: b'x' },
            Token::Literal { byte: b'y' },
            Token::Reference {
                distance: 2,
                length: 4,
            },
            Token::Literal { byte: b'z' },
            Token::Reference {
                distance: 1,
                length: 3,
            },
        ];
        let node = build_from_tokens(&mut arena, &tokens);
        let expected = decode_tokens(&tokens);
        assert_eq!(arena.to_bytes(node), expected);
    }

    // ---- Property: build_rope matches decode_tokens for all generators ----

    #[test]
    fn test_matches_decode_random() {
        for seed in 0..10u64 {
            let mut gen = RandomGenerator::new(seed, 500, 5.0, 128);
            let tokens = collect_tokens(&mut gen);
            let expected = decode_tokens(&tokens);

            let mut arena = Arena::new();
            let node = build_from_tokens(&mut arena, &tokens);
            let actual = arena.to_bytes(node);

            assert_eq!(
                actual,
                expected,
                "seed={}: rope bytes != decode_tokens (len {} vs {})",
                seed,
                actual.len(),
                expected.len()
            );
        }
    }

    #[test]
    fn test_matches_decode_shared_prefix() {
        let prefix = SharedPrefixGenerator::generate_prefix(0, 100, 26);
        for seed in 0..5u64 {
            let mut gen = SharedPrefixGenerator::new(prefix.clone(), seed, 300, 3.0, 26);
            let tokens = collect_tokens(&mut gen);
            let expected = decode_tokens(&tokens);

            let mut arena = Arena::new();
            let node = build_from_tokens(&mut arena, &tokens);
            assert_eq!(arena.to_bytes(node), expected, "seed={}", seed);
        }
    }

    #[test]
    fn test_matches_decode_genome() {
        for seed in 0..5u64 {
            let mut gen = GenomeLikeGenerator::new(seed, 400, 3.0);
            let tokens = collect_tokens(&mut gen);
            let expected = decode_tokens(&tokens);

            let mut arena = Arena::new();
            let node = build_from_tokens(&mut arena, &tokens);
            assert_eq!(arena.to_bytes(node), expected, "seed={}", seed);
        }
    }

    #[test]
    fn test_matches_decode_log() {
        for seed in 0..5u64 {
            let mut gen = LogLikeGenerator::new(seed, 400);
            let tokens = collect_tokens(&mut gen);
            let expected = decode_tokens(&tokens);

            let mut arena = Arena::new();
            let node = build_from_tokens(&mut arena, &tokens);
            assert_eq!(arena.to_bytes(node), expected, "seed={}", seed);
        }
    }

    // ---- Integration: tokens → rope → sort ----

    #[test]
    fn test_rope_built_strings_sort_correctly() {
        // Build ropes from token streams, sort with cd_radix,
        // verify against sorting the decoded byte strings.
        use crate::sort::cd_radix::cd_radix_sort;

        let n = 15;
        let mut arena = Arena::new();
        let mut decoded_strings: Vec<Vec<u8>> = Vec::new();
        let mut rope_nodes: Vec<(Node, usize)> = Vec::new();

        for i in 0..n {
            let mut gen = RandomGenerator::new(i as u64, 200, 3.0, 26);
            let tokens = collect_tokens(&mut gen);
            let decoded = decode_tokens(&tokens);

            let node = build_from_tokens(&mut arena, &tokens);
            // Verify rope matches decoded
            assert_eq!(arena.to_bytes(node), decoded, "string {}", i);

            decoded_strings.push(decoded);
            rope_nodes.push((node, i));
        }

        // Sort ropes via cd_radix
        let rope_perm = cd_radix_sort(&arena, &rope_nodes);

        // Sort decoded strings via std
        let mut std_indices: Vec<usize> = (0..n).collect();
        std_indices.sort_by(|&a, &b| decoded_strings[a].cmp(&decoded_strings[b]));

        // Apply permutations and compare
        let rope_sorted: Vec<&[u8]> = rope_perm
            .iter()
            .map(|&i| decoded_strings[i].as_slice())
            .collect();
        let std_sorted: Vec<&[u8]> = std_indices
            .iter()
            .map(|&i| decoded_strings[i].as_slice())
            .collect();

        assert_eq!(rope_sorted, std_sorted);
    }

    // ---- Hash correctness: CDH = H (Theorem 12 verification) ----

    #[test]
    fn test_rope_hash_matches_direct_hash() {
        // Verify that the rope's root hash matches hashing the decoded
        // bytes directly. This is the implementation-level check of
        // Theorem 12 (CDH = H).
        use hashrope::PolynomialHash;

        for seed in 0..10u64 {
            let mut gen = RandomGenerator::new(seed, 300, 4.0, 128);
            let tokens = collect_tokens(&mut gen);
            let decoded = decode_tokens(&tokens);

            let mut arena = Arena::new();
            let node = build_from_tokens(&mut arena, &tokens);

            // Hash from rope (CDH)
            let rope_hash = arena.substr_hash(node, 0, decoded.len() as u64);

            // Hash from bytes directly (H)
            let h = PolynomialHash::default_hash();
            let direct_hash = h.hash(&decoded);

            assert_eq!(
                rope_hash, direct_hash,
                "seed={}: CDH hash {} != direct hash {} (Theorem 12 violation!)",
                seed, rope_hash, direct_hash
            );
        }
    }

    #[test]
    fn literal_leaves_are_bounded() {
        use hashrope::NodeInner;

        let tokens = vec![Token::Literal { byte: b'x' }; 10_000];
        let params = FormatParams::synthetic();
        let mut stream = SliceStream {
            tokens: &tokens,
            pos: 0,
            params,
        };
        let mut arena = Arena::new();
        let root = build_rope(&mut arena, &mut stream).unwrap();

        assert_eq!(arena.len(root), 10_000);
        for id in 0..arena.node_count() as u32 {
            if let NodeInner::Leaf { data, .. } = arena.node(id) {
                assert!(data.len() <= DEFAULT_MAX_LEAF_BYTES);
            }
        }
    }

    #[test]
    fn decoded_output_budget_is_recoverable() {
        let tokens = vec![Token::Literal { byte: b'x' }; 11];
        let params = FormatParams::synthetic();
        let mut stream = SliceStream {
            tokens: &tokens,
            pos: 0,
            params,
        };
        let mut arena = Arena::new();
        let limits = BuildLimits {
            max_leaf_bytes: 4,
            max_decoded_bytes: 10,
            max_arena_nodes: 10_000,
            ..BuildLimits::default()
        };

        assert_eq!(
            build_rope_with_limits(&mut arena, &mut stream, &limits),
            Err(BuildError::DecodedSizeLimitExceeded { maximum: 10 }),
        );
    }

    #[test]
    fn persistent_split_growth_stays_below_node_ceiling() {
        let mut tokens = vec![Token::Literal { byte: b'a' }, Token::Literal { byte: b'b' }];
        tokens.extend((0..80).map(|_| Token::Reference {
            distance: 2,
            length: 8,
        }));
        let params = FormatParams::synthetic();
        let mut stream = SliceStream {
            tokens: &tokens,
            pos: 0,
            params,
        };
        let mut arena = Arena::new();
        let limits = BuildLimits {
            max_leaf_bytes: 8,
            max_arena_nodes: 50_000,
            ..BuildLimits::default()
        };

        let root = build_rope_with_limits(&mut arena, &mut stream, &limits).unwrap();
        assert!(arena.node_count() <= limits.max_arena_nodes);
        assert!(arena.height(root) <= limits.max_depth);
    }

    #[test]
    fn node_reservation_stops_before_arena_ceiling() {
        let tokens = vec![Token::Literal { byte: b'x' }; 100];
        let params = FormatParams::synthetic();
        let mut stream = SliceStream {
            tokens: &tokens,
            pos: 0,
            params,
        };
        let mut arena = Arena::new();
        let limits = BuildLimits {
            max_leaf_bytes: 1,
            max_arena_nodes: 100,
            ..BuildLimits::default()
        };

        assert!(matches!(
            build_rope_with_limits(&mut arena, &mut stream, &limits),
            Err(BuildError::ArenaNodeLimitExceeded { maximum: 100, .. })
        ));
        assert!(arena.node_count() <= limits.max_arena_nodes);
    }
}
