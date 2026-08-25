#![no_main]

use cdh_sort::build::rope_builder::{build_rope_with_limits, BuildLimits};
use cdh_sort::tokens::types::{FormatParams, Token, TokenStream};
use hashrope::Arena;
use libfuzzer_sys::fuzz_target;

struct VectorStream {
    tokens: std::vec::IntoIter<Token>,
    params: FormatParams,
}

impl TokenStream for VectorStream {
    fn next_token(&mut self) -> Option<Token> {
        self.tokens.next()
    }

    fn format_params(&self) -> &FormatParams {
        &self.params
    }
}

fuzz_target!(|input: &[u8]| {
    let bounded = &input[..input.len().min(2048)];
    let mut tokens = Vec::new();
    let mut expected = Vec::new();

    for (index, &byte) in bounded.iter().enumerate() {
        if expected.len() < 3 || index % 3 == 0 {
            tokens.push(Token::Literal { byte });
            expected.push(byte);
            continue;
        }

        let distance = 1 + usize::from(byte) % expected.len().min(32_768);
        let length = 3 + usize::from(byte) % 32;
        tokens.push(Token::Reference {
            distance: distance as u32,
            length: length as u32,
        });
        for _ in 0..length {
            let copied = expected[expected.len() - distance];
            expected.push(copied);
        }
    }

    let limits = BuildLimits {
        max_leaf_bytes: 64,
        max_tokens: 4096,
        max_decoded_bytes: 65_536,
        max_arena_nodes: 200_000,
        max_depth: 512,
    };
    let mut stream = VectorStream {
        tokens: tokens.into_iter(),
        params: FormatParams::deflate(),
    };
    let mut arena = Arena::new();
    let node = build_rope_with_limits(&mut arena, &mut stream, &limits)
        .expect("generated token stream is valid and within its explicit budgets");
    assert_eq!(arena.to_bytes(node), expected);
});
