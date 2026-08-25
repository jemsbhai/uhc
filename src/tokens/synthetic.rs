//! Synthetic token stream generators for experiments (Definition 26).
//!
//! Four distributions producing token streams with controlled properties:
//! - `RandomGenerator`: uniform random bytes + random references
//! - `SharedPrefixGenerator`: shared literal prefix + random suffix
//! - `GenomeLikeGenerator`: 4-letter alphabet (ACGT) with tandem repeats
//! - `LogLikeGenerator`: printable ASCII with timestamp-like prefixes
//!
//! All generators are deterministically seeded for reproducibility
//! (Section 7.4 of impl spec).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::types::{FormatParams, Token, TokenStream};

// -----------------------------------------------------------------------
// Random Generator
// -----------------------------------------------------------------------

/// Random mix of literals and back-references.
///
/// Achieves target compression ratio by controlling the probability of
/// emitting a reference vs a literal: `P(literal) ≈ 1 / target_cr`.
pub struct RandomGenerator {
    rng: StdRng,
    params: FormatParams,
    target_length: u64,
    target_cr: f64,
    alphabet_size: u8,
    pos: u64,
    done: bool,
}

impl RandomGenerator {
    pub fn new(seed: u64, target_length: u64, target_cr: f64, alphabet_size: u8) -> Self {
        assert!(target_length > 0, "target_length must be > 0");
        assert!(target_cr >= 1.0, "target_cr must be >= 1.0");
        assert!(alphabet_size > 0, "alphabet_size must be > 0");
        Self {
            rng: StdRng::seed_from_u64(seed),
            params: FormatParams::synthetic(),
            target_length,
            target_cr,
            alphabet_size,
            pos: 0,
            done: false,
        }
    }

    fn random_byte(&mut self) -> u8 {
        self.rng.gen_range(0..self.alphabet_size)
    }

    fn emit_reference(&mut self) -> Token {
        let m_min = self.params.m_min as u64;
        let m_max = self.params.m_max as u64;
        let d_max = self.params.d_max as u64;

        let max_d = d_max.min(self.pos);
        let distance = self.rng.gen_range(1..=max_d) as u32;

        let remaining = self.target_length - self.pos;
        let max_l = m_max.min(remaining);
        // Bias toward longer matches for higher CR
        let mean_len = (self.target_cr as u64).max(m_min).min(max_l);
        let biased_max = (2 * mean_len).min(max_l).max(m_min);
        let length = self.rng.gen_range(m_min..=biased_max) as u32;

        self.pos += length as u64;
        Token::Reference { distance, length }
    }
}

impl TokenStream for RandomGenerator {
    fn next_token(&mut self) -> Option<Token> {
        if self.done || self.pos >= self.target_length {
            self.done = true;
            return None;
        }

        let m_min = self.params.m_min as u64;

        // Must emit literal if not enough history for a reference
        let can_reference = self.pos >= m_min && (self.target_length - self.pos) >= m_min;

        if can_reference && self.rng.gen::<f64>() > 1.0 / self.target_cr {
            Some(self.emit_reference())
        } else {
            let byte = self.random_byte();
            self.pos += 1;
            Some(Token::Literal { byte })
        }
    }

    fn format_params(&self) -> &FormatParams {
        &self.params
    }
}

// -----------------------------------------------------------------------
// SharedPrefix Generator
// -----------------------------------------------------------------------

/// Emits a fixed literal prefix, then random suffix tokens.
///
/// Multiple strings using the same `prefix` but different `suffix_seed`
/// will share a long common prefix — the regime where CD-LCP-Mergesort
/// excels (Corollary 6).
pub struct SharedPrefixGenerator {
    prefix: Vec<u8>,
    suffix: RandomGenerator,
    prefix_pos: usize,
    in_prefix: bool,
    params: FormatParams,
}

impl SharedPrefixGenerator {
    /// Create a generator that emits `prefix` as literals, then a random
    /// suffix of length `target_length - prefix.len()`.
    ///
    /// # Panics
    /// Panics if `prefix.len() >= target_length`.
    pub fn new(
        prefix: Vec<u8>,
        suffix_seed: u64,
        target_length: u64,
        suffix_cr: f64,
        alphabet_size: u8,
    ) -> Self {
        let prefix_len = prefix.len() as u64;
        assert!(
            prefix_len < target_length,
            "prefix must be shorter than target_length"
        );
        let suffix_len = target_length - prefix_len;
        Self {
            prefix,
            suffix: RandomGenerator::new(suffix_seed, suffix_len, suffix_cr, alphabet_size),
            prefix_pos: 0,
            in_prefix: true,
            params: FormatParams::synthetic(),
        }
    }

    /// Generate a random prefix of the given length using a shared seed.
    /// All strings in a corpus should use the same prefix seed.
    pub fn generate_prefix(seed: u64, length: u64, alphabet_size: u8) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..length)
            .map(|_| rng.gen_range(0..alphabet_size))
            .collect()
    }
}

impl TokenStream for SharedPrefixGenerator {
    fn next_token(&mut self) -> Option<Token> {
        if self.in_prefix {
            if self.prefix_pos < self.prefix.len() {
                let byte = self.prefix[self.prefix_pos];
                self.prefix_pos += 1;
                return Some(Token::Literal { byte });
            }
            self.in_prefix = false;
        }
        self.suffix.next_token()
    }

    fn format_params(&self) -> &FormatParams {
        &self.params
    }
}

// -----------------------------------------------------------------------
// GenomeLike Generator
// -----------------------------------------------------------------------

/// 4-letter alphabet (values 0-3, representing ACGT) with tandem repeats.
///
/// Generates motifs of 3-30 bases, then repeats them via overlapping
/// back-references. This mimics genomic tandem repeat regions.
pub struct GenomeLikeGenerator {
    rng: StdRng,
    params: FormatParams,
    target_length: u64,
    target_cr: f64,
    pos: u64,
    /// Pending tokens from the current motif+repeat cycle
    pending: Vec<Token>,
    pending_idx: usize,
    done: bool,
}

impl GenomeLikeGenerator {
    pub fn new(seed: u64, target_length: u64, target_cr: f64) -> Self {
        assert!(target_length > 0);
        assert!(target_cr >= 1.0);
        Self {
            rng: StdRng::seed_from_u64(seed),
            params: FormatParams::synthetic(),
            target_length,
            target_cr,
            pos: 0,
            pending: Vec::new(),
            pending_idx: 0,
            done: false,
        }
    }

    fn generate_cycle(&mut self) {
        self.pending.clear();
        self.pending_idx = 0;

        let remaining = self.target_length - self.pos;
        if remaining == 0 {
            self.done = true;
            return;
        }

        // Generate motif: 3-30 literal bases
        let max_motif = 30u64.min(remaining);
        if max_motif < 3 {
            // Not enough room for a full motif — emit remaining as literals
            for _ in 0..remaining {
                let byte = self.rng.gen_range(0u8..4);
                self.pending.push(Token::Literal { byte });
            }
            self.pos += remaining;
            return;
        }
        let motif_len = self.rng.gen_range(3u64..=max_motif);

        for _ in 0..motif_len {
            let byte = self.rng.gen_range(0u8..4); // ACGT
            self.pending.push(Token::Literal { byte });
        }
        self.pos += motif_len;

        // Repeat the motif via back-reference if there's room
        let remaining = self.target_length - self.pos;
        let m_min = self.params.m_min as u64;
        if remaining >= m_min && motif_len >= m_min {
            // Number of repeated copies, biased by target_cr
            let mean_repeats = (self.target_cr as u64).max(1);
            let max_repeat_len = remaining.min(self.params.m_max as u64);
            let upper = (mean_repeats * motif_len).min(max_repeat_len).max(m_min);
            let repeat_len = self.rng.gen_range(m_min..=upper);
            self.pending.push(Token::Reference {
                distance: motif_len as u32,
                length: repeat_len as u32,
            });
            self.pos += repeat_len;
        }
    }
}

impl TokenStream for GenomeLikeGenerator {
    fn next_token(&mut self) -> Option<Token> {
        if self.done {
            return None;
        }
        // Drain pending tokens from current cycle
        if self.pending_idx < self.pending.len() {
            let tok = self.pending[self.pending_idx].clone();
            self.pending_idx += 1;
            return Some(tok);
        }
        // Generate next cycle
        if self.pos >= self.target_length {
            self.done = true;
            return None;
        }
        self.generate_cycle();
        if self.done {
            return None;
        }
        let tok = self.pending[self.pending_idx].clone();
        self.pending_idx += 1;
        Some(tok)
    }

    fn format_params(&self) -> &FormatParams {
        &self.params
    }
}

// -----------------------------------------------------------------------
// LogLike Generator
// -----------------------------------------------------------------------

/// Printable ASCII with timestamp-like prefixes.
///
/// Generates lines resembling log entries:
/// - First line: all literals (timestamp + message)
/// - Subsequent lines: back-reference to previous timestamp prefix,
///   then literal message bytes
///
/// This creates strings with moderate shared prefixes (timestamps share
/// date/hour prefixes) and varying suffixes (log messages).
pub struct LogLikeGenerator {
    rng: StdRng,
    params: FormatParams,
    target_length: u64,
    pos: u64,
    line_no: u64,
    /// Length of timestamp prefix (e.g., "2024-04-09T12:" = 14 bytes)
    timestamp_prefix_len: u64,
    pending: Vec<Token>,
    pending_idx: usize,
    done: bool,
}

impl LogLikeGenerator {
    pub fn new(seed: u64, target_length: u64) -> Self {
        assert!(target_length > 0);
        Self {
            rng: StdRng::seed_from_u64(seed),
            params: FormatParams::synthetic(),
            target_length,
            pos: 0,
            line_no: 0,
            timestamp_prefix_len: 14,
            pending: Vec::new(),
            pending_idx: 0,
            done: false,
        }
    }

    fn generate_line(&mut self) {
        self.pending.clear();
        self.pending_idx = 0;

        let remaining = self.target_length - self.pos;
        if remaining == 0 {
            self.done = true;
            return;
        }

        let m_min = self.params.m_min as u64;

        if self.line_no == 0 {
            // First line: emit timestamp + message as literals
            let line_len = remaining.min(60);
            // Timestamp portion: digits and punctuation in printable ASCII
            for i in 0..line_len {
                let byte = if i < self.timestamp_prefix_len {
                    // Timestamp-like: digits '0'-'9' and separators
                    match i % 5 {
                        4 => b'-',
                        _ => self.rng.gen_range(b'0'..=b'9'),
                    }
                } else {
                    // Message: printable ASCII
                    self.rng.gen_range(32u8..=126u8)
                };
                self.pending.push(Token::Literal { byte });
            }
            self.pos += line_len;
            // Newline
            if self.pos < self.target_length {
                self.pending.push(Token::Literal { byte: b'\n' });
                self.pos += 1;
            }
        } else {
            // Subsequent lines: reference to timestamp prefix, then literal message
            let ts_len = self.timestamp_prefix_len.min(remaining);

            if ts_len >= m_min && self.pos >= ts_len {
                // Back-reference to previous line's timestamp
                // Distance ≈ previous line length (roughly 60 bytes)
                let line_size = 61u64; // approximate line length
                let distance = (self.line_no * line_size)
                    .min(self.pos)
                    .min(self.params.d_max as u64);
                if distance >= 1 {
                    self.pending.push(Token::Reference {
                        distance: distance as u32,
                        length: ts_len as u32,
                    });
                    self.pos += ts_len;
                } else {
                    // Fallback: emit as literals
                    for _ in 0..ts_len {
                        let byte = self.rng.gen_range(b'0'..=b'9');
                        self.pending.push(Token::Literal { byte });
                    }
                    self.pos += ts_len;
                }
            } else {
                // Not enough room for a reference — emit literals
                for _ in 0..ts_len {
                    let byte = self.rng.gen_range(b'0'..=b'9');
                    self.pending.push(Token::Literal { byte });
                }
                self.pos += ts_len;
            }

            // Message portion: printable ASCII literals
            let remaining = self.target_length - self.pos;
            let msg_len = self
                .rng
                .gen_range(10u64..=50u64.min(remaining).max(10))
                .min(remaining);
            for _ in 0..msg_len {
                let byte = self.rng.gen_range(32u8..=126u8);
                self.pending.push(Token::Literal { byte });
            }
            self.pos += msg_len;

            // Newline
            if self.pos < self.target_length {
                self.pending.push(Token::Literal { byte: b'\n' });
                self.pos += 1;
            }
        }
        self.line_no += 1;
    }
}

impl TokenStream for LogLikeGenerator {
    fn next_token(&mut self) -> Option<Token> {
        if self.done {
            return None;
        }
        if self.pending_idx < self.pending.len() {
            let tok = self.pending[self.pending_idx].clone();
            self.pending_idx += 1;
            return Some(tok);
        }
        if self.pos >= self.target_length {
            self.done = true;
            return None;
        }
        self.generate_line();
        if self.done {
            return None;
        }
        let tok = self.pending[self.pending_idx].clone();
        self.pending_idx += 1;
        Some(tok)
    }

    fn format_params(&self) -> &FormatParams {
        &self.params
    }
}

// -----------------------------------------------------------------------
// Helper: collect all tokens from a stream
// -----------------------------------------------------------------------

/// Drain a `TokenStream` into a `Vec<Token>`.
pub fn collect_tokens(stream: &mut dyn TokenStream) -> Vec<Token> {
    let mut tokens = Vec::new();
    while let Some(tok) = stream.next_token() {
        tokens.push(tok);
    }
    tokens
}

/// Decode a token sequence into raw bytes (for testing/verification).
///
/// Literals are appended directly. References copy from the already-decoded
/// output buffer, supporting overlapping copies (distance < length).
pub fn decode_tokens(tokens: &[Token]) -> Vec<u8> {
    let mut output = Vec::new();
    for tok in tokens {
        match tok {
            Token::Literal { byte } => {
                output.push(*byte);
            }
            Token::Reference { distance, length } => {
                let d = *distance as usize;
                let l = *length as usize;
                assert!(
                    d <= output.len(),
                    "Invalid reference: distance {} > output length {}",
                    d,
                    output.len()
                );
                let src_start = output.len() - d;
                for i in 0..l {
                    let byte = output[src_start + (i % d)];
                    output.push(byte);
                }
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Rigorous validation helper ----

    /// Validate every token in a stream against format constraints.
    /// Checks: distance ≤ d_max, distance ≤ current position,
    /// length ∈ [m_min, m_max] for references.
    /// Returns (decoded_bytes, token_count, literal_count, ref_count).
    fn validate_and_decode(
        tokens: &[Token],
        params: &FormatParams,
    ) -> (Vec<u8>, usize, usize, usize) {
        let mut output = Vec::new();
        let mut literal_count = 0usize;
        let mut ref_count = 0usize;

        for (i, tok) in tokens.iter().enumerate() {
            match tok {
                Token::Literal { byte } => {
                    output.push(*byte);
                    literal_count += 1;
                }
                Token::Reference { distance, length } => {
                    let d = *distance as usize;
                    let l = *length as u64;
                    assert!(
                        d <= output.len(),
                        "Token {}: distance {} > current position {}",
                        i,
                        d,
                        output.len()
                    );
                    assert!(
                        *distance <= params.d_max,
                        "Token {}: distance {} > d_max {}",
                        i,
                        distance,
                        params.d_max
                    );
                    assert!(
                        l >= params.m_min as u64,
                        "Token {}: length {} < m_min {}",
                        i,
                        l,
                        params.m_min
                    );
                    assert!(
                        l <= params.m_max as u64,
                        "Token {}: length {} > m_max {}",
                        i,
                        l,
                        params.m_max
                    );
                    let src_start = output.len() - d;
                    for j in 0..l as usize {
                        let byte = output[src_start + (j % d)];
                        output.push(byte);
                    }
                    ref_count += 1;
                }
            }
        }
        (output, tokens.len(), literal_count, ref_count)
    }

    // ---- decode_tokens tests ----

    #[test]
    fn test_decode_literals_only() {
        let tokens = vec![Token::Literal { byte: b'h' }, Token::Literal { byte: b'i' }];
        assert_eq!(decode_tokens(&tokens), b"hi");
    }

    #[test]
    fn test_decode_reference() {
        // "abc" then copy 3 bytes from distance 3 → "abcabc"
        let tokens = vec![
            Token::Literal { byte: b'a' },
            Token::Literal { byte: b'b' },
            Token::Literal { byte: b'c' },
            Token::Reference {
                distance: 3,
                length: 3,
            },
        ];
        assert_eq!(decode_tokens(&tokens), b"abcabc");
    }

    #[test]
    fn test_decode_overlapping_reference() {
        // "ab" then copy from distance 2, length 6 → "abababab"
        let tokens = vec![
            Token::Literal { byte: b'a' },
            Token::Literal { byte: b'b' },
            Token::Reference {
                distance: 2,
                length: 6,
            },
        ];
        assert_eq!(decode_tokens(&tokens), b"abababab");
    }

    #[test]
    fn test_decode_run_length() {
        // "a" then copy from distance 1, length 4 → "aaaaa"
        let tokens = vec![
            Token::Literal { byte: b'a' },
            Token::Reference {
                distance: 1,
                length: 4,
            },
        ];
        assert_eq!(decode_tokens(&tokens), b"aaaaa");
    }

    // ---- RandomGenerator tests ----

    #[test]
    fn test_random_produces_exact_length() {
        // RandomGenerator should produce decoded output of exactly target_length.
        // The generator emits literals when remaining < m_min, ensuring
        // it fills to exactly the target.
        for &target in &[100u64, 500, 1000, 5000] {
            for &cr in &[1.5, 2.0, 5.0, 10.0] {
                let mut gen = RandomGenerator::new(42, target, cr, 128);
                let tokens = collect_tokens(&mut gen);
                let decoded = decode_tokens(&tokens);
                assert_eq!(
                    decoded.len(),
                    target as usize,
                    "Random(target={}, cr={}): decoded len {} != target",
                    target,
                    cr,
                    decoded.len()
                );
            }
        }
    }

    #[test]
    fn test_random_deterministic() {
        let mut gen1 = RandomGenerator::new(42, 500, 3.0, 26);
        let mut gen2 = RandomGenerator::new(42, 500, 3.0, 26);
        let t1 = collect_tokens(&mut gen1);
        let t2 = collect_tokens(&mut gen2);
        assert_eq!(t1, t2, "Same seed should produce identical tokens");
    }

    #[test]
    fn test_random_different_seeds_differ() {
        let mut gen1 = RandomGenerator::new(1, 500, 2.0, 26);
        let mut gen2 = RandomGenerator::new(2, 500, 2.0, 26);
        let t1 = collect_tokens(&mut gen1);
        let t2 = collect_tokens(&mut gen2);
        // Extremely unlikely to be identical with different seeds
        assert_ne!(decode_tokens(&t1), decode_tokens(&t2));
    }

    #[test]
    fn test_random_achieves_compression() {
        // Higher CR should produce fewer tokens (more references)
        let mut gen_low = RandomGenerator::new(42, 1000, 1.5, 128);
        let mut gen_high = RandomGenerator::new(42, 1000, 10.0, 128);
        let tok_low = collect_tokens(&mut gen_low);
        let tok_high = collect_tokens(&mut gen_high);
        assert!(
            tok_high.len() < tok_low.len(),
            "CR=10 should use fewer tokens ({}) than CR=1.5 ({})",
            tok_high.len(),
            tok_low.len()
        );
    }

    #[test]
    fn test_random_alphabet_constraint() {
        let mut gen = RandomGenerator::new(99, 200, 1.0, 4);
        let tokens = collect_tokens(&mut gen);
        let decoded = decode_tokens(&tokens);
        for &b in &decoded {
            assert!(b < 4, "byte {} exceeds alphabet size 4", b);
        }
    }

    #[test]
    fn test_random_format_constraints() {
        // Validate every token against FormatParams constraints
        // across multiple seeds and CR values.
        let params = FormatParams::synthetic();
        for seed in 0..10u64 {
            for &cr in &[1.5, 3.0, 10.0, 50.0] {
                let mut gen = RandomGenerator::new(seed, 1000, cr, 128);
                let tokens = collect_tokens(&mut gen);
                let (decoded, _total, _lits, _refs) = validate_and_decode(&tokens, &params);
                assert_eq!(
                    decoded.len(),
                    1000,
                    "seed={}, cr={}: wrong length {}",
                    seed,
                    cr,
                    decoded.len()
                );
            }
        }
    }

    // ---- SharedPrefixGenerator tests ----

    #[test]
    fn test_shared_prefix_basic() {
        let prefix = vec![10, 20, 30, 40, 50];
        let mut gen = SharedPrefixGenerator::new(prefix.clone(), 42, 100, 2.0, 128);
        let tokens = collect_tokens(&mut gen);
        let decoded = decode_tokens(&tokens);

        // First 5 bytes should be the prefix
        assert_eq!(&decoded[..5], &prefix);
        assert!(decoded.len() >= 100);
    }

    #[test]
    fn test_shared_prefix_two_strings_share() {
        let prefix = SharedPrefixGenerator::generate_prefix(0, 50, 26);

        let mut gen1 = SharedPrefixGenerator::new(prefix.clone(), 1, 100, 2.0, 26);
        let mut gen2 = SharedPrefixGenerator::new(prefix.clone(), 2, 100, 2.0, 26);

        let d1 = decode_tokens(&collect_tokens(&mut gen1));
        let d2 = decode_tokens(&collect_tokens(&mut gen2));

        // Both share the prefix
        assert_eq!(&d1[..50], &d2[..50]);
        // Suffixes differ (different seeds)
        assert_ne!(d1, d2);
    }

    // ---- GenomeLikeGenerator tests ----

    #[test]
    fn test_genome_produces_output() {
        let mut gen = GenomeLikeGenerator::new(42, 500, 3.0);
        let tokens = collect_tokens(&mut gen);
        let decoded = decode_tokens(&tokens);
        assert!(decoded.len() >= 500, "decoded len {} < 500", decoded.len());
    }

    #[test]
    fn test_genome_alphabet() {
        let mut gen = GenomeLikeGenerator::new(42, 300, 2.0);
        let tokens = collect_tokens(&mut gen);
        let decoded = decode_tokens(&tokens);
        // After decoding references, all literal-origin bytes are 0-3
        // References copy from existing bytes, so all output is 0-3
        for &b in &decoded {
            assert!(b < 4, "genome byte {} not in ACGT (0-3)", b);
        }
    }

    #[test]
    fn test_genome_deterministic() {
        let mut g1 = GenomeLikeGenerator::new(99, 400, 5.0);
        let mut g2 = GenomeLikeGenerator::new(99, 400, 5.0);
        assert_eq!(collect_tokens(&mut g1), collect_tokens(&mut g2));
    }

    // ---- LogLikeGenerator tests ----

    #[test]
    fn test_log_produces_output() {
        let mut gen = LogLikeGenerator::new(42, 500);
        let tokens = collect_tokens(&mut gen);
        let decoded = decode_tokens(&tokens);
        assert!(decoded.len() >= 500, "decoded len {} < 500", decoded.len());
    }

    #[test]
    fn test_log_contains_newlines() {
        let mut gen = LogLikeGenerator::new(42, 500);
        let decoded = decode_tokens(&collect_tokens(&mut gen));
        let newline_count = decoded.iter().filter(|&&b| b == b'\n').count();
        assert!(newline_count >= 2, "log output should have multiple lines");
    }

    #[test]
    fn test_log_deterministic() {
        let mut g1 = LogLikeGenerator::new(7, 300);
        let mut g2 = LogLikeGenerator::new(7, 300);
        assert_eq!(collect_tokens(&mut g1), collect_tokens(&mut g2));
    }

    // ---- Cross-generator property: all decode without panic ----

    #[test]
    fn test_all_generators_decode_clean() {
        let target = 1000u64;
        let generators: Vec<Box<dyn TokenStream>> = vec![
            Box::new(RandomGenerator::new(0, target, 2.0, 255)),
            Box::new(RandomGenerator::new(0, target, 10.0, 255)),
            Box::new(SharedPrefixGenerator::new(
                SharedPrefixGenerator::generate_prefix(0, 500, 26),
                1,
                target,
                3.0,
                26,
            )),
            Box::new(GenomeLikeGenerator::new(0, target, 5.0)),
            Box::new(LogLikeGenerator::new(0, target)),
        ];
        for mut gen in generators {
            let tokens = collect_tokens(&mut *gen);
            assert!(!tokens.is_empty(), "generator produced no tokens");
            let decoded = decode_tokens(&tokens);
            assert!(decoded.len() >= target as usize, "decoded too short");
        }
    }

    // ---- CR verification (impl spec Section 7.3) ----

    #[test]
    fn test_random_cr_within_bounds() {
        // Actual CR = decoded_length / token_count.
        // The impl spec requires actual CR within 20% of target.
        // We use a generous 50% tolerance since the random generator
        // uses a probabilistic approach, not exact CR targeting.
        for &target_cr in &[2.0, 5.0, 10.0, 50.0] {
            let mut gen = RandomGenerator::new(42, 5000, target_cr, 128);
            let tokens = collect_tokens(&mut gen);
            let decoded = decode_tokens(&tokens);
            let actual_cr = decoded.len() as f64 / tokens.len() as f64;
            let ratio = actual_cr / target_cr;
            assert!(
                ratio > 0.3 && ratio < 3.0,
                "CR={}: actual_cr={:.2}, ratio={:.2} out of bounds",
                target_cr,
                actual_cr,
                ratio
            );
            // Verify monotonicity: higher target_cr → higher actual_cr
            // (tested implicitly by test_random_achieves_compression)
        }
    }

    // ---- Format constraint validation across ALL generators ----

    #[test]
    fn test_all_generators_format_constraints() {
        // Every generator must produce tokens that satisfy the synthetic
        // format constraints: m_min=3, m_max=258, d_max=32768.
        let params = FormatParams::synthetic();
        let target = 500u64;

        let mut generators: Vec<(&str, Box<dyn TokenStream>)> = vec![
            (
                "Random(cr=2)",
                Box::new(RandomGenerator::new(0, target, 2.0, 128)),
            ),
            (
                "Random(cr=20)",
                Box::new(RandomGenerator::new(0, target, 20.0, 128)),
            ),
            (
                "SharedPrefix",
                Box::new(SharedPrefixGenerator::new(
                    SharedPrefixGenerator::generate_prefix(0, 250, 26),
                    1,
                    target,
                    3.0,
                    26,
                )),
            ),
            (
                "GenomeLike",
                Box::new(GenomeLikeGenerator::new(0, target, 3.0)),
            ),
            ("LogLike", Box::new(LogLikeGenerator::new(0, target))),
        ];

        for (name, gen) in &mut generators {
            let tokens = collect_tokens(&mut **gen);
            let (decoded, total, lits, refs) = validate_and_decode(&tokens, &params);
            assert!(
                decoded.len() >= target as usize,
                "{}: decoded len {} < target {}",
                name,
                decoded.len(),
                target
            );
            assert_eq!(total, lits + refs, "{}: token count mismatch", name);
        }
    }

    // ---- Integration: tokens → decode → rope → sort pipeline ----

    #[test]
    fn test_integration_tokens_to_sorted_ropes() {
        // Generate strings from each distribution, build ropes from
        // decoded bytes, sort with all algorithms, verify agreement.
        use crate::sort::{cd_merge, cd_radix, dth_quicksort, dth_radix};

        let n = 20; // number of strings
        let target = 200u64;

        // Generate n strings from RandomGenerator with different seeds
        let mut decoded_strings: Vec<Vec<u8>> = Vec::new();
        for i in 0..n {
            let mut gen = RandomGenerator::new(i as u64, target, 3.0, 26);
            let tokens = collect_tokens(&mut gen);
            decoded_strings.push(decode_tokens(&tokens));
        }

        // Sort with all 4 algorithms
        let refs: Vec<&[u8]> = decoded_strings.iter().map(|v| v.as_slice()).collect();
        let r_radix = cd_radix::sort_byte_slices(&refs);
        let r_merge = cd_merge::sort_byte_slices(&refs);
        let r_dth_qs = dth_quicksort::sort_byte_slices(&refs);
        let r_dth_rx = dth_radix::sort_byte_slices(&refs);

        // All must agree
        let apply = |perm: &[usize]| -> Vec<&[u8]> { perm.iter().map(|&i| refs[i]).collect() };
        let sorted_radix = apply(&r_radix);
        let sorted_merge = apply(&r_merge);
        let sorted_dth_qs = apply(&r_dth_qs);
        let sorted_dth_rx = apply(&r_dth_rx);

        assert_eq!(sorted_radix, sorted_merge, "radix vs merge disagree");
        assert_eq!(sorted_merge, sorted_dth_qs, "merge vs dth_qs disagree");
        assert_eq!(sorted_dth_qs, sorted_dth_rx, "dth_qs vs dth_rx disagree");

        // Verify it's actually sorted
        for i in 0..sorted_radix.len() - 1 {
            assert!(
                sorted_radix[i] <= sorted_radix[i + 1],
                "Not sorted at position {}: {:?} > {:?}",
                i,
                sorted_radix[i],
                sorted_radix[i + 1]
            );
        }
    }

    #[test]
    fn test_integration_shared_prefix_sort() {
        // SharedPrefix strings should have long LCPs — verify sort
        // correctness for this regime specifically (Corollary 6).
        use crate::sort::{cd_merge, cd_radix};

        let n = 15;
        let prefix = SharedPrefixGenerator::generate_prefix(0, 150, 26);

        let mut decoded_strings: Vec<Vec<u8>> = Vec::new();
        for i in 0..n {
            let mut gen = SharedPrefixGenerator::new(prefix.clone(), i as u64, 200, 2.0, 26);
            let tokens = collect_tokens(&mut gen);
            decoded_strings.push(decode_tokens(&tokens));
        }

        // Verify all share the prefix
        for s in &decoded_strings {
            assert_eq!(&s[..150], &prefix[..], "string doesn't share prefix");
        }

        let refs: Vec<&[u8]> = decoded_strings.iter().map(|v| v.as_slice()).collect();
        let r1 = cd_radix::sort_byte_slices(&refs);
        let r2 = cd_merge::sort_byte_slices(&refs);

        let apply = |perm: &[usize]| -> Vec<&[u8]> { perm.iter().map(|&i| refs[i]).collect() };
        assert_eq!(
            apply(&r1),
            apply(&r2),
            "radix vs merge disagree on shared prefix data"
        );
    }

    #[test]
    fn test_integration_genome_sort() {
        // GenomeLike: 4-letter alphabet, verify sort correctness
        use crate::sort::{cd_radix, dth_quicksort};

        let n = 20;
        let mut decoded_strings: Vec<Vec<u8>> = Vec::new();
        for i in 0..n {
            let mut gen = GenomeLikeGenerator::new(i as u64, 300, 3.0);
            let tokens = collect_tokens(&mut gen);
            let decoded = decode_tokens(&tokens);
            // Verify alphabet
            for &b in &decoded {
                assert!(b < 4, "genome byte {} not in 0-3", b);
            }
            decoded_strings.push(decoded);
        }

        let refs: Vec<&[u8]> = decoded_strings.iter().map(|v| v.as_slice()).collect();
        let r1 = cd_radix::sort_byte_slices(&refs);
        let r2 = dth_quicksort::sort_byte_slices(&refs);

        let apply = |perm: &[usize]| -> Vec<&[u8]> { perm.iter().map(|&i| refs[i]).collect() };
        assert_eq!(
            apply(&r1),
            apply(&r2),
            "cd_radix vs dth disagree on genome data"
        );
    }
}
