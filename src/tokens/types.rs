//! LZ77 token types and stream trait.

/// A single LZ77 token: either a literal byte or a back-reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// A literal byte value.
    Literal { byte: u8 },
    /// A back-reference: copy `length` bytes from `distance` bytes back.
    Reference { distance: u32, length: u32 },
}

/// Format-specific parameters constraining token values.
#[derive(Clone, Debug)]
pub struct FormatParams {
    /// Minimum match length.
    pub m_min: u32,
    /// Maximum match length (u32::MAX for unbounded, e.g., LZ4).
    pub m_max: u32,
    /// Maximum back-reference distance.
    pub d_max: u32,
    /// Format name for logging.
    pub name: &'static str,
}

impl FormatParams {
    pub fn deflate() -> Self {
        FormatParams {
            m_min: 3,
            m_max: 258,
            d_max: 32768,
            name: "DEFLATE",
        }
    }

    pub fn lz4() -> Self {
        FormatParams {
            m_min: 4,
            m_max: u32::MAX,
            d_max: 65535,
            name: "LZ4",
        }
    }

    pub fn zstandard() -> Self {
        FormatParams {
            m_min: 3,
            m_max: 131074,
            d_max: 134_217_728,
            name: "Zstandard",
        }
    }

    pub fn synthetic() -> Self {
        FormatParams {
            m_min: 3,
            m_max: 258,
            d_max: 32768,
            name: "Synthetic",
        }
    }
}

/// Trait for token stream sources.
pub trait TokenStream {
    /// Return the next token, or None if the stream is exhausted.
    fn next_token(&mut self) -> Option<Token>;

    /// Format parameters for this stream.
    fn format_params(&self) -> &FormatParams;
}
