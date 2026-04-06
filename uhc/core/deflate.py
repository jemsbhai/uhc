"""
DEFLATE token extractor (Lemma 9).

Parses raw DEFLATE streams (RFC 1951) to extract LZ77 Lit/Ref tokens
without decompressing to raw bytes. This satisfies conditions C1 and C2
(Definition 9):

  C1 — Token extractability: Huffman-coded symbols are decoded to produce
       Lit(c) and Ref(d, l) tokens directly.
  C2 — Semantic compatibility: Back-reference semantics match Definition 5
       (byte-by-byte copy with wrap-around for overlapping references).

DEFLATE format parameters (Definition 8):
    m_min = 3, m_max = 258, d_max = 32768, E = Huffman
"""

from __future__ import annotations

from uhc.core.lz77 import Token, Literal, Reference


# ---------------------------------------------------------------------------
# Bitstream reader
# ---------------------------------------------------------------------------


class _BitReader:
    """Read bits from a byte stream, LSB first (DEFLATE convention)."""

    __slots__ = ("_data", "_pos", "_bit", "_len")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0      # current byte index
        self._bit = 0       # current bit within byte (0-7)
        self._len = len(data)

    def read_bits(self, n: int) -> int:
        """Read n bits, LSB first. Returns integer value."""
        result = 0
        for i in range(n):
            if self._pos >= self._len:
                raise ValueError("Unexpected end of DEFLATE stream")
            bit = (self._data[self._pos] >> self._bit) & 1
            result |= bit << i
            self._bit += 1
            if self._bit == 8:
                self._bit = 0
                self._pos += 1
        return result

    def align_to_byte(self) -> None:
        """Advance to next byte boundary."""
        if self._bit > 0:
            self._bit = 0
            self._pos += 1

    def read_bytes(self, n: int) -> bytes:
        """Read n bytes (must be byte-aligned)."""
        assert self._bit == 0
        if self._pos + n > self._len:
            raise ValueError("Unexpected end of DEFLATE stream")
        result = self._data[self._pos:self._pos + n]
        self._pos += n
        return result

    @property
    def exhausted(self) -> bool:
        return self._pos >= self._len and self._bit == 0


# ---------------------------------------------------------------------------
# Huffman decoder
# ---------------------------------------------------------------------------


class _HuffmanTable:
    """
    Huffman decoding table built from code lengths.

    Uses a simple lookup: for each (code_length, code_value) pair,
    store the symbol. Decoding reads bits one at a time and traverses.
    For performance we use a flat array indexed by code length.
    """

    __slots__ = ("_min_len", "_max_len", "_symbols_by_code",)

    def __init__(self, code_lengths: list[int]) -> None:
        """
        Build Huffman table from per-symbol code lengths.

        code_lengths[i] = length of code for symbol i (0 = not used).
        Algorithm from RFC 1951 Section 3.2.2.
        """
        max_bits = max(code_lengths) if code_lengths and max(code_lengths) > 0 else 0
        if max_bits == 0:
            self._min_len = 0
            self._max_len = 0
            self._symbols_by_code = {}
            return

        # Step 1: count codes per length
        bl_count = [0] * (max_bits + 1)
        for length in code_lengths:
            if length > 0:
                bl_count[length] += 1

        # Step 2: compute first code for each length
        code = 0
        next_code = [0] * (max_bits + 1)
        for bits in range(1, max_bits + 1):
            code = (code + bl_count[bits - 1]) << 1
            next_code[bits] = code

        # Step 3: assign codes to symbols
        # Map: (length, code) -> symbol
        self._symbols_by_code: dict[tuple[int, int], int] = {}
        self._min_len = max_bits
        self._max_len = 0

        for symbol, length in enumerate(code_lengths):
            if length > 0:
                self._symbols_by_code[(length, next_code[length])] = symbol
                next_code[length] += 1
                self._min_len = min(self._min_len, length)
                self._max_len = max(self._max_len, length)

    def decode(self, reader: _BitReader) -> int:
        """Decode one symbol from the bitstream."""
        code = 0
        for length in range(1, self._max_len + 1):
            # DEFLATE Huffman codes are read MSB first within each code,
            # but the bitstream itself is LSB-first per byte.
            # We read one bit at a time and build the code MSB-first.
            code = (code << 1) | reader.read_bits(1)
            if length >= self._min_len:
                key = (length, code)
                if key in self._symbols_by_code:
                    return self._symbols_by_code[key]

        raise ValueError(f"Invalid Huffman code (reached max length {self._max_len})")


# ---------------------------------------------------------------------------
# Fixed Huffman tables (RFC 1951 Section 3.2.6)
# ---------------------------------------------------------------------------

def _build_fixed_lit_lengths() -> list[int]:
    """Fixed literal/length code lengths per RFC 1951."""
    lengths = [0] * 288
    for i in range(0, 144):
        lengths[i] = 8
    for i in range(144, 256):
        lengths[i] = 9
    for i in range(256, 280):
        lengths[i] = 7
    for i in range(280, 288):
        lengths[i] = 8
    return lengths


def _build_fixed_dist_lengths() -> list[int]:
    """Fixed distance code lengths per RFC 1951."""
    return [5] * 32


_FIXED_LIT_TABLE: _HuffmanTable | None = None
_FIXED_DIST_TABLE: _HuffmanTable | None = None


def _get_fixed_tables() -> tuple[_HuffmanTable, _HuffmanTable]:
    global _FIXED_LIT_TABLE, _FIXED_DIST_TABLE
    if _FIXED_LIT_TABLE is None:
        _FIXED_LIT_TABLE = _HuffmanTable(_build_fixed_lit_lengths())
        _FIXED_DIST_TABLE = _HuffmanTable(_build_fixed_dist_lengths())
    return _FIXED_LIT_TABLE, _FIXED_DIST_TABLE


# ---------------------------------------------------------------------------
# Length and distance decoding tables (RFC 1951 Section 3.2.5)
# ---------------------------------------------------------------------------

# Length codes 257-285 → (base_length, extra_bits)
_LENGTH_TABLE: list[tuple[int, int]] = [
    (3, 0), (4, 0), (5, 0), (6, 0), (7, 0), (8, 0), (9, 0), (10, 0),  # 257-264
    (11, 1), (13, 1), (15, 1), (17, 1),                                  # 265-268
    (19, 2), (23, 2), (27, 2), (31, 2),                                  # 269-272
    (35, 3), (43, 3), (51, 3), (59, 3),                                  # 273-276
    (67, 4), (83, 4), (99, 4), (115, 4),                                 # 277-280
    (131, 5), (163, 5), (195, 5), (227, 5),                              # 281-284
    (258, 0),                                                              # 285
]

# Distance codes 0-29 → (base_distance, extra_bits)
_DISTANCE_TABLE: list[tuple[int, int]] = [
    (1, 0), (2, 0), (3, 0), (4, 0),
    (5, 1), (7, 1),
    (9, 2), (13, 2),
    (17, 3), (25, 3),
    (33, 4), (49, 4),
    (65, 5), (97, 5),
    (129, 6), (193, 6),
    (257, 7), (385, 7),
    (513, 8), (769, 8),
    (1025, 9), (1537, 9),
    (2049, 10), (3073, 10),
    (4097, 11), (6145, 11),
    (8193, 12), (12289, 12),
    (16385, 13), (24577, 13),
]


def _decode_length(symbol: int, reader: _BitReader) -> int:
    """Decode match length from length symbol 257-285."""
    idx = symbol - 257
    base, extra = _LENGTH_TABLE[idx]
    if extra > 0:
        return base + reader.read_bits(extra)
    return base


def _decode_distance(dist_symbol: int, reader: _BitReader) -> int:
    """Decode distance from distance symbol 0-29."""
    base, extra = _DISTANCE_TABLE[dist_symbol]
    if extra > 0:
        return base + reader.read_bits(extra)
    return base


# ---------------------------------------------------------------------------
# Dynamic Huffman table decoding (RFC 1951 Section 3.2.7)
# ---------------------------------------------------------------------------

# Code length alphabet order
_CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


def _decode_dynamic_tables(reader: _BitReader) -> tuple[_HuffmanTable, _HuffmanTable]:
    """Read and build dynamic Huffman tables from the stream."""
    hlit = reader.read_bits(5) + 257    # number of literal/length codes
    hdist = reader.read_bits(5) + 1     # number of distance codes
    hclen = reader.read_bits(4) + 4     # number of code length codes

    # Read code length code lengths
    cl_lengths = [0] * 19
    for i in range(hclen):
        cl_lengths[_CL_ORDER[i]] = reader.read_bits(3)

    cl_table = _HuffmanTable(cl_lengths)

    # Decode literal/length + distance code lengths
    total = hlit + hdist
    lengths: list[int] = []

    while len(lengths) < total:
        sym = cl_table.decode(reader)
        if sym < 16:
            lengths.append(sym)
        elif sym == 16:
            # Repeat previous length 3-6 times
            repeat = 3 + reader.read_bits(2)
            prev = lengths[-1] if lengths else 0
            lengths.extend([prev] * repeat)
        elif sym == 17:
            # Repeat 0 for 3-10 times
            repeat = 3 + reader.read_bits(3)
            lengths.extend([0] * repeat)
        elif sym == 18:
            # Repeat 0 for 11-138 times
            repeat = 11 + reader.read_bits(7)
            lengths.extend([0] * repeat)
        else:
            raise ValueError(f"Invalid code length symbol: {sym}")

    # Truncate if run-length produced excess
    lengths = lengths[:total]

    lit_lengths = lengths[:hlit]
    dist_lengths = lengths[hlit:hlit + hdist]

    lit_table = _HuffmanTable(lit_lengths)
    dist_table = _HuffmanTable(dist_lengths)

    return lit_table, dist_table


# ---------------------------------------------------------------------------
# Main extractor (Lemma 9)
# ---------------------------------------------------------------------------


def deflate_extract_tokens(compressed: bytes) -> list[Token]:
    """
    Parse a raw DEFLATE stream (RFC 1951) and extract LZ77 tokens.

    Satisfies conditions C1 and C2 (Definition 9):
    - C1: Tokens are extracted by sequential Huffman decoding.
    - C2: Ref(d, l) semantics match Definition 5.

    Parameters
    ----------
    compressed : bytes
        Raw DEFLATE stream (no zlib/gzip header).

    Returns
    -------
    list[Token]
        Sequence of Literal and Reference tokens.
    """
    reader = _BitReader(compressed)
    tokens: list[Token] = []

    while True:
        bfinal = reader.read_bits(1)
        btype = reader.read_bits(2)

        if btype == 0:
            # Stored block (no compression)
            _parse_stored_block(reader, tokens)
        elif btype == 1:
            # Fixed Huffman
            lit_table, dist_table = _get_fixed_tables()
            _parse_compressed_block(reader, lit_table, dist_table, tokens)
        elif btype == 2:
            # Dynamic Huffman
            lit_table, dist_table = _decode_dynamic_tables(reader)
            _parse_compressed_block(reader, lit_table, dist_table, tokens)
        else:
            raise ValueError(f"Invalid DEFLATE block type: {btype}")

        if bfinal:
            break

    return tokens


def _parse_stored_block(reader: _BitReader, tokens: list[Token]) -> None:
    """Parse a stored (uncompressed) DEFLATE block."""
    reader.align_to_byte()
    length = int.from_bytes(reader.read_bytes(2), "little")
    nlength = int.from_bytes(reader.read_bytes(2), "little")
    if length != (~nlength & 0xFFFF):
        raise ValueError(f"Stored block length check failed: {length} vs {nlength}")

    data = reader.read_bytes(length)
    for byte in data:
        tokens.append(Literal(byte))


def _parse_compressed_block(
    reader: _BitReader,
    lit_table: _HuffmanTable,
    dist_table: _HuffmanTable,
    tokens: list[Token],
) -> None:
    """Parse a Huffman-compressed DEFLATE block."""
    while True:
        symbol = lit_table.decode(reader)

        if symbol < 256:
            # Literal byte
            tokens.append(Literal(symbol))
        elif symbol == 256:
            # End of block
            break
        else:
            # Length/distance pair (symbol 257-285)
            if symbol > 285:
                raise ValueError(f"Invalid literal/length symbol: {symbol}")
            length = _decode_length(symbol, reader)
            dist_symbol = dist_table.decode(reader)
            distance = _decode_distance(dist_symbol, reader)
            tokens.append(Reference(distance=distance, length=length))
