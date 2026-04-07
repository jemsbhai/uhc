"""
Zstandard token extractor (Lemma 11).

Parses Zstandard frames (RFC 8878) to extract LZ77 Lit/Ref tokens
without decompressing to raw bytes. Satisfies conditions C1 and C2
(Definition 9):

  C1 — Token extractability: FSE/Huffman-coded symbols are decoded to
       produce Lit(c) and Ref(d, l) tokens directly.
  C2 — Semantic compatibility: Back-reference semantics match Definition 5
       (byte-by-byte copy with wrap-around for overlapping references).

Zstandard format parameters (Definition 8):
    m_min = 3, m_max = 131074, d_max = 2^27, E = FSE+Huffman

Implementation covers:
    - Frame header parsing (magic, window descriptor, FCS)
    - Block types: Raw, RLE, Compressed
    - Literals: Raw, RLE, Compressed (Huffman), Treeless
    - Sequences: FSE-encoded (literal_length, offset, match_length) triples
    - Predefined, RLE, FSE_Compressed, and Repeat compression modes
    - Repeat-offset cache with special handling for literals_length == 0
    - Multi-stream (4-stream) Huffman literal decoding
"""

from __future__ import annotations

import struct
from typing import Optional

from uhc.core.lz77 import Token, Literal, Reference


# ===================================================================
# Constants
# ===================================================================

ZSTD_MAGIC = 0xFD2FB528

_PREDEFINED = 0
_RLE = 1
_FSE_COMPRESSED = 2
_REPEAT = 3

_RAW_LITERALS = 0
_RLE_LITERALS = 1
_COMPRESSED_LITERALS = 2
_TREELESS_LITERALS = 3

# ---------------------------------------------------------------------------
# Baseline / extra-bits tables (spec Section 3.1.1.3.2.1)
# ---------------------------------------------------------------------------

_LL_BASELINE = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512,
    1024, 2048, 4096, 8192, 16384, 32768, 65536,
]
_LL_EXTRA = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16,
]

_ML_BASELINE = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515,
    1027, 2051, 4099, 8195, 16387, 32771, 65539,
]
_ML_EXTRA = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
]

# ---------------------------------------------------------------------------
# Default FSE distributions (spec Section 3.1.1.3.2.2)
# ---------------------------------------------------------------------------

_LL_DEFAULT_DIST = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
]
_LL_DEFAULT_AL = 6

_ML_DEFAULT_DIST = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1,
]
_ML_DEFAULT_AL = 6

_OF_DEFAULT_DIST = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
]
_OF_DEFAULT_AL = 5


# ===================================================================
# Forward bit reader (for FSE table descriptions)
# ===================================================================

class _ForwardBitReader:
    __slots__ = ("_data", "_byte_pos", "_bit_pos", "_start_pos")

    def __init__(self, data: bytes, byte_offset: int = 0):
        self._data = data
        self._byte_pos = byte_offset
        self._bit_pos = 0
        self._start_pos = byte_offset

    def read(self, n: int) -> int:
        if n == 0:
            return 0
        result = 0
        bits_read = 0
        while bits_read < n:
            if self._byte_pos >= len(self._data):
                return result
            byte = self._data[self._byte_pos]
            avail = 8 - self._bit_pos
            need = n - bits_read
            take = min(avail, need)
            bits = (byte >> self._bit_pos) & ((1 << take) - 1)
            result |= bits << bits_read
            bits_read += take
            self._bit_pos += take
            if self._bit_pos >= 8:
                self._bit_pos = 0
                self._byte_pos += 1
        return result

    def bytes_consumed(self) -> int:
        return (self._byte_pos - self._start_pos) + (1 if self._bit_pos > 0 else 0)


# ===================================================================
# Reverse bit reader (for FSE sequence bitstreams)
# ===================================================================

class _ReverseBitReader:
    """
    Read bits from a reverse bitstream (used for FSE sequence decoding).
    The last byte contains a sentinel '1' bit followed by padding.
    Reads from high bit positions downward.
    """

    __slots__ = ("_val", "_pos")

    def __init__(self, data: bytes):
        if not data:
            self._val = 0
            self._pos = -1
            return
        self._val = int.from_bytes(data, "little")
        bl = self._val.bit_length()
        if bl == 0:
            raise ValueError("Reverse bitstream: last byte cannot be 0")
        self._val ^= 1 << (bl - 1)
        self._pos = bl - 2

    def read(self, n: int) -> int:
        """Read n bits from high to low. Pads with 0 if insufficient."""
        if n == 0:
            return 0
        avail = self._pos + 1
        if avail >= n:
            self._pos -= n
            return (self._val >> (self._pos + 1)) & ((1 << n) - 1)
        if avail > 0:
            val = self._val & ((1 << avail) - 1)
            self._pos = -1
            return val << (n - avail)
        self._pos = -1
        return 0

    @property
    def remaining(self) -> int:
        return max(self._pos + 1, 0)


# ===================================================================
# LE bit reader for Huffman streams
# ===================================================================

def _read_bits_le(src: bytes, num_bits: int, offset: int) -> int:
    """
    Read num_bits from src starting at bit position offset, in LE order.
    Bit 0 = LSB of src[0]. Returns the value with bit at 'offset' as LSB.
    Matches the C reference decoder's read_bits_LE.
    """
    if num_bits == 0:
        return 0
    if offset < 0:
        offset = 0
    byte_off = offset >> 3
    bit_off = offset & 7
    # Read enough bytes
    need_bytes = (bit_off + num_bits + 7) >> 3
    val = 0
    for i in range(need_bytes):
        idx = byte_off + i
        if idx < len(src):
            val |= src[idx] << (8 * i)
    val >>= bit_off
    val &= (1 << num_bits) - 1
    return val


# ===================================================================
# FSE table construction
# ===================================================================

class _FSEEntry:
    __slots__ = ("symbol", "num_bits", "baseline")

    def __init__(self, symbol: int, num_bits: int, baseline: int):
        self.symbol = symbol
        self.num_bits = num_bits
        self.baseline = baseline


def _build_fse_table(distribution: list[int], accuracy_log: int) -> list[_FSEEntry]:
    table_size = 1 << accuracy_log
    high_threshold = table_size - 1
    table_symbol = [0] * table_size

    for s, p in enumerate(distribution):
        if p == -1:
            table_symbol[high_threshold] = s
            high_threshold -= 1

    step = (table_size >> 1) + (table_size >> 3) + 3
    mask = table_size - 1
    position = 0

    for s, p in enumerate(distribution):
        if p <= 0:
            continue
        for _ in range(p):
            table_symbol[position] = s
            position = (position + step) & mask
            while position > high_threshold:
                position = (position + step) & mask

    symbol_next = {}
    for s, p in enumerate(distribution):
        if p == -1:
            symbol_next[s] = 1
        elif p > 0:
            symbol_next[s] = p

    table = [None] * table_size
    for i in range(table_size):
        s = table_symbol[i]
        x = symbol_next[s]
        symbol_next[s] = x + 1
        nb = accuracy_log - (x.bit_length() - 1)
        new_state = (x << nb) - table_size
        table[i] = _FSEEntry(s, nb, new_state)

    return table


def _decode_fse_distribution(reader: _ForwardBitReader,
                              max_accuracy_log: int) -> tuple[list[int], int]:
    accuracy_log = reader.read(4) + 5
    if accuracy_log > max_accuracy_log:
        raise ValueError(f"AL {accuracy_log} > max {max_accuracy_log}")

    remaining = 1 << accuracy_log
    distribution = []

    while remaining > 0:
        max_val = remaining + 1
        bits_needed = max_val.bit_length()
        # Match C reference educational decoder (zstd_decompress.c
        # FSE_decode_header lines 2238-2252):
        #   lower_mask = (1 << (bits-1)) - 1
        #   threshold  = (1 << bits) - 1 - (remaining + 1)
        #   short:  (val & lower_mask) < threshold  -> rewind 1 bit
        #   long:   val > lower_mask                -> val -= threshold
        #   middle: val stays, all bits consumed
        half = 1 << (bits_needed - 1)
        threshold = (2 * half - 1) - (remaining + 1)

        low = reader.read(bits_needed - 1)
        if low < threshold:
            count = low
        else:
            extra = reader.read(1)
            if extra:
                # Long path: val = low + half, count = val - threshold
                count = low + half - threshold
            else:
                # Middle path: val = low, all bits consumed
                count = low

        prob = count - 1

        if prob == 0:
            distribution.append(0)
            while True:
                repeat = reader.read(2)
                for _ in range(repeat):
                    distribution.append(0)
                if repeat < 3:
                    break
        else:
            distribution.append(prob)
            if prob == -1:
                remaining -= 1
            else:
                remaining -= prob

    return distribution, accuracy_log


# ===================================================================
# Huffman decoding (LE bit-order, matching zstd reference decoder)
# ===================================================================

def _build_huffman_decode_info(weights: list[int]):
    """
    Build Huffman decoding table using rank-based fill.

    Matches the C reference decoder's HUF_init_dtable_usingweights:
    symbols are iterated in natural order (NOT sorted), and each symbol
    is assigned the next available table range for its bit length.

    The table is indexed by peeking max_bits from the bitstream where
    the MSB of the lookup corresponds to the current stream position.
    Longest codes occupy the lowest table indices.

    Returns (table_sym, table_bits, max_bits).
    """
    # Find the LARGEST valid prefix (FSE may produce extra garbage weights)
    best_n = None
    for n in range(len(weights), 0, -1):
        ws = sum(1 << (w - 1) for w in weights[:n] if w > 0)
        if ws == 0:
            continue
        mb = ws.bit_length()
        t = 1 << mb
        rem = t - ws
        if rem > 0 and (rem & (rem - 1)) == 0 and mb <= 11:
            best_n = n
            break

    if best_n is None:
        raise ValueError("No valid Huffman tree prefix found")

    weights = weights[:best_n]
    weight_sum = sum(1 << (w - 1) for w in weights if w > 0)

    max_bits = weight_sum.bit_length()
    total = 1 << max_bits
    last_weight_val = total - weight_sum

    last_weight = last_weight_val.bit_length()
    if (1 << (last_weight - 1)) != last_weight_val:
        raise ValueError("Invalid last weight")

    all_weights = list(weights) + [last_weight]
    num_symbs = len(all_weights)

    if max_bits > 11:
        raise ValueError(f"Max bits {max_bits} > 11")

    # Convert weights to number of bits: bits[i] = max_bits + 1 - weight[i]
    bits = [0] * num_symbs
    for i, w in enumerate(all_weights):
        if w > 0:
            bits[i] = max_bits + 1 - w

    # Count symbols per bit length
    rank_count = [0] * (max_bits + 1)
    for b in bits:
        if b > 0:
            rank_count[b] += 1

    # Build rank_idx: starting table index for each bit length.
    # Longest codes (max_bits) start at index 0.
    # Shorter codes come after, each occupying stride = 1 << (max_bits - b).
    rank_idx = [0] * (max_bits + 1)
    rank_idx[max_bits] = 0
    for i in range(max_bits, 0, -1):
        rank_idx[i - 1] = rank_idx[i] + rank_count[i] * (1 << (max_bits - i))

    if rank_idx[0] != total:
        raise ValueError(
            f"Huffman table corruption: rank_idx[0]={rank_idx[0]} != {total}"
        )

    # Fill num_bits for each rank's range
    table_sym = [-1] * total
    table_bits = [0] * total

    for i in range(max_bits, 0, -1):
        start = rank_idx[i]
        end = start + rank_count[i] * (1 << (max_bits - i))
        for j in range(start, end):
            table_bits[j] = i

    # Reset rank_idx for symbol assignment pass
    rank_idx[max_bits] = 0
    for i in range(max_bits, 0, -1):
        rank_idx[i - 1] = rank_idx[i] + rank_count[i] * (1 << (max_bits - i))

    # Fill table: iterate symbols in NATURAL ORDER (matching C reference)
    for sym in range(num_symbs):
        nb = bits[sym]
        if nb == 0:
            continue
        code = rank_idx[nb]
        length = 1 << (max_bits - nb)
        for x in range(length):
            table_sym[code + x] = sym
        rank_idx[nb] += length

    return table_sym, table_bits, max_bits


def _decode_huffman_tree(data: bytes, offset: int):
    """
    Decode Huffman tree description.
    Returns (table_sym, table_bits, max_bits, bytes_consumed).
    """
    header_byte = data[offset]

    if header_byte >= 128:
        # Direct representation: each weight is 4 bits
        num_weights = header_byte - 127
        weights = []
        pos = offset + 1
        for i in range(num_weights):
            byte_idx = pos + (i // 2)
            if i % 2 == 0:
                weights.append((data[byte_idx] >> 4) & 0xF)
            else:
                weights.append(data[byte_idx] & 0xF)
        bytes_consumed = 1 + (num_weights + 1) // 2
        table_sym, table_bits, max_bits = _build_huffman_decode_info(weights)
        return table_sym, table_bits, max_bits, bytes_consumed

    # FSE-compressed weights
    compressed_size = header_byte
    if compressed_size == 0:
        raise ValueError("Huffman FSE size is 0")

    fse_data = data[offset + 1: offset + 1 + compressed_size]
    fse_reader = _ForwardBitReader(fse_data)
    dist, al = _decode_fse_distribution(fse_reader, max_accuracy_log=7)
    fse_table = _build_fse_table(dist, al)

    fse_header_bytes = fse_reader.bytes_consumed()
    weight_stream = fse_data[fse_header_bytes:]  # Only bytes after FSE header

    if not weight_stream:
        raise ValueError("Empty weight bitstream")

    rbr = _ReverseBitReader(weight_stream)
    state1 = rbr.read(al)
    state2 = rbr.read(al)

    weights = []
    while len(weights) < 255:
        e1 = fse_table[state1]
        weights.append(e1.symbol)
        if len(weights) >= 255:
            break

        prev_remaining = rbr.remaining
        state1 = e1.baseline + rbr.read(e1.num_bits)
        if e1.num_bits > 0 and prev_remaining < e1.num_bits:
            e2 = fse_table[state2]
            weights.append(e2.symbol)
            break

        e2 = fse_table[state2]
        weights.append(e2.symbol)
        if len(weights) >= 255:
            break

        prev_remaining = rbr.remaining
        state2 = e2.baseline + rbr.read(e2.num_bits)
        if e2.num_bits > 0 and prev_remaining < e2.num_bits:
            break

    while weights and weights[-1] == 0:
        weights.pop()

    bytes_consumed = 1 + compressed_size
    table_sym, table_bits, max_bits = _build_huffman_decode_info(weights)
    return table_sym, table_bits, max_bits, bytes_consumed


def _huf_decode_stream(data: bytes, num_symbols: int,
                       table_sym: list[int], table_bits: list[int],
                       max_bits: int) -> bytes:
    """
    Decode num_symbols from a Huffman reverse bitstream using LE reads.

    Matches the C reference decoder: read max_bits from current offset
    upward (LE order), look up in table, advance offset by actual bits.
    """
    if num_symbols == 0 or not data:
        return b""

    # Find the sentinel bit to determine the starting offset
    val = int.from_bytes(data, "little")
    bl = val.bit_length()
    if bl == 0:
        return b""
    # Starting offset is one below the sentinel
    offset = bl - 2

    result = bytearray(num_symbols)
    for i in range(num_symbols):
        if offset < 0:
            break
        # Read max_bits from offset going upward (LE)
        bits_start = offset - max_bits + 1
        if bits_start < 0:
            # Read available bits and left-shift to MSB-align with table
            lookup = _read_bits_le(data, offset + 1, 0) << (-bits_start)
        else:
            lookup = _read_bits_le(data, max_bits, bits_start)

        sym = table_sym[lookup]
        actual = table_bits[lookup]
        offset -= actual
        result[i] = sym

    return bytes(result)


# ===================================================================
# Frame and block parsing
# ===================================================================

def _parse_frame_header(data: bytes, pos: int):
    magic = struct.unpack_from("<I", data, pos)[0]
    if magic != ZSTD_MAGIC:
        raise ValueError(f"Bad magic: 0x{magic:08X}")
    pos += 4

    fhd = data[pos]
    pos += 1

    fcs_flag = (fhd >> 6) & 3
    single_segment = (fhd >> 5) & 1
    content_checksum = (fhd >> 2) & 1
    dict_id_flag = fhd & 3

    if single_segment:
        window_size = None
    else:
        wd = data[pos]
        pos += 1
        exponent = (wd >> 3) & 0x1F
        mantissa = wd & 0x07
        window_log = 10 + exponent
        window_base = 1 << window_log
        window_add = (window_base // 8) * mantissa
        window_size = window_base + window_add

    did_size = [0, 1, 2, 4][dict_id_flag]
    pos += did_size

    if fcs_flag == 0:
        fcs_field_size = 1 if single_segment else 0
    else:
        fcs_field_size = [0, 2, 4, 8][fcs_flag]

    fcs = None
    if fcs_field_size == 1:
        fcs = data[pos]
    elif fcs_field_size == 2:
        fcs = struct.unpack_from("<H", data, pos)[0] + 256
    elif fcs_field_size == 4:
        fcs = struct.unpack_from("<I", data, pos)[0]
    elif fcs_field_size == 8:
        fcs = struct.unpack_from("<Q", data, pos)[0]
    pos += fcs_field_size

    if window_size is None:
        window_size = fcs if fcs is not None else 0

    return pos, window_size, fcs, content_checksum


# ===================================================================
# Literals section
# ===================================================================

def _decode_literals(data: bytes, pos: int, prev_huf):
    byte0 = data[pos]
    block_type = byte0 & 3

    if block_type in (_RAW_LITERALS, _RLE_LITERALS):
        size_format = (byte0 >> 2) & 3
        if size_format in (0, 2):
            regen_size = byte0 >> 3
            hdr = 1
        elif size_format == 1:
            regen_size = (byte0 >> 4) | (data[pos + 1] << 4)
            hdr = 2
        else:
            regen_size = ((byte0 >> 4) | (data[pos + 1] << 4)
                          | (data[pos + 2] << 12))
            hdr = 3

        if block_type == _RAW_LITERALS:
            lits = data[pos + hdr: pos + hdr + regen_size]
            return lits, pos + hdr + regen_size, prev_huf
        else:
            lits = bytes([data[pos + hdr]]) * regen_size
            return lits, pos + hdr + 1, prev_huf

    # Compressed or Treeless
    size_format = (byte0 >> 2) & 3
    if size_format == 0:
        v = int.from_bytes(data[pos:pos + 3], "little")
        regen_size = (v >> 4) & 0x3FF
        comp_size = (v >> 14) & 0x3FF
        num_streams = 1
        hdr = 3
    elif size_format == 1:
        v = int.from_bytes(data[pos:pos + 3], "little")
        regen_size = (v >> 4) & 0x3FF
        comp_size = (v >> 14) & 0x3FF
        num_streams = 4
        hdr = 3
    elif size_format == 2:
        v = int.from_bytes(data[pos:pos + 4], "little")
        regen_size = (v >> 4) & 0x3FFF
        comp_size = (v >> 18) & 0x3FFF
        num_streams = 4
        hdr = 4
    else:
        v = int.from_bytes(data[pos:pos + 5], "little")
        regen_size = (v >> 4) & 0x3FFFF
        comp_size = (v >> 22) & 0x3FFFF
        num_streams = 4
        hdr = 5

    huf_start = pos + hdr
    huf_state = prev_huf

    if block_type == _COMPRESSED_LITERALS:
        ts, tb, mb, tree_bytes = _decode_huffman_tree(data, huf_start)
        huf_state = (ts, tb, mb)
        stream_start = huf_start + tree_bytes
        stream_size = comp_size - tree_bytes
    else:
        if prev_huf is None:
            raise ValueError("Treeless without previous Huffman tree")
        ts, tb, mb = prev_huf
        stream_start = huf_start
        stream_size = comp_size

    stream_data = data[stream_start: stream_start + stream_size]

    if num_streams == 1:
        lits = _huf_decode_stream(stream_data, regen_size, ts, tb, mb)
    else:
        if len(stream_data) < 6:
            raise ValueError("4-stream: not enough for jump table")
        s1_sz = struct.unpack_from("<H", stream_data, 0)[0]
        s2_sz = struct.unpack_from("<H", stream_data, 2)[0]
        s3_sz = struct.unpack_from("<H", stream_data, 4)[0]
        s4_sz = len(stream_data) - 6 - s1_sz - s2_sz - s3_sz

        per = (regen_size + 3) // 4
        n1 = min(per, regen_size)
        n2 = min(per, regen_size - n1)
        n3 = min(per, regen_size - n1 - n2)
        n4 = regen_size - n1 - n2 - n3

        b = 6
        d1 = _huf_decode_stream(stream_data[b:b + s1_sz], n1, ts, tb, mb)
        b += s1_sz
        d2 = _huf_decode_stream(stream_data[b:b + s2_sz], n2, ts, tb, mb)
        b += s2_sz
        d3 = _huf_decode_stream(stream_data[b:b + s3_sz], n3, ts, tb, mb)
        b += s3_sz
        d4 = _huf_decode_stream(stream_data[b:b + s4_sz], n4, ts, tb, mb)
        lits = d1 + d2 + d3 + d4

    return lits, huf_start + comp_size, huf_state


# ===================================================================
# Sequences section
# ===================================================================

def _decode_sequences(data: bytes, pos: int, block_end: int,
                      literals: bytes,
                      prev_ll, prev_of, prev_ml,
                      repeat_offsets: list[int]):
    if pos >= block_end:
        tokens = [Literal(b) for b in literals]
        return tokens, pos, prev_ll, prev_of, prev_ml, repeat_offsets

    byte0 = data[pos]
    pos += 1
    if byte0 < 128:
        num_seq = byte0
    elif byte0 < 255:
        num_seq = ((byte0 - 128) << 8) + data[pos]
        pos += 1
    else:
        num_seq = data[pos] + (data[pos + 1] << 8) + 0x7F00
        pos += 2

    if num_seq == 0:
        tokens = [Literal(b) for b in literals]
        return tokens, pos, prev_ll, prev_of, prev_ml, repeat_offsets

    mode_byte = data[pos]
    pos += 1
    ll_mode = (mode_byte >> 6) & 3
    of_mode = (mode_byte >> 4) & 3
    ml_mode = (mode_byte >> 2) & 3

    def resolve(mode, default_dist, default_al, prev, max_al):
        nonlocal pos
        if mode == _PREDEFINED:
            return _build_fse_table(default_dist, default_al), default_al
        elif mode == _RLE:
            sym = data[pos]
            pos += 1
            return [_FSEEntry(sym, 0, 0)], 0
        elif mode == _FSE_COMPRESSED:
            rdr = _ForwardBitReader(data, pos)
            dist, al = _decode_fse_distribution(rdr, max_al)
            pos += rdr.bytes_consumed()
            return _build_fse_table(dist, al), al
        else:  # REPEAT
            if prev is None:
                raise ValueError("Repeat mode without previous table")
            return prev

    ll_info = resolve(ll_mode, _LL_DEFAULT_DIST, _LL_DEFAULT_AL, prev_ll, 9)
    of_info = resolve(of_mode, _OF_DEFAULT_DIST, _OF_DEFAULT_AL, prev_of, 8)
    ml_info = resolve(ml_mode, _ML_DEFAULT_DIST, _ML_DEFAULT_AL, prev_ml, 9)

    ll_table, ll_al = ll_info
    of_table, of_al = of_info
    ml_table, ml_al = ml_info

    bitstream = data[pos:block_end]
    if not bitstream:
        raise ValueError("Empty sequence bitstream")

    rbr = _ReverseBitReader(bitstream)

    ll_state = rbr.read(ll_al) if ll_al > 0 else 0
    of_state = rbr.read(of_al) if of_al > 0 else 0
    ml_state = rbr.read(ml_al) if ml_al > 0 else 0

    tokens = []
    lit_pos = 0

    for seq_idx in range(num_seq):
        of_e = of_table[of_state] if of_al > 0 else of_table[0]
        ml_e = ml_table[ml_state] if ml_al > 0 else ml_table[0]
        ll_e = ll_table[ll_state] if ll_al > 0 else ll_table[0]

        of_code = of_e.symbol
        ml_code = ml_e.symbol
        ll_code = ll_e.symbol

        of_extra = rbr.read(of_code) if of_code > 0 else 0
        ml_extra = rbr.read(_ML_EXTRA[ml_code]) if _ML_EXTRA[ml_code] > 0 else 0
        ll_extra = rbr.read(_LL_EXTRA[ll_code]) if _LL_EXTRA[ll_code] > 0 else 0

        offset_value = (1 << of_code) + of_extra
        match_length = _ML_BASELINE[ml_code] + ml_extra
        literals_length = _LL_BASELINE[ll_code] + ll_extra

        if offset_value > 3:
            offset = offset_value - 3
            repeat_offsets = [offset, repeat_offsets[0], repeat_offsets[1]]
        elif literals_length > 0:
            if offset_value == 1:
                offset = repeat_offsets[0]
            elif offset_value == 2:
                offset = repeat_offsets[1]
                repeat_offsets = [offset, repeat_offsets[0], repeat_offsets[2]]
            else:
                offset = repeat_offsets[2]
                repeat_offsets = [offset, repeat_offsets[0], repeat_offsets[1]]
        else:
            if offset_value == 1:
                offset = repeat_offsets[1]
                repeat_offsets = [offset, repeat_offsets[0], repeat_offsets[2]]
            elif offset_value == 2:
                offset = repeat_offsets[2]
                repeat_offsets = [offset, repeat_offsets[0], repeat_offsets[1]]
            else:
                offset = repeat_offsets[0] - 1
                if offset == 0:
                    raise ValueError("Repeat offset evaluates to 0")
                repeat_offsets = [offset, repeat_offsets[0], repeat_offsets[1]]

        for _ in range(literals_length):
            if lit_pos < len(literals):
                tokens.append(Literal(literals[lit_pos]))
                lit_pos += 1

        if match_length > 0:
            tokens.append(Reference(distance=offset, length=match_length))

        if seq_idx < num_seq - 1:
            if ll_al > 0:
                ll_state = ll_e.baseline + rbr.read(ll_e.num_bits)
            if ml_al > 0:
                ml_state = ml_e.baseline + rbr.read(ml_e.num_bits)
            if of_al > 0:
                of_state = of_e.baseline + rbr.read(of_e.num_bits)

    while lit_pos < len(literals):
        tokens.append(Literal(literals[lit_pos]))
        lit_pos += 1

    return tokens, block_end, ll_info, of_info, ml_info, repeat_offsets


# ===================================================================
# Public API
# ===================================================================

def zstd_extract_tokens(data: bytes) -> list[Token]:
    """
    Parse a Zstandard frame and extract LZ77 tokens.

    Satisfies conditions C1 and C2 (Definition 9, Lemma 11).

    Parameters
    ----------
    data : bytes
        Complete Zstandard frame data.

    Returns
    -------
    list[Token]
        Sequence of Literal and Reference tokens whose lz77_decode
        equals the original uncompressed data.
    """
    if len(data) < 4:
        return []

    magic = struct.unpack_from("<I", data, 0)[0]
    if 0x184D2A50 <= magic <= 0x184D2A5F:
        return []

    pos, window_size, fcs, has_checksum = _parse_frame_header(data, 0)

    all_tokens: list[Token] = []
    repeat_offsets = [1, 4, 8]
    prev_huf = None
    prev_ll = None
    prev_of = None
    prev_ml = None

    while True:
        if pos + 3 > len(data):
            break

        bh = data[pos] | (data[pos + 1] << 8) | (data[pos + 2] << 16)
        pos += 3

        last_block = bh & 1
        block_type = (bh >> 1) & 3
        block_size = bh >> 3

        if block_type == 0:  # Raw
            for b in data[pos: pos + block_size]:
                all_tokens.append(Literal(b))
            pos += block_size

        elif block_type == 1:  # RLE
            rle_byte = data[pos]
            pos += 1
            for _ in range(block_size):
                all_tokens.append(Literal(rle_byte))

        elif block_type == 2:  # Compressed
            block_end = pos + block_size

            lits, lit_end, prev_huf = _decode_literals(data, pos, prev_huf)

            tokens, _, ll_info, of_info, ml_info, repeat_offsets = \
                _decode_sequences(
                    data, lit_end, block_end, lits,
                    prev_ll, prev_of, prev_ml,
                    repeat_offsets
                )

            prev_ll = ll_info
            prev_of = of_info
            prev_ml = ml_info

            all_tokens.extend(tokens)
            pos = block_end

        elif block_type == 3:
            raise ValueError("Reserved block type")

        if last_block:
            break

    return all_tokens
