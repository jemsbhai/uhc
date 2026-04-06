"""Compare decoded Huffman weights: full buffer vs truncated buffer."""
import zstandard as zstd

text = (
    b"The quick brown fox jumps over the lazy dog. "
    b"Pack my box with five dozen liquor jugs. "
    b"How vexingly quick daft zebras jump. "
) * 100

compressed = zstd.ZstdCompressor(level=1).compress(text)

# Parse to get fse_data
pos = 7 + 3  # frame header + block header
byte0 = compressed[pos]
v = int.from_bytes(compressed[pos:pos+3], "little")
regen_size = (v >> 4) & 0x3FF
comp_size = (v >> 14) & 0x3FF
huf_start = pos + 3
fse_compressed_size = compressed[huf_start]  # = 23
fse_data = compressed[huf_start+1 : huf_start+1+fse_compressed_size]

from uhc.core.zstd_parser import (
    _ForwardBitReader, _decode_fse_distribution, _build_fse_table, _ReverseBitReader
)

# Decode FSE distribution
reader = _ForwardBitReader(fse_data)
dist, al = _decode_fse_distribution(reader, 7)
consumed = reader.bytes_consumed()
fse_table = _build_fse_table(dist, al)

print(f"FSE dist consumed {consumed} bytes out of {len(fse_data)}")
print(f"Byte {consumed-1} of fse_data: 0x{fse_data[consumed-1]:02x} = {fse_data[consumed-1]:08b}")
print()

# Approach A: truncated (old)
trunc = fse_data[consumed:]
rbr_a = _ReverseBitReader(trunc)
print(f"Truncated: {len(trunc)} bytes, bit_length={int.from_bytes(trunc, 'little').bit_length()}, _pos={rbr_a._pos}")

# Approach B: full buffer (new)
rbr_b = _ReverseBitReader(fse_data)
print(f"Full:      {len(fse_data)} bytes, bit_length={int.from_bytes(fse_data, 'little').bit_length()}, _pos={rbr_b._pos}")
print()

# Decode weights with both approaches
def decode_weights(rbr, fse_table, al):
    state1 = rbr.read(al)
    state2 = rbr.read(al)
    weights = []
    while len(weights) < 255:
        e1 = fse_table[state1]
        weights.append(e1.symbol)
        if len(weights) >= 255: break
        prev = rbr.remaining
        state1 = e1.baseline + rbr.read(e1.num_bits)
        if e1.num_bits > 0 and prev < e1.num_bits:
            weights.append(fse_table[state2].symbol)
            break
        e2 = fse_table[state2]
        weights.append(e2.symbol)
        if len(weights) >= 255: break
        prev = rbr.remaining
        state2 = e2.baseline + rbr.read(e2.num_bits)
        if e2.num_bits > 0 and prev < e2.num_bits:
            break
    while weights and weights[-1] == 0:
        weights.pop()
    return weights

weights_a = decode_weights(rbr_a, fse_table, al)
rbr_b2 = _ReverseBitReader(fse_data)
weights_b = decode_weights(rbr_b2, fse_table, al)

print(f"Truncated weights: {len(weights_a)} total, {sum(1 for w in weights_a if w > 0)} nonzero")
print(f"Full buffer weights: {len(weights_b)} total, {sum(1 for w in weights_b if w > 0)} nonzero")
print(f"Same? {weights_a == weights_b}")

if weights_a != weights_b:
    for i in range(max(len(weights_a), len(weights_b))):
        wa = weights_a[i] if i < len(weights_a) else '-'
        wb = weights_b[i] if i < len(weights_b) else '-'
        if wa != wb:
            print(f"  First diff at index {i}: trunc={wa}, full={wb}")
            break

# Find valid prefixes for both
def find_valid(weights):
    for n in range(len(weights), 0, -1):
        ws = sum(1 << (w-1) for w in weights[:n] if w > 0)
        if ws == 0: continue
        mb = ws.bit_length()
        t = 1 << mb
        rem = t - ws
        if rem > 0 and (rem & (rem-1)) == 0 and mb <= 11:
            return n, ws, mb
    return None, None, None

na, wsa, mba = find_valid(weights_a)
nb, wsb, mbb = find_valid(weights_b)
print(f"\nTruncated valid prefix: n={na}, wsum={wsa}, max_bits={mba}")
print(f"Full buffer valid prefix: n={nb}, wsum={wsb}, max_bits={mbb}")

# Show the actual nonzero weights for the valid prefix
if nb:
    print(f"\nFull buffer weights (first {nb}):")
    nonzero = [(i, weights_b[i]) for i in range(nb) if weights_b[i] > 0]
    for idx, w in nonzero:
        bits = mbb + 1 - w
        ch = chr(idx) if 32 <= idx <= 126 else f'\\x{idx:02x}'
        print(f"  sym {idx:3d} ({ch:4s}): weight={w}, bits={bits}")
