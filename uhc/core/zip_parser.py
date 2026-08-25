"""
ZIP container parser for compressed-domain hashing.

Parses ZIP archives (PKZIP APPNOTE 6.3.10) to extract per-entry
DEFLATE streams, enabling CDH of individual files within a ZIP
without extracting the archive.

ZIP is fundamentally multi-stream: each entry is independently
compressed. This module provides per-entry token extraction:

    entries = zip_list_entries(data)
    for entry in entries:
        tokens = zip_entry_extract_tokens(data, entry)
        h = compressed_domain_hash(tokens)  # H(original_file) by Theorem 12

Supported compression methods:
    0 (Stored)  — uncompressed, tokens are all Literals
    8 (Deflate) — delegates to deflate_extract_tokens (Lemma 9)

ZIP structure used:
    1. End of Central Directory Record (EOCD) — locates central directory
    2. Central Directory — reliable entry metadata (sizes, offsets, CRC)
    3. Local File Headers — locates compressed data start per entry
"""

from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass

from uhc.core.lz77 import Token, Literal, lz77_decode
from uhc.core.deflate import deflate_extract_tokens


# ---------------------------------------------------------------------------
# ZIP signatures
# ---------------------------------------------------------------------------

_SIG_LOCAL = b"PK\x03\x04"       # Local file header
_SIG_CENTRAL = b"PK\x01\x02"     # Central directory file header
_SIG_EOCD = b"PK\x05\x06"        # End of central directory record
_SIG_EOCD64 = b"PK\x06\x06"      # ZIP64 end of central directory record
_SIG_EOCD64_LOC = b"PK\x06\x07"  # ZIP64 end of central directory locator


# ---------------------------------------------------------------------------
# ZipEntry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ZipEntry:
    """
    Metadata for a single file entry in a ZIP archive.

    Attributes
    ----------
    filename : str
        Entry path within the archive.
    compression_method : int
        0 = stored (uncompressed), 8 = DEFLATE.
    compressed_size : int
        Size of compressed data in bytes.
    uncompressed_size : int
        Size of original uncompressed data in bytes.
    crc32 : int
        CRC-32 of the uncompressed data.
    local_header_offset : int
        Byte offset of the local file header in the ZIP data.
    data_offset : int
        Byte offset where the compressed data begins (after local header).
    """
    filename: str
    compression_method: int
    compressed_size: int
    uncompressed_size: int
    crc32: int
    local_header_offset: int
    data_offset: int


# ---------------------------------------------------------------------------
# EOCD parsing
# ---------------------------------------------------------------------------

def _find_eocd(data: bytes) -> int:
    """
    Find the End of Central Directory record.

    Scans backwards from the end of the file. EOCD is at least 22 bytes
    and can have a variable-length comment (up to 65535 bytes).

    Returns the byte offset of the EOCD signature.

    Raises ValueError if EOCD is not found.
    """
    # EOCD is at least 22 bytes. Search backwards up to 22 + 65535 bytes.
    min_eocd_size = 22
    max_comment = 65535
    search_limit = min(len(data), min_eocd_size + max_comment)

    for i in range(min_eocd_size, search_limit + 1):
        offset = len(data) - i
        if data[offset:offset + 4] != _SIG_EOCD:
            continue
        comment_len = struct.unpack_from("<H", data, offset + 20)[0]
        if offset + min_eocd_size + comment_len == len(data):
            return offset

    raise ValueError("Not a ZIP archive: End of Central Directory record not found")


def _parse_eocd(data: bytes, eocd_offset: int) -> tuple[int, int, int]:
    """
    Parse the EOCD record.

    Returns (num_entries, central_dir_size, central_dir_offset).
    Handles ZIP64 if sizes are 0xFFFF / 0xFFFFFFFF.
    """
    # Standard EOCD: 22 bytes minimum
    # Offset 8: total number of entries (2 bytes)
    # Offset 10: central directory size (4 bytes) — not used
    # Offset 12: central directory size (4 bytes)
    # Offset 16: offset of central directory (4 bytes)

    disk_number = struct.unpack_from("<H", data, eocd_offset + 4)[0]
    central_disk = struct.unpack_from("<H", data, eocd_offset + 6)[0]
    disk_entries = struct.unpack_from("<H", data, eocd_offset + 8)[0]
    num_entries = struct.unpack_from("<H", data, eocd_offset + 10)[0]
    cd_size = struct.unpack_from("<I", data, eocd_offset + 12)[0]
    cd_offset = struct.unpack_from("<I", data, eocd_offset + 16)[0]

    if disk_number != 0 or central_disk != 0 or disk_entries != num_entries:
        raise ValueError("Multi-disk ZIP archives are not supported")

    # Check for ZIP64
    if num_entries == 0xFFFF or cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        # Look for ZIP64 EOCD locator (20 bytes before standard EOCD)
        loc_offset = eocd_offset - 20
        if loc_offset < 0 or data[loc_offset:loc_offset + 4] != _SIG_EOCD64_LOC:
            raise ValueError("ZIP64 archive is missing its EOCD locator")
        if loc_offset + 20 > len(data):
            raise ValueError("Truncated ZIP64 EOCD locator")
        eocd64_offset = struct.unpack_from("<Q", data, loc_offset + 8)[0]
        if eocd64_offset + 56 > len(data):
            raise ValueError("Truncated ZIP64 EOCD record")
        if data[eocd64_offset:eocd64_offset + 4] != _SIG_EOCD64:
            raise ValueError("Invalid ZIP64 EOCD signature")
        zip64_disk = struct.unpack_from("<I", data, eocd64_offset + 16)[0]
        zip64_central_disk = struct.unpack_from("<I", data, eocd64_offset + 20)[0]
        zip64_disk_entries = struct.unpack_from("<Q", data, eocd64_offset + 24)[0]
        num_entries = struct.unpack_from("<Q", data, eocd64_offset + 32)[0]
        if zip64_disk != 0 or zip64_central_disk != 0 or zip64_disk_entries != num_entries:
            raise ValueError("Multi-disk ZIP64 archives are not supported")
        cd_size = struct.unpack_from("<Q", data, eocd64_offset + 40)[0]
        cd_offset = struct.unpack_from("<Q", data, eocd64_offset + 48)[0]

    if cd_offset > eocd_offset or cd_size > eocd_offset - cd_offset:
        raise ValueError("ZIP central directory lies outside the archive")
    if num_entries > cd_size // 46:
        raise ValueError(
            "ZIP entry count cannot fit in the declared central directory"
        )

    return num_entries, cd_size, cd_offset


# ---------------------------------------------------------------------------
# Central directory parsing
# ---------------------------------------------------------------------------

def _parse_central_directory(
    data: bytes, cd_offset: int, cd_size: int, num_entries: int
) -> list[ZipEntry]:
    """
    Parse the central directory to extract entry metadata.

    Uses the central directory (not local headers) for reliable size
    and offset information. Then reads the local header at each
    entry's offset to determine the exact data start position.
    """
    entries: list[ZipEntry] = []
    pos = cd_offset
    cd_end = cd_offset + cd_size

    for entry_index in range(num_entries):
        if pos + 46 > cd_end or pos + 46 > len(data):
            raise ValueError(
                f"Truncated ZIP central directory at entry {entry_index}"
            )
        if data[pos:pos + 4] != _SIG_CENTRAL:
            raise ValueError(
                f"Invalid central directory signature at entry {entry_index}"
            )

        # Central directory file header (46 bytes fixed)
        method = struct.unpack_from("<H", data, pos + 10)[0]
        crc32 = struct.unpack_from("<I", data, pos + 16)[0]
        comp_size = struct.unpack_from("<I", data, pos + 20)[0]
        uncomp_size = struct.unpack_from("<I", data, pos + 24)[0]
        fname_len = struct.unpack_from("<H", data, pos + 28)[0]
        extra_len = struct.unpack_from("<H", data, pos + 30)[0]
        comment_len = struct.unpack_from("<H", data, pos + 32)[0]
        local_offset = struct.unpack_from("<I", data, pos + 42)[0]
        next_pos = pos + 46 + fname_len + extra_len + comment_len
        if next_pos > cd_end or next_pos > len(data):
            raise ValueError(
                f"Truncated variable fields in central directory entry {entry_index}"
            )

        # Filename
        fname_bytes = data[pos + 46: pos + 46 + fname_len]

        # Check for UTF-8 flag (bit 11 of general purpose flags)
        gp_flags = struct.unpack_from("<H", data, pos + 8)[0]
        if gp_flags & (1 << 11):
            filename = fname_bytes.decode("utf-8")
        else:
            try:
                filename = fname_bytes.decode("utf-8")
            except UnicodeDecodeError:
                filename = fname_bytes.decode("cp437")

        # Handle ZIP64 extended information in extra field
        extra_data = data[pos + 46 + fname_len: pos + 46 + fname_len + extra_len]
        if uncomp_size == 0xFFFFFFFF or comp_size == 0xFFFFFFFF or local_offset == 0xFFFFFFFF:
            uncomp_size, comp_size, local_offset = _parse_zip64_extra(
                extra_data, uncomp_size, comp_size, local_offset
            )

        # Skip directory entries (filename ends with /)
        if filename.endswith("/") and uncomp_size == 0:
            pos += 46 + fname_len + extra_len + comment_len
            continue

        # Read and cross-check the local header before trusting its data offset.
        if local_offset + 30 > len(data):
            raise ValueError(
                f"Truncated local file header for entry {filename!r}"
            )
        local_flags = struct.unpack_from("<H", data, local_offset + 6)[0]
        local_method = struct.unpack_from("<H", data, local_offset + 8)[0]
        local_fname_len = struct.unpack_from("<H", data, local_offset + 26)[0]
        local_extra_len = struct.unpack_from("<H", data, local_offset + 28)[0]
        local_name_start = local_offset + 30
        local_name_end = local_name_start + local_fname_len
        if local_name_end + local_extra_len > len(data):
            raise ValueError(
                f"Truncated local file header fields for entry {filename!r}"
            )
        if local_method != method or local_flags != gp_flags:
            raise ValueError(
                f"Local/central header mismatch for entry {filename!r}"
            )
        if data[local_name_start:local_name_end] != fname_bytes:
            raise ValueError(
                f"Local/central filename mismatch for entry {filename!r}"
            )
        data_start = _local_header_data_offset(data, local_offset)
        if data_start + comp_size > cd_offset:
            raise ValueError(
                f"Compressed data for entry {filename!r} overlaps the central directory"
            )
        if method == 0 and comp_size != uncomp_size:
            raise ValueError(
                f"Stored entry {filename!r} has inconsistent compressed and decoded sizes"
            )

        entries.append(ZipEntry(
            filename=filename,
            compression_method=method,
            compressed_size=comp_size,
            uncompressed_size=uncomp_size,
            crc32=crc32,
            local_header_offset=local_offset,
            data_offset=data_start,
        ))

        pos = next_pos

    if pos != cd_end:
        raise ValueError(
            f"ZIP central directory size mismatch: parsed {pos - cd_offset} byte(s), "
            f"expected {cd_size}"
        )

    return entries


def _parse_zip64_extra(
    extra: bytes,
    uncomp: int,
    comp: int,
    offset: int,
) -> tuple[int, int, int]:
    """
    Parse ZIP64 extended information extra field (header ID 0x0001).

    Fields are present only when the corresponding standard field is 0xFFFFFFFF.
    Order: uncompressed size, compressed size, local header offset, disk number.
    """
    pos = 0
    while pos + 4 <= len(extra):
        header_id = struct.unpack_from("<H", extra, pos)[0]
        field_size = struct.unpack_from("<H", extra, pos + 2)[0]
        if header_id == 0x0001:
            fpos = pos + 4
            if uncomp == 0xFFFFFFFF and fpos + 8 <= pos + 4 + field_size:
                uncomp = struct.unpack_from("<Q", extra, fpos)[0]
                fpos += 8
            if comp == 0xFFFFFFFF and fpos + 8 <= pos + 4 + field_size:
                comp = struct.unpack_from("<Q", extra, fpos)[0]
                fpos += 8
            if offset == 0xFFFFFFFF and fpos + 8 <= pos + 4 + field_size:
                offset = struct.unpack_from("<Q", extra, fpos)[0]
            break
        pos += 4 + field_size

    return uncomp, comp, offset


def _local_header_data_offset(data: bytes, local_offset: int) -> int:
    """
    Read a local file header and return the offset where file data begins.

    Local file header: 30 bytes fixed + filename_len + extra_len.
    Data starts immediately after.
    """
    if data[local_offset:local_offset + 4] != _SIG_LOCAL:
        raise ValueError(
            f"Invalid local file header signature at offset {local_offset}"
        )

    # Local header fields we need:
    # Offset 26: filename length (2 bytes)
    # Offset 28: extra field length (2 bytes)
    fname_len = struct.unpack_from("<H", data, local_offset + 26)[0]
    extra_len = struct.unpack_from("<H", data, local_offset + 28)[0]

    return local_offset + 30 + fname_len + extra_len


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def zip_list_entries(data: bytes) -> list[ZipEntry]:
    """
    Parse a ZIP archive and return metadata for all file entries.

    Skips directory entries (filename ending with /).

    Parameters
    ----------
    data : bytes
        Complete ZIP archive data.

    Returns
    -------
    list[ZipEntry]
        Metadata for each file entry.

    Raises
    ------
    ValueError
        If data is not a valid ZIP archive.
    """
    eocd_offset = _find_eocd(data)
    num_entries, cd_size, cd_offset = _parse_eocd(data, eocd_offset)
    return _parse_central_directory(data, cd_offset, cd_size, num_entries)


def zip_entry_extract_tokens(
    data: bytes, entry: ZipEntry
) -> list[Token]:
    """
    Extract LZ77 tokens from a single ZIP entry.

    For method=8 (DEFLATE): delegates to deflate_extract_tokens (Lemma 9).
    For method=0 (Stored): returns one Literal per byte.

    Correctness: Theorem 12 holds for DEFLATE entries since the inner
    DEFLATE stream satisfies conditions C1 and C2 (Lemma 9).
    Stored entries produce Literal-only token streams where CDH = H
    trivially.

    Parameters
    ----------
    data : bytes
        Complete ZIP archive data.
    entry : ZipEntry
        Entry metadata from zip_list_entries.

    Returns
    -------
    list[Token]
        LZ77 token stream for the entry's content.

    Raises
    ------
    ValueError
        If compression method is not supported (only 0 and 8).
    """
    # Check for encryption
    if entry.local_header_offset < 0 or entry.local_header_offset + 30 > len(data):
        raise ValueError(f"Invalid local header offset for entry {entry.filename!r}")
    expected_data_offset = _local_header_data_offset(data, entry.local_header_offset)
    if expected_data_offset != entry.data_offset:
        raise ValueError(f"Invalid data offset for entry {entry.filename!r}")
    gp_flags = struct.unpack_from("<H", data, entry.local_header_offset + 6)[0]
    if gp_flags & 0x0001:
        raise ValueError(
            f"Encrypted entry '{entry.filename}' cannot be processed. "
            f"UHC does not support encrypted ZIP entries "
            f"(traditional PKZIP encryption detected)."
        )
    if gp_flags & 0x0040:
        raise ValueError(
            f"Encrypted entry '{entry.filename}' cannot be processed. "
            f"UHC does not support encrypted ZIP entries "
            f"(strong encryption detected)."
        )

    # Check for AES encryption (WinZip AE-x: compression method 99)
    if entry.compression_method == 99:
        raise ValueError(
            f"Encrypted entry '{entry.filename}' cannot be processed. "
            f"UHC does not support AES-encrypted ZIP entries "
            f"(WinZip AE-x, method 99)."
        )

    # Extract the compressed data slice
    data_end = entry.data_offset + entry.compressed_size
    if entry.data_offset < 0 or data_end > len(data):
        raise ValueError(f"Truncated compressed data for entry {entry.filename!r}")
    comp_data = data[entry.data_offset:data_end]

    if entry.compression_method == 0:
        # Stored: raw bytes → Literal tokens
        tokens: list[Token] = [Literal(b) for b in comp_data]

    elif entry.compression_method == 8:
        # DEFLATE: delegate to our RFC 1951 parser (Lemma 9)
        tokens = deflate_extract_tokens(comp_data)

    else:
        raise ValueError(
            f"Unsupported compression method {entry.compression_method} "
            f"for entry '{entry.filename}'. Only stored (0) and DEFLATE (8) "
            f"are supported."
        )

    decoded = lz77_decode(tokens)
    if len(decoded) != entry.uncompressed_size:
        raise ValueError(
            f"Decoded size mismatch for entry {entry.filename!r}: "
            f"expected {entry.uncompressed_size}, got {len(decoded)}"
        )
    actual_crc = binascii.crc32(decoded) & 0xFFFFFFFF
    if actual_crc != entry.crc32:
        raise ValueError(
            f"CRC mismatch for entry {entry.filename!r}: "
            f"expected 0x{entry.crc32:08x}, got 0x{actual_crc:08x}"
        )
    return tokens
