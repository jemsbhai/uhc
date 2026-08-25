"""
Naive LZ77 encoder and decoder.

Implements Definitions 4-5 and Theorem 4 from the compressed-domain
hashing framework. This is a reference implementation optimized for
correctness, not speed. It serves as the token source for compressed-
domain hash verification.

The encoder uses a simple greedy longest-match search with a sliding
window. The decoder faithfully implements byte-by-byte copy semantics
for overlapping back-references (Definition 5).
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable, Iterator
from typing import Sequence

from uhc.core.resources import DEFAULT_LIMITS, ResourceLimitError, ResourceLimits


# ---------------------------------------------------------------------------
# Definition 4: Token types
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Literal:
    """
    A literal byte token (Definition 4).

    Parameters
    ----------
    byte : int
        Byte value in [0, 255].
    """
    byte: int

    def __post_init__(self) -> None:
        _validate_literal(self.byte)


@dataclass(frozen=True, slots=True)
class Reference:
    """
    A back-reference token (Definition 4).

    Parameters
    ----------
    distance : int
        How far back to look (d ≥ 1).
    length : int
        How many bytes to copy (l ≥ 1).
    """
    distance: int
    length: int

    def __post_init__(self) -> None:
        _validate_reference(self.distance, self.length)


# Type alias for a token
Token = Literal | Reference


def _validate_literal(byte: int) -> None:
    """Validate one literal field at the single construction boundary."""
    if type(byte) is not int or not (0 <= byte <= 255):
        raise ValueError(f"Literal byte must be an integer in [0, 255], got {byte!r}")


def _validate_reference(distance: int, length: int) -> None:
    """Validate context-independent fields of one back-reference."""
    if type(distance) is not int or distance < 1:
        raise ValueError(f"Reference distance must be a positive integer, got {distance!r}")
    if type(length) is not int or length < 1:
        raise ValueError(f"Reference length must be a positive integer, got {length!r}")


def validate_tokens(
    tokens: Iterable[Token],
    *,
    max_distance: int | None = None,
    max_length: int | None = None,
) -> int:
    """Validate an LZ77 stream and return its decoded length.

    This is the authoritative stream-level validation boundary used by the
    decoder and hash implementations. In addition to validating token fields,
    it rejects references that reach before the beginning of the current
    stream and optional format-limit violations.
    """
    position = 0
    for index, token in enumerate(tokens):
        if isinstance(token, Literal):
            _validate_literal(token.byte)
            position += 1
            continue
        if not isinstance(token, Reference):
            raise TypeError(f"Token {index} has unsupported type {type(token).__name__}")

        _validate_reference(token.distance, token.length)
        if token.distance > position:
            raise ValueError(
                f"Invalid token {index}: reference distance {token.distance} "
                f"exceeds decoded length {position}"
            )
        if max_distance is not None and token.distance > max_distance:
            raise ValueError(
                f"Invalid token {index}: reference distance {token.distance} "
                f"exceeds format limit {max_distance}"
            )
        if max_length is not None and token.length > max_length:
            raise ValueError(
                f"Invalid token {index}: reference length {token.length} "
                f"exceeds format limit {max_length}"
            )
        position += token.length
    return position


def iter_validated_tokens(
    tokens: Iterable[Token],
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
    max_distance: int | None = None,
    max_length: int | None = None,
) -> Iterator[Token]:
    """Validate and yield a token stream in one pass.

    This is the consumption boundary used by streaming hash paths.  It avoids
    converting iterators to lists and enforces token, decoded-output, and
    reference budgets before yielding each token to downstream state.
    """
    position = 0
    distance_limit = min(
        limits.max_reference_distance,
        max_distance if max_distance is not None else limits.max_reference_distance,
    )
    length_limit = min(
        limits.max_reference_length,
        max_length if max_length is not None else limits.max_reference_length,
    )
    for index, token in enumerate(tokens):
        if index >= limits.max_tokens:
            raise ResourceLimitError(
                f"Token count exceeds max_tokens={limits.max_tokens}"
            )
        if isinstance(token, Literal):
            _validate_literal(token.byte)
            next_position = position + 1
        elif isinstance(token, Reference):
            _validate_reference(token.distance, token.length)
            if token.distance > position:
                raise ValueError(
                    f"Invalid token {index}: reference distance {token.distance} "
                    f"exceeds decoded length {position}"
                )
            if token.distance > distance_limit:
                raise ResourceLimitError(
                    f"Token {index} reference distance {token.distance} exceeds "
                    f"limit {distance_limit}"
                )
            if token.length > length_limit:
                raise ResourceLimitError(
                    f"Token {index} reference length {token.length} exceeds "
                    f"limit {length_limit}"
                )
            next_position = position + token.length
        else:
            raise TypeError(f"Token {index} has unsupported type {type(token).__name__}")

        limits.check_output(next_position)
        yield token
        position = next_position


def iter_lz77_decode(
    tokens: Iterable[Token],
    *,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> Iterator[bytes]:
    """Decode tokens incrementally with a bounded back-reference window."""
    window = bytearray()
    pending = bytearray()
    keep = limits.max_reference_distance

    for token in iter_validated_tokens(tokens, limits=limits):
        if isinstance(token, Literal):
            pending.append(token.byte)
            window.append(token.byte)
        else:
            for _ in range(token.length):
                byte = window[-token.distance]
                pending.append(byte)
                window.append(byte)
                if len(pending) >= limits.io_chunk_size:
                    yield bytes(pending)
                    pending.clear()

        if len(window) > keep + limits.io_chunk_size:
            del window[:-keep]
        if len(pending) >= limits.io_chunk_size:
            yield bytes(pending)
            pending.clear()

    if pending:
        yield bytes(pending)


# ---------------------------------------------------------------------------
# Definition 5: LZ77 Decoding
# ---------------------------------------------------------------------------

def lz77_decode(tokens: Sequence[Token]) -> bytes:
    """
    Decode an LZ77 token stream to bytes (Definition 5).

    For Ref(d, l) at position pos, bytes are copied one at a time:
        w_k = buffer[pos - d + (k mod d)]   for k = 0, ..., l-1

    When d < l (overlapping), this produces a repeating pattern of
    period d (Theorem 4): W = P^q ‖ P[0..r-1].

    Parameters
    ----------
    tokens : sequence of Token
        The LZ77 token stream.

    Returns
    -------
    bytes
        The decoded byte string.

    Raises
    ------
    ValueError
        If a back-reference refers before the start of the buffer.
    """
    validate_tokens(tokens)
    buf = bytearray()

    for tok in tokens:
        if isinstance(tok, Literal):
            buf.append(tok.byte)

        elif isinstance(tok, Reference):
            pos = len(buf)
            d, l = tok.distance, tok.length

            if d > pos:
                raise ValueError(
                    f"Invalid back-reference: distance {d} exceeds "
                    f"buffer length {pos}"
                )

            # Byte-by-byte copy (Definition 5).
            # This correctly handles overlapping references (d < l)
            # by reading bytes that the current copy is producing.
            for k in range(l):
                buf.append(buf[pos - d + (k % d)])

    return bytes(buf)


# ---------------------------------------------------------------------------
# Naive LZ77 Encoder
# ---------------------------------------------------------------------------

# Encoder parameters
_MIN_MATCH: int = 3       # Minimum match length (same as DEFLATE)
_MAX_MATCH: int = 258     # Maximum match length (same as DEFLATE)
_WINDOW_SIZE: int = 32768 # Sliding window size (same as DEFLATE)


def lz77_encode(
    data: bytes,
    min_match: int = _MIN_MATCH,
    max_match: int = _MAX_MATCH,
    window_size: int = _WINDOW_SIZE,
) -> list[Token]:
    """
    Encode bytes to an LZ77 token stream using greedy longest-match.

    This is a naive O(n · window_size) encoder intended for correctness
    testing, not production use. It produces both non-overlapping and
    overlapping back-references.

    Parameters
    ----------
    data : bytes
        Input data to compress.
    min_match : int
        Minimum match length to emit a Reference (default: 3).
    max_match : int
        Maximum match length per Reference (default: 258).
    window_size : int
        Maximum back-reference distance (default: 32768).

    Returns
    -------
    list[Token]
        The LZ77 token stream.
    """
    tokens: list[Token] = []
    n = len(data)
    pos = 0

    while pos < n:
        best_dist = 0
        best_len = 0

        # Search window: [max(0, pos - window_size), pos)
        window_start = max(0, pos - window_size)

        # Try each starting position in the window
        for s in range(window_start, pos):
            d = pos - s  # distance
            match_len = 0

            # Extend match byte-by-byte, allowing overlapping reads.
            # When match extends past the source start (match_len >= d),
            # we wrap around using modular indexing, exactly matching
            # the decoder semantics (Definition 5).
            while (
                pos + match_len < n
                and match_len < max_match
                and data[pos + match_len] == data[s + (match_len % d)]
            ):
                match_len += 1

            if match_len > best_len:
                best_len = match_len
                best_dist = d

        if best_len >= min_match:
            tokens.append(Reference(distance=best_dist, length=best_len))
            pos += best_len
        else:
            tokens.append(Literal(data[pos]))
            pos += 1

    return tokens
