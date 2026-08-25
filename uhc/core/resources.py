"""Shared resource budgets for public parsing, hashing, and decoding APIs."""

from __future__ import annotations

from dataclasses import dataclass


class ResourceLimitError(ValueError):
    """Raised before a configured input, output, or structural budget is exceeded."""


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Finite defaults for work triggered by untrusted public input.

    Callers processing larger trusted datasets can pass an explicit enlarged
    instance.  ``max_depth`` applies to rope/tree structure; the format parsers
    already impose their specification-defined Huffman/FSE depth limits.
    """

    max_input_bytes: int = 1 << 30
    max_output_bytes: int = 1 << 30
    max_tokens: int = 10_000_000
    max_depth: int = 256
    max_reference_distance: int = 1 << 27
    max_reference_length: int = 1 << 30
    io_chunk_size: int = 1 << 20

    def __post_init__(self) -> None:
        for name in (
            "max_input_bytes",
            "max_output_bytes",
            "max_tokens",
            "max_depth",
            "max_reference_distance",
            "max_reference_length",
            "io_chunk_size",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")

    def check_input(self, size: int) -> None:
        if size > self.max_input_bytes:
            raise ResourceLimitError(
                f"Input size {size} exceeds max_input_bytes={self.max_input_bytes}"
            )

    def check_output(self, size: int) -> None:
        if size > self.max_output_bytes:
            raise ResourceLimitError(
                f"Decoded size {size} exceeds max_output_bytes={self.max_output_bytes}"
            )


DEFAULT_LIMITS = ResourceLimits()
