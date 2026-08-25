"""
UHC - Unified Hash-Compression Engine

Compressed-domain hashing over LZ77 streams.
Computes polynomial hashes of uncompressed data directly from
compressed token representations without decompression.

EXPERIMENTAL: polynomial-hash equality is probabilistic screening, not
authentication. The public ``uhc_verify_exact`` path (and compatible
``uhc_verify`` name) strictly decodes and compares bytes exactly, but it does
not establish authenticity or provenance. Format
token parsers and compressed-domain algorithms remain pre-alpha.
"""

__version__ = "0.1.6"
__author__ = "UHC Contributors"
