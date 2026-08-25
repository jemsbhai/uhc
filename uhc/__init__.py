"""UHC 0.2 Python release candidate.

The release-candidate surface is strict decoded-byte verification and the
parser/resource contracts that support it. ``uhc_verify_exact`` (and the
compatible ``uhc_verify`` name) compares decoded bytes exactly; it does not
establish authenticity or provenance.

Polynomial hashing, chunk hashes, and compressed-domain algorithms remain
explicit research opt-ins. Their equality results are probabilistic screening,
not a production or security decision. The co-located unpublished Rust crate
is outside this Python release candidate.
"""

__version__ = "0.2.0rc1"
__author__ = "UHC Contributors"
