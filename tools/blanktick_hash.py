"""
The hash functions, in Python.

This is the third implementation of the same specification. The other two are
`core/src/main/kotlin/com/blanktick/core/filters/Hashing.kt` and
`ios/BlanktickCore/Sources/Hashing.swift`.

All three must agree on every bit for every input, forever. If they ever drift,
a bundle built here becomes unreadable by the app in the worst possible way --
not a crash, but silently wrong membership answers, which for the password
filter means telling someone a breached password is safe.

`tools/check_hash_parity.py` and `HashParityTest.kt` both pin the same vectors
so a change to any one implementation fails the build.

Specification
-------------
    h1(x) = splitmix64( fnv1a64(x, OFFSET_A) )
    h2(x) = splitmix64( fnv1a64(x, OFFSET_B) XOR 0xD6E8FEB86659FD93 )

with FNV-1a operating on the UTF-8 bytes of the input, and all arithmetic in
unsigned 64-bit two's complement.
"""

from __future__ import annotations

MASK64 = 0xFFFFFFFFFFFFFFFF

FNV_PRIME = 0x100000001B3
FNV_OFFSET_A = 0xCBF29CE484222325
FNV_OFFSET_B = 0x9E3779B97F4A7C15
H2_TWEAK = 0xD6E8FEB86659FD93


def splitmix64(value: int) -> int:
    """SplitMix64 mixer. Strong avalanche; fixes FNV-1a's weak low bits."""
    z = (value + 0x9E3779B97F4A7C15) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return (z ^ (z >> 31)) & MASK64


def fnv1a64(data: bytes, offset: int) -> int:
    h = offset
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    return h


def h1(value: str | bytes) -> int:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return splitmix64(fnv1a64(data, FNV_OFFSET_A))


def h2(value: str | bytes) -> int:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return splitmix64(fnv1a64(data, FNV_OFFSET_B) ^ H2_TWEAK)


def digest(value: str | bytes) -> int:
    """Single 64-bit digest, for the exact-membership tables."""
    return h1(value)


def normalize_domain(raw: str) -> str:
    """
    Must match `DomainNormalizer.normalize` in Kotlin exactly.

    Note what is NOT done: `www.` is not stripped. `www.example.com` and
    `example.com` are different names, and the parent-domain walk at query time
    handles the relationship.
    """
    s = raw.strip().lower()
    if s.startswith("*."):
        s = s[2:]
    s = s.rstrip(".")
    if ":" in s:
        head, _, tail = s.rpartition(":")
        if tail.isdigit() and head:
            s = head
    return s


def to_punycode(domain: str) -> str:
    """
    IDN -> ASCII, so the bundle and the app agree on the key.

    The app normalises to punycode before hashing, so a Unicode domain in a
    source list must be converted here or it would never match.
    """
    if domain.isascii():
        return domain
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Leave undecodable input alone rather than dropping it: an entry we
        # cannot canonicalise is better stored verbatim than lost.
        return domain
