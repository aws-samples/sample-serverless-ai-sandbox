# kiro-classification: public
"""The adversarial byte domains the design's generators for Properties 3 and 5 name.

Two generators live here. `output_bytes()` is the domain of R8.9: byte sequences a process
may write, including sequences that are not valid UTF-8. `path_component()` is the domain of
a single filesystem name, which is the same domain minus the two bytes a Linux path component
cannot contain.

The adversarial cases are the ones the design lists by name, and they are grouped into
`ADVERSARIAL_BYTE_CLASSES` rather than flattened into one tuple so that a class dropped by a
future edit is a visible omission. Every class is a sequence a real Linux process can produce
and a real filesystem can hold; none of them is a hypothetical.

Length is its own fault domain. `CBOR_LENGTH_BOUNDARIES` holds the sizes either side of each
CBOR length-prefix width change, because a codec that mis-selects a prefix width fails only
at the crossing and passes everywhere else.
"""

from __future__ import annotations

from typing import Final

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

__all__ = [
    "ADVERSARIAL_BYTE_CLASSES",
    "ADVERSARIAL_BYTE_SEQUENCES",
    "CBOR_LENGTH_BOUNDARIES",
    "MAX_OUTPUT_BYTES",
    "MAX_PATH_COMPONENT_BYTES",
    "PATH_SEPARATOR",
    "RESERVED_PATH_COMPONENTS",
    "output_bytes",
    "path_component",
]

# UTF-8-style encodings of the surrogate range U+D800 to U+DFFF, which is unassignable to a
# scalar value and therefore never appears in well-formed UTF-8, plus the CESU-8 surrogate
# pair a JVM or a Windows tool may emit for an astral character.
LONE_SURROGATES: Final[tuple[bytes, ...]] = (
    b"\xed\xa0\x80",  # U+D800, first high surrogate
    b"\xed\xaf\xbf",  # U+DBFF, last high surrogate
    b"\xed\xb0\x80",  # U+DC00, first low surrogate
    b"\xed\xbf\xbf",  # U+DFFF, last low surrogate
    b"\xed\xa0\xbd\xed\xb8\x80",  # CESU-8 pair for U+1F600
)

# Multi-byte sequences cut short, which is what a reader sees when output is chunked on a
# byte boundary rather than a character boundary, and bare continuation bytes, which is what
# it sees when a chunk begins mid-character.
TRUNCATED_SEQUENCES: Final[tuple[bytes, ...]] = (
    b"\xc3",  # a two-byte sequence missing its continuation
    b"\xe2\x82",  # three bytes of U+20AC, one short
    b"\xf0\x9f\x92",  # four bytes of U+1F4A9, one short
    b"\x80",  # a bare continuation byte
    b"\xbf",
    b"\xe2\x82\xac"[1:],  # the tail of a character, as a resumed chunk begins
)

# Encodings that use more bytes than the scalar value requires. Rejected by every conformant
# UTF-8 decoder and historically a security hazard, which is exactly why a codec must carry
# them rather than normalise them.
OVERLONG_ENCODINGS: Final[tuple[bytes, ...]] = (
    b"\xc0\x80",  # overlong NUL
    b"\xc1\xbf",  # overlong U+007F
    b"\xe0\x80\x80",  # overlong NUL, three bytes
    b"\xe0\x9f\xbf",  # overlong U+07FF
    b"\xf0\x80\x80\x80",  # overlong NUL, four bytes
    b"\xf0\x8f\xbf\xbf",  # overlong U+FFFF
)

# Bytes that cannot begin, or appear anywhere in, a valid UTF-8 sequence. 0xFE and 0xFF are
# the pair a caller might mistake for a byte-order mark; 0xF5 upward is unassigned.
HIGH_BYTES: Final[tuple[bytes, ...]] = (
    b"\xff",
    b"\xfe",
    b"\xff\xfe",
    b"\xfe\xff",
    b"\xff" * 4,
    bytes(range(0xF5, 0x100)),
)

# NUL is legal in a byte string and in process output, and it terminates a C string. A codec
# that hands output to a C API without carrying its length loses everything after the first
# one, which a single embedded NUL does not always reveal but a run does.
NUL_RUNS: Final[tuple[bytes, ...]] = (
    b"\x00",
    b"\x00\x00",
    b"before\x00after",
    b"\x00" * 16,
    b"\x00a\x00b\x00",
)

ADVERSARIAL_BYTE_CLASSES: Final[dict[str, tuple[bytes, ...]]] = {
    "lone-surrogate": LONE_SURROGATES,
    "truncated-sequence": TRUNCATED_SEQUENCES,
    "overlong-encoding": OVERLONG_ENCODINGS,
    "high-byte": HIGH_BYTES,
    "nul-run": NUL_RUNS,
}

ADVERSARIAL_BYTE_SEQUENCES: Final[tuple[bytes, ...]] = tuple(
    sequence for group in ADVERSARIAL_BYTE_CLASSES.values() for sequence in group
)

# The sizes either side of each CBOR length-prefix width change: an argument below 24 is
# immediate, then one, two and four additional bytes. A codec that emits a wider prefix than
# the length needs still round-trips, but it violates the deterministic profile, and the fault
# is only reachable at a crossing.
CBOR_LENGTH_BOUNDARIES: Final[tuple[int, ...]] = (0, 1, 23, 24, 255, 256, 65535, 65536)

MAX_OUTPUT_BYTES: Final = 65536

MAX_PATH_COMPONENT_BYTES: Final = 64

PATH_SEPARATOR: Final = 0x2F

_NUL: Final = 0x00

# `.` and `..` are byte sequences a filesystem holds, but they name an existing directory
# rather than a new entry, so a generator that produced them would make "a written file reads
# back byte-identically and appears in its directory listing" untestable rather than false.
RESERVED_PATH_COMPONENTS: Final[tuple[bytes, ...]] = (b".", b"..")

_FORBIDDEN_IN_COMPONENT: Final = bytes((_NUL, PATH_SEPARATOR))

# Enough arbitrary bytes to surround a spliced adversarial run without dominating it.
_SPLICE_MARGIN: Final = 64


def _fitting(sequences: tuple[bytes, ...], max_size: int) -> tuple[bytes, ...]:
    fitted = tuple(sequence for sequence in sequences if len(sequence) <= max_size)
    # Every class holds at least one sequence of three bytes or fewer, so this only empties
    # under a max_size no caller has a use for.
    if not fitted:
        raise ValueError(f"no adversarial sequence fits in {max_size} bytes")
    return fitted


def _exact_length(size: int) -> SearchStrategy[bytes]:
    return st.binary(min_size=size, max_size=size)


def _boundary_lengths(max_size: int) -> SearchStrategy[bytes]:
    """Byte sequences whose length sits on a CBOR length-prefix width boundary."""
    boundaries = tuple(size for size in CBOR_LENGTH_BOUNDARIES if size <= max_size)
    return st.sampled_from(boundaries).flatmap(_exact_length)


@st.composite
def _spliced(draw: st.DrawFn, max_size: int) -> bytes:
    """Arbitrary bytes with one adversarial run embedded at a drawn offset.

    The mixed case rather than the pure one: real process output is mostly ordinary text with
    an invalid sequence somewhere inside it, and a codec that transcodes only when the whole
    payload is invalid would pass against the pure cases alone.
    """
    margin = min(_SPLICE_MARGIN, max_size)
    prefix = draw(st.binary(max_size=margin))
    run = draw(st.sampled_from(_fitting(ADVERSARIAL_BYTE_SEQUENCES, max_size)))
    suffix = draw(st.binary(max_size=margin))
    return (prefix + run + suffix)[:max_size]


def output_bytes(*, max_size: int = MAX_OUTPUT_BYTES) -> SearchStrategy[bytes]:
    """Byte sequences a process may write, adversarial cases at raised weight (R8.9).

    Four branches, drawn with roughly equal weight, so three quarters of the domain is
    adversarial rather than the vanishing fraction an unweighted `binary()` would give:
    arbitrary bytes including empty, the named adversarial sequences, sequences whose length
    crosses a CBOR length-prefix width boundary, and arbitrary bytes with an adversarial run
    spliced in.
    """
    if max_size < min(len(s) for s in ADVERSARIAL_BYTE_SEQUENCES):
        raise ValueError(
            f"max_size {max_size} is too small to carry any adversarial case"
        )
    return st.one_of(
        st.binary(max_size=min(max_size, 256)),
        st.sampled_from(_fitting(ADVERSARIAL_BYTE_SEQUENCES, max_size)),
        _boundary_lengths(max_size),
        _spliced(max_size),
    )


def _scrub(data: bytes) -> bytes:
    """Drop the two bytes a path component cannot contain, keeping the rest verbatim."""
    return data.translate(None, delete=_FORBIDDEN_IN_COMPONENT)


def _is_usable_component(component: bytes) -> bool:
    return bool(component) and component not in RESERVED_PATH_COMPONENTS


def path_component(
    *, max_size: int = MAX_PATH_COMPONENT_BYTES
) -> SearchStrategy[bytes]:
    """One filesystem name: arbitrary bytes excluding NUL and the path separator.

    Drawn from the same adversarial domain as process output, so filenames that are not valid
    UTF-8 are covered — a filename on a Linux filesystem is a byte sequence, and a generator
    restricted to text would never reach the names the Sandbox can create. NUL and `/` are
    excluded because the kernel cannot represent them inside a component, not as a
    simplification.
    """
    return (
        st.one_of(
            st.binary(min_size=1, max_size=max_size),
            st.sampled_from(_fitting(ADVERSARIAL_BYTE_SEQUENCES, max_size)),
            _spliced(max_size),
        )
        .map(_scrub)
        .filter(_is_usable_component)
    )
