# kiro-classification: public
"""What the codec raises.

Five failure modes in two groups. The first three are the *internal* ones, raised by the halves
of the codec, and they are genuinely different things rather than three spellings of "bad input":

- `UnencodableValue` — the caller handed the encoder a value no Sandbox_Protocol message can
  carry. A defect on this side of the wire, not a report about a peer.
- `NonCanonicalEncoding` — the bytes are not in RFC 8949's deterministic encoding profile, or
  are not well-formed CBOR at all. Rejecting them is what makes R8.5 hold by construction: a
  representation the codec accepted but could not re-emit byte-identically would break the
  wire round-trip, so the profile is enforced on the way in rather than repaired on the way out.
- `SchemaViolationError` — the value is a CBOR value the profile admits, but not a message the
  catalogue declares. It names the offending field, which is the material R8.6's decode error
  is built from.

The other two are the error *shapes* Requirement 8 fixes, and they are what `decode` raises:

- `DecodeError` — a decode error naming a field (R8.6).
- `VersionError` — a version error carrying the received version and both bounds of the
  supported range (R8.7).

The split is deliberate rather than redundant. The internal three say *which half of the codec
objected*, which is what a maintainer reading a traceback wants; the outer two say *which of the
two things the protocol promises a peer went wrong*, which is what R8.6 and R8.7 fix and what a
peer can act on. `decode` maps one onto the other by re-raising with the `field` and `detail`
already carried, so field identity has a single source — `protocol.codec.validate` reading the
catalogue — rather than being decided a second time at the boundary.

`VersionError` names no field on purpose. A version outside the supported range is not a
malformed field, it is a well-formed statement the codec cannot honour, and R8.8 turns on the two
being distinguishable: a representation carrying both an unsupported version and a schema
violation raises this and not `DecodeError`.
"""

from __future__ import annotations


class CodecError(Exception):
    """Base class for every Protocol_Codec failure."""


class UnencodableValue(CodecError):
    """A value outside the protocol's value space reached the encoder."""


class NonCanonicalEncoding(CodecError):
    """The wire bytes are not one deterministic-profile CBOR value.

    Covers ill-formed CBOR, the profile's own rules — indefinite lengths, non-shortest heads,
    map keys out of sorted order — and anything else the codec could not re-emit byte-identically,
    such as a map whose keys are distinct on the wire but equal once decoded.
    """

    def __init__(self, detail: str, *, at: int | None = None) -> None:
        self.detail = detail
        #: Byte offset of the offending item, where one item is to blame.
        self.at = at
        super().__init__(detail if at is None else f"at byte {at}: {detail}")


class SchemaViolationError(CodecError):
    """A decoded value does not conform to the catalogue, and this is the field at fault.

    `field` is the identity the decode error reports (R8.6). Envelope keys are named by their
    catalogue name — `v`, `t`, `id`, `b` — and body fields are qualified by the envelope's body
    key, so `b.argv` is the `argv` field of the body. Nesting extends the path rather than
    collapsing to the outermost field: `b.entries[2].kind` says which of a listing's entries
    offends, which is the whole value of naming a field in the first place.
    """

    def __init__(self, *, field: str, detail: str) -> None:
        self.field = field
        self.detail = detail
        super().__init__(f"{field}: {detail}")


class DecodeError(CodecError):
    """A wire representation this codec will not accept, and this is the field at fault (R8.6).

    The shape `decode` raises. `field` is the identity the criterion requires it to identify, and
    it is not invented here: Phase 2 re-raises the `field` a `SchemaViolationError` carried, so
    the spelling is the catalogue's — `v`, `b.argv`, `b.entries[2].kind`. Phase 0 is the one case
    with no catalogue name available, and it reports `VERSION_IDENTITY`, the version key's number,
    because at that point there is no schema-conforming envelope to name a field of.

    A representation refused by the deterministic profile below the version field — map keys out
    of order, invalid UTF-8 in a text string — is also a decode error, as the design's decode
    algorithm states, and reports `protocol.codec.validate.ROOT_IDENTITY`. No field is to blame
    for it: the whole representation is the thing the codec could not have emitted.
    """

    def __init__(self, *, field: str, detail: str) -> None:
        self.field = field
        self.detail = detail
        super().__init__(f"{field}: {detail}")


class VersionError(CodecError):
    """The representation's protocol version is outside the range this codec supports (R8.7).

    Carries all three numbers the criterion names — the version received and both bounds — and
    reads both bounds off the catalogue rather than restating them, so widening `supportedMax` in
    `messages.yaml` changes what a peer is told with no edit here. The attribute names are the
    catalogue's `error.version` body field names in `snake_case`, so rendering this into that
    message type is a rename and not a decision.
    """

    def __init__(
        self, *, received: int, supported_min: int, supported_max: int
    ) -> None:
        self.received = received
        self.supported_min = supported_min
        self.supported_max = supported_max
        super().__init__(
            f"protocol version {received} is outside the supported range "
            f"[{supported_min}, {supported_max}]"
        )

    @property
    def supported(self) -> tuple[int, int]:
        """Both bounds of the supported range, inclusive."""
        return (self.supported_min, self.supported_max)
