# kiro-classification: public
"""`encode` and `decode`: a Sandbox_Protocol message to its wire representation and back.

R8.2 and R8.3 are these two functions, and R8.5 is the reason they are composed the way they are.
`encode` validates against the catalogue and *then* encodes, so the codec cannot emit a
representation it would refuse to read back: every byte sequence it produces is both
deterministic-profile CBOR and a message the schema declares. `decode` reverses that — the
profile first, the schema second — because a value has to be a CBOR value before there is
anything to validate.

`encode` also refuses to emit a protocol version outside the supported range. That is not the
decode algorithm's version admissibility check, which belongs on the receiving side; it is the
observation that the catalogue names the version the codec emits, so emitting another one would
produce a representation this codec could not itself accept. It is also what lets the fault
generator build an unsupported-version input by byte surgery over a canonical encoding and know
that the encoder played no part in it.

Version admissibility on decode is the receiving side's, and it is `decode`'s first concern rather
than its last. The decode algorithm the design fixes has three phases — structural extraction of
the version, admissibility of that version, then schema validation — and the phase *order* is the
whole mechanism for R8.8, so the two error shapes it selects between are part of the same piece of
work. Phases 0 and 1 are `protocol.codec.version`; Phase 2 is `decode_value` followed by
`validate`, which is what `decode` already was. The phases layer in front of that rather than
replacing it.

`decode` therefore raises exactly two things, and they are the two Requirement 8 fixes:
`DecodeError` naming a field (R8.6) and `VersionError` carrying the received version and both
bounds (R8.7). The codec's internal failures — `NonCanonicalEncoding` from the profile,
`SchemaViolationError` from the schema — are mapped onto the first by re-raising the `field` and
`detail` they already carry. `encode` is the other way round: it raises the internal shapes,
because a caller who hands the encoder an inadmissible message has a defect on this side of the
wire, not a decode error to report to a peer.
"""

from __future__ import annotations

from protocol.codec.errors import (
    DecodeError,
    NonCanonicalEncoding,
    SchemaViolationError,
)
from protocol.codec.profile import decode_value, encode_value
from protocol.codec.validate import ROOT_IDENTITY, envelope_field_name, validate
from protocol.codec.values import Message, Value
from protocol.codec.version import read_version, require_supported
from protocol.schema import ENVELOPE_KEY_VERSION, Catalogue, load_catalogue

__all__ = ["decode", "encode"]


def encode(message: Message, *, catalogue: Catalogue | None = None) -> bytes:
    """Serialise `message` into its wire representation (R8.2).

    Raises `SchemaViolationError` if `message` is not one the catalogue declares, naming the
    offending field. Byte-typed fields are carried verbatim: no transcoding, no escaping and no
    validity constraint, which is what makes R8.9 a property of the format rather than of a
    convention layered over it.
    """
    resolved = catalogue if catalogue is not None else load_catalogue()
    validated: Message = validate(message, catalogue=resolved)

    version = validated[ENVELOPE_KEY_VERSION]
    if not isinstance(version, int) or not resolved.supports(version):
        raise SchemaViolationError(
            field=envelope_field_name(resolved, ENVELOPE_KEY_VERSION),
            detail=f"this codec emits versions in "
            f"[{resolved.supported_min}, {resolved.supported_max}], not {version!r}",
        )

    return encode_value(_as_value_map(validated))


def decode(wire: bytes, *, catalogue: Catalogue | None = None) -> Message:
    """Deserialise a wire representation into a message, in three phases (R8.3, R8.6, R8.7, R8.8).

    Phase 0 reads the protocol version and nothing else. Phase 1 admits that version. Phase 2 is
    the profile and the schema, in that order. The sequence is the whole content of R8.8: Phase 1
    completes before Phase 2 begins, so a representation carrying both an unsupported version and
    a schema violation raises `VersionError` and never reaches the field that would have raised
    `DecodeError`.

    Raises `DecodeError` naming the offending field, or `VersionError` carrying the received
    version and both bounds of the supported range. Those two are the only failures a caller sees;
    the internal `NonCanonicalEncoding` and `SchemaViolationError` are mapped onto them, carrying
    their `field` and `detail` across rather than deciding either a second time.
    """
    resolved = catalogue if catalogue is not None else load_catalogue()

    # Phase 0 — structural extraction of the version only.
    version = read_version(wire)

    # Phase 1 — version admissibility, before any other field is inspected.
    require_supported(version, catalogue=resolved)

    # Phase 2 — the deterministic profile, then the schema.
    try:
        value = decode_value(wire)
    except NonCanonicalEncoding as exc:
        raise DecodeError(field=ROOT_IDENTITY, detail=str(exc)) from exc
    try:
        return validate(value, catalogue=resolved)
    except SchemaViolationError as exc:
        raise DecodeError(field=exc.field, detail=exc.detail) from exc


def _as_value_map(message: Message) -> dict[Value, Value]:
    """Widen the key type for the encoder.

    Key by key rather than by a cast, because a `dict` is invariant in both parameters: a
    `dict[int, Value]` is not a `dict[Value, Value]` however compatible the two look.
    """
    return {key: item for key, item in message.items()}
