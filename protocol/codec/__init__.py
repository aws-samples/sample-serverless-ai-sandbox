# kiro-classification: public
"""The Protocol_Codec: Sandbox_Protocol messages to CBOR and back (R8.2, R8.3, R8.9).

CBOR as RFC 8949 specifies it, restricted to the deterministic encoding profile of §4.2. The
design settles that choice against Requirement 8's constraint set rather than by preference, and
three of its consequences are visible in the shape of this package:

- Byte-typed fields are major type 2 and travel verbatim, so process output containing invalid
  UTF-8 survives a serialise and deserialise cycle unchanged (R8.9). Nothing here decodes a byte
  string as text, and the catalogue is what says which fields are byte-typed.
- The profile is enforced in both directions, which is what makes the wire round-trip byte-exact
  without a canonicalisation pass (R8.5). See `protocol.codec.profile`.
- Field identity is the catalogue's, so a violation names a field the way the schema names it
  (R8.6). See `protocol.codec.errors`.
- The protocol version is read and admitted before any other field is validated, which is what
  makes R8.8 an ordering fact rather than a promise about error messages. See
  `protocol.codec.version`.

Five modules, split along the lines the failures fall on:

| Module | Answers |
| --- | --- |
| `values` | What a message and a value are |
| `profile` | Are these bytes one deterministic-profile CBOR value? |
| `version` | What version does this representation carry, and do we support it? |
| `validate` | Is that value a message the catalogue declares, and if not, which field is wrong? |
| `messages` | `encode` and `decode`, the latter composed as Phase 0, Phase 1, Phase 2 |

The TypeScript codec is the `*.ts` half of this same directory — `cbor.ts`, `values.ts`,
`profile.ts`, `version.ts`, `validate.ts`, `messages.ts` — placed beside the modules that specify
it for the reason `protocol/generators/` holds both languages' generator halves: the two are one
artefact stated twice, and a schema change has to reach both or fail. It validates against the
same `messages.yaml`, through the `catalogue.json` mirror `protocol/generators/export_catalogue.py`
writes, and emits the same profile. The vector corpus is what checks that claim in both directions
rather than assuming two independent round-trips imply wire agreement.
"""

from __future__ import annotations

from protocol.codec.errors import (
    CodecError,
    DecodeError,
    NonCanonicalEncoding,
    SchemaViolationError,
    UnencodableValue,
    VersionError,
)
from protocol.codec.messages import decode, encode
from protocol.codec.profile import decode_value, encode_value
from protocol.codec.validate import ROOT_IDENTITY, envelope_field_name, validate
from protocol.codec.values import Message, Value
from protocol.codec.version import VERSION_IDENTITY, read_version, require_supported

__all__ = [
    "ROOT_IDENTITY",
    "VERSION_IDENTITY",
    "CodecError",
    "DecodeError",
    "Message",
    "NonCanonicalEncoding",
    "SchemaViolationError",
    "UnencodableValue",
    "Value",
    "VersionError",
    "decode",
    "decode_value",
    "encode",
    "encode_value",
    "envelope_field_name",
    "read_version",
    "require_supported",
    "validate",
]
