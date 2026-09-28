// kiro-classification: public
//
// The TypeScript Protocol_Codec: Sandbox_Protocol messages to CBOR and back (R8.2, R8.3, R8.9).
//
// The second implementation of the codec `protocol/codec/*.py` specifies, module for module, against
// the same `messages.yaml` and emitting the same deterministic profile. It sits in this directory
// rather than inside the SDK for the reason `protocol/generators/` holds both languages' generator
// halves: the two are one artefact stated twice, and a schema change has to reach both or fail.
//
// CBOR as RFC 8949 specifies it, restricted to the deterministic encoding profile of §4.2. Four
// consequences of that choice are visible in the shape of this package:
//
// - Byte-typed fields are major type 2 and travel verbatim, so process output containing invalid
//   UTF-8 survives a serialise and deserialise cycle unchanged (R8.9). Nothing here decodes a byte
//   string as text, and the catalogue is what says which fields are byte-typed.
// - The profile is enforced in both directions, which is what makes the wire round-trip byte-exact
//   without a canonicalisation pass (R8.5). See `profile.ts`, which also records why the pinned
//   `cbor-x` could not be the codec.
// - Field identity is the catalogue's, so a violation names a field the way the schema names it
//   (R8.6). See `errors.ts` and `validate.ts`.
// - The protocol version is read and admitted before any other field is validated, which is what
//   makes R8.8 an ordering fact rather than a promise about error messages. See `version.ts`.
//
// | Module | Answers |
// | --- | --- |
// | `cbor` | Where are the items, and is each head one the profile permits? |
// | `values` | What a message and a value are |
// | `equal` | When two of them are the same value, which JavaScript does not answer |
// | `catalogue` | The one seam onto the schema mirror |
// | `profile` | Are these bytes one deterministic-profile CBOR value? |
// | `version` | What version does this representation carry, and do we support it? |
// | `validate` | Is that value a message the catalogue declares, and if not, which field is wrong? |
// | `messages` | `encode` and `decode`, the latter composed as Phase 0, Phase 1, Phase 2 |
//
// The vector corpus (task 2.10) is what checks that the two implementations agree on the wire, rather
// than assuming two independent round-trips imply it.

export {
  BREAK,
  CborScanError,
  INDEFINITE_INFO,
  type Item,
  MAX_HEAD_ARGUMENT,
  Major,
  compareBytes,
  concat,
  encodeHead,
  entries,
  hasArgument,
  isContainer,
  isString,
  minimalWidth,
  payloadStart,
  replace,
  scan,
  walk,
  widerWidths,
} from './cbor.js'

export { valueIdentity, valuesEqual } from './equal.js'

export {
  CodecError,
  DecodeError,
  NonCanonicalEncoding,
  SchemaViolation,
  UnencodableValue,
  VersionError,
} from './errors.js'

export { decode, encode } from './messages.js'

export { decodeValue, encodeValue } from './profile.js'

export { ROOT_IDENTITY, envelopeFieldName, validate } from './validate.js'

export { type Message, type Value, narrowInteger } from './values.js'

export { VERSION_IDENTITY, readVersion, requireSupported } from './version.js'

export {
  type Catalogue,
  ENVELOPE_KEY_BODY,
  ENVELOPE_KEY_ID,
  ENVELOPE_KEY_TYPE,
  ENVELOPE_KEY_VERSION,
  type Field,
  type MessageType,
  type TypeSpec,
  loadCatalogue,
  messageTypes,
  supports,
} from './catalogue.js'
