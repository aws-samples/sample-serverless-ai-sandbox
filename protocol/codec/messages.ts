// kiro-classification: public
//
// `encode` and `decode`: a Sandbox_Protocol message to its wire representation and back.
//
// R8.2 and R8.3 are these two functions, and R8.5 is the reason they are composed the way they are.
// `encode` validates against the catalogue and *then* encodes, so the codec cannot emit a
// representation it would refuse to read back: every byte sequence it produces is both
// deterministic-profile CBOR and a message the schema declares. `decode` reverses that — the profile
// first, the schema second — because a value has to be a CBOR value before there is anything to
// validate.
//
// `encode` also refuses to emit a protocol version outside the supported range. That is not the
// decode algorithm's version admissibility check, which belongs on the receiving side; it is the
// observation that the catalogue names the version the codec emits, so emitting another one would
// produce a representation this codec could not itself accept. It is also what lets the fault
// generator build an unsupported-version input by byte surgery over a canonical encoding and know
// that the encoder played no part in it.
//
// Version admissibility on decode is the receiving side's, and it is `decode`'s first concern rather
// than its last. The decode algorithm the design fixes has three phases — structural extraction of the
// version, admissibility of that version, then schema validation — and the phase *order* is the whole
// mechanism for R8.8, so the two error shapes it selects between are part of the same piece of work.
// Phases 0 and 1 are `version.ts`; Phase 2 is `decodeValue` followed by `validate`.
//
// `decode` therefore throws exactly two things, and they are the two Requirement 8 fixes:
// `DecodeError` naming a field (R8.6) and `VersionError` carrying the received version and both
// bounds (R8.7). The codec's internal failures — `NonCanonicalEncoding` from the profile,
// `SchemaViolation` from the schema — are mapped onto the first by re-throwing the `field` and
// `detail` they already carry. `encode` is the other way round: it throws the internal shapes, because
// a caller who hands the encoder an inadmissible message has a defect on this side of the wire, not a
// decode error to report to a peer.

import { type Catalogue, ENVELOPE_KEY_VERSION, loadCatalogue, supports } from './catalogue.js'
import { DecodeError, NonCanonicalEncoding, SchemaViolation } from './errors.js'
import { decodeValue, encodeValue } from './profile.js'
import { ROOT_IDENTITY, envelopeFieldName, validate } from './validate.js'
import type { Message, Value } from './values.js'
import { readVersion, requireSupported } from './version.js'

/**
 * Serialise `message` into its wire representation (R8.2).
 *
 * Throws `SchemaViolation` if `message` is not one the catalogue declares, naming the offending field.
 * Byte-typed fields are carried verbatim: no transcoding, no escaping and no validity constraint,
 * which is what makes R8.9 a property of the format rather than of a convention layered over it.
 */
export function encode(message: Message, catalogue: Catalogue = loadCatalogue()): Uint8Array {
  const validated = validate(message, catalogue)

  const version = validated.get(ENVELOPE_KEY_VERSION)
  const readable = typeof version === 'number' || typeof version === 'bigint'
  if (!readable || !supports(catalogue, version)) {
    throw new SchemaViolation(
      envelopeFieldName(catalogue, ENVELOPE_KEY_VERSION),
      `this codec emits versions in [${catalogue.supportedMin}, ${catalogue.supportedMax}], ` +
        `not ${String(version)}`,
    )
  }

  return encodeValue(validated as ReadonlyMap<Value, Value>)
}

/**
 * Deserialise a wire representation into a message, in three phases (R8.3, R8.6, R8.7, R8.8).
 *
 * Phase 0 reads the protocol version and nothing else. Phase 1 admits that version. Phase 2 is the
 * profile and the schema, in that order. The sequence is the whole content of R8.8: Phase 1 completes
 * before Phase 2 begins, so a representation carrying both an unsupported version and a schema
 * violation throws `VersionError` and never reaches the field that would have thrown `DecodeError`.
 *
 * Throws `DecodeError` naming the offending field, or `VersionError` carrying the received version and
 * both bounds of the supported range. Those two are the only failures a caller sees; the internal
 * `NonCanonicalEncoding` and `SchemaViolation` are mapped onto them, carrying their `field` and
 * `detail` across rather than deciding either a second time.
 */
export function decode(wire: Uint8Array, catalogue: Catalogue = loadCatalogue()): Message {
  // Phase 0 — structural extraction of the version only.
  const version = readVersion(wire)

  // Phase 1 — version admissibility, before any other field is inspected.
  requireSupported(version, catalogue)

  // Phase 2 — the deterministic profile, then the schema.
  let value: Value
  try {
    value = decodeValue(wire)
  } catch (error) {
    if (error instanceof NonCanonicalEncoding) {
      throw new DecodeError(ROOT_IDENTITY, error.message)
    }
    throw error
  }
  try {
    return validate(value, catalogue)
  } catch (error) {
    if (error instanceof SchemaViolation) {
      throw new DecodeError(error.field, error.detail)
    }
    throw error
  }
}
