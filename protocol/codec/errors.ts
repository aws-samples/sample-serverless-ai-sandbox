// kiro-classification: public
//
// What the TypeScript codec throws. The same five failure modes as `protocol/codec/errors.py`,
// with the same split and the same attribute names, because the two halves report the same two
// things to a peer and a difference between them would be a difference in the protocol.
//
// The first three are the *internal* ones, thrown by the halves of the codec, and they are
// genuinely different things rather than three spellings of "bad input":
//
// - `UnencodableValue` — the caller handed the encoder a value no Sandbox_Protocol message can
//   carry. A defect on this side of the wire, not a report about a peer.
// - `NonCanonicalEncoding` — the bytes are not in RFC 8949's deterministic encoding profile, or
//   are not well-formed CBOR at all. Rejecting them is what makes R8.5 hold by construction.
// - `SchemaViolation` — the value is a CBOR value the profile admits, but not a message the
//   catalogue declares. It names the offending field, which is the material R8.6's decode error
//   is built from.
//
// The other two are the error *shapes* Requirement 8 fixes, and they are what `decode` throws:
// `DecodeError` naming a field (R8.6), and `VersionError` carrying the received version and both
// bounds of the supported range (R8.7).
//
// `VersionError` names no field on purpose. A version outside the supported range is not a
// malformed field, it is a well-formed statement the codec cannot honour, and R8.8 turns on the
// two being distinguishable: a representation carrying both an unsupported version and a schema
// violation throws this and not `DecodeError`. Neither extends the other, so `instanceof` is a
// test of which arrived.
//
// The Python half names the schema failure `SchemaViolationError`; here it is `SchemaViolation`,
// because `Error` is already in the name of every class in this file through the base and the
// doubled suffix reads badly in TypeScript. The `field` and `detail` attributes are identical,
// and those are what cross the wire.

/** Base class for every Protocol_Codec failure. */
export class CodecError extends Error {
  override readonly name: string = 'CodecError'
}

/** A value outside the protocol's value space reached the encoder. */
export class UnencodableValue extends CodecError {
  override readonly name = 'UnencodableValue'
}

/**
 * The wire bytes are not one deterministic-profile CBOR value.
 *
 * Covers ill-formed CBOR, the profile's own rules — indefinite lengths, non-shortest heads, map
 * keys out of sorted order — and anything else the codec could not re-emit byte-identically, such
 * as a map whose keys are distinct on the wire but equal once decoded.
 */
export class NonCanonicalEncoding extends CodecError {
  override readonly name = 'NonCanonicalEncoding'

  readonly detail: string

  /** Byte offset of the offending item, where one item is to blame. */
  readonly at: number | null

  constructor(detail: string, at: number | null = null) {
    super(at === null ? detail : `at byte ${at}: ${detail}`)
    this.detail = detail
    this.at = at
  }
}

/**
 * A decoded value does not conform to the catalogue, and this is the field at fault.
 *
 * `field` is the identity the decode error reports (R8.6). Envelope keys are named by their
 * catalogue name — `v`, `t`, `id`, `b` — and body fields are qualified by the envelope's body key,
 * so `b.argv` is the `argv` field of the body. Nesting extends the path rather than collapsing to
 * the outermost field: `b.entries[2].kind` says which of a listing's entries offends, which is the
 * whole value of naming a field in the first place.
 */
export class SchemaViolation extends CodecError {
  override readonly name = 'SchemaViolation'

  readonly field: string

  readonly detail: string

  constructor(field: string, detail: string) {
    super(`${field}: ${detail}`)
    this.field = field
    this.detail = detail
  }
}

/**
 * A wire representation this codec will not accept, and this is the field at fault (R8.6).
 *
 * The shape `decode` throws. `field` is not invented here: Phase 2 re-throws the `field` a
 * `SchemaViolation` carried, so the spelling is the catalogue's. Phase 0 is the one case with no
 * catalogue name available, and it reports `VERSION_IDENTITY`, the version key's number, because
 * at that point there is no schema-conforming envelope to name a field of.
 *
 * A representation refused by the deterministic profile below the version field — map keys out of
 * order, invalid UTF-8 in a text string — is also a decode error, as the design's decode algorithm
 * states, and reports `ROOT_IDENTITY`. No field is to blame for it: the whole representation is the
 * thing the codec could not have emitted.
 */
export class DecodeError extends CodecError {
  override readonly name = 'DecodeError'

  readonly field: string

  readonly detail: string

  constructor(field: string, detail: string) {
    super(`${field}: ${detail}`)
    this.field = field
    this.detail = detail
  }
}

/**
 * The representation's protocol version is outside the range this codec supports (R8.7).
 *
 * Carries all three numbers the criterion names — the version received and both bounds — and reads
 * both bounds off the catalogue rather than restating them, so widening `supportedMax` in
 * `messages.yaml` changes what a peer is told with no edit here. The attribute names are the
 * catalogue's `error.version` body field names, so rendering this into that message type is a
 * rename and not a decision.
 *
 * `received` is `bigint` because the envelope's `v` admits the full CBOR unsigned range, and a
 * version error that reported an approximation of the number that arrived would be reporting
 * something the peer did not send.
 */
export class VersionError extends CodecError {
  override readonly name = 'VersionError'

  readonly received: bigint

  readonly supportedMin: bigint

  readonly supportedMax: bigint

  constructor(received: bigint, supportedMin: bigint, supportedMax: bigint) {
    super(
      `protocol version ${received} is outside the supported range ` +
        `[${supportedMin}, ${supportedMax}]`,
    )
    this.received = received
    this.supportedMin = supportedMin
    this.supportedMax = supportedMax
  }

  /** Both bounds of the supported range, inclusive. */
  get supported(): readonly [bigint, bigint] {
    return [this.supportedMin, this.supportedMax]
  }
}
