// kiro-classification: public
//
// The wire format: CBOR restricted to RFC 8949's deterministic encoding profile.
//
// Two functions, and they are inverses on the domain the profile admits. `encodeValue` can only
// emit the profile — every head is written at its shortest width, every string and container is
// definite-length, and every map's entries are sorted by their encoded key bytes — so there is no
// canonicalisation pass to maintain and no way for a caller to ask for a non-canonical encoding.
// `decodeValue` accepts only the profile, and that is the half that needs the argument:
//
// R8.5 requires that deserialising a representation and re-serialising it produce bytes identical
// to the input. An encoder that always emits the profile gets that for free *provided* the decoder
// never accepts anything the encoder cannot reproduce. Two indefinite-length chunks, a length
// written in four bytes where one would do, or a map whose keys ascend in the wrong order all decode
// to a perfectly ordinary value under a permissive reader — and re-encoding that value yields
// different bytes. So the criterion is met by refusing those representations, not by tolerating them
// and hoping the re-encoding matches. That is why the design calls a non-deterministic encoding a
// decode error rather than a curiosity.
//
// ## Why `cbor-x` is not the codec
//
// The package is pinned and is a fine general-purpose CBOR library; it is not a deterministic
// profile implementation, in three ways that each break a requirement outright:
//
// - It has no canonical map ordering at all. `new Map([[-1n, 0], [24, 0]])` and the same two
//   entries in the other order encode to different bytes, because insertion order is preserved.
//   RFC 8949 §4.2.1 fixes one order. (The Python half found `cbor2` orders keys by RFC 7049 §3.9's
//   superseded shortest-encoding-first rule; `cbor-x` does not order them at all.)
// - It does not always write shortest-form heads: -1 comes out as `3b` and eight zero bytes.
// - Its decoder is permissive, and on text strings it is destructive. Non-shortest heads and
//   out-of-order map keys are accepted, duplicate keys are silently dropped, and an invalid UTF-8
//   sequence inside a text string is replaced with U+FFFD rather than refused — which loses the
//   bytes that arrived, so R8.5 fails on the way back out and there is nothing the caller can do
//   about it.
//
// So the profile is implemented here, on `cbor.ts`'s scanner, exactly as the Python half is. The
// pinned library keeps its place as an independent cross-check in the tests, which is what a second
// implementation is good for and all it is good for here.
//
// The structural work is `cbor.ts`'s: `encodeHead` writes heads, and `scan` locates every item while
// rejecting ill-formed CBOR, indefinite lengths, non-shortest heads, reserved additional
// information, unused simple values, floats, tags, truncation and trailing bytes. What is added here
// is what a scanner cannot see from one item's head: map key ordering, strict UTF-8 for text
// strings, and the guard against a map whose keys are distinct on the wire but equal once decoded.

import {
  FALSE_SIMPLE,
  type Item,
  MAX_HEAD_ARGUMENT,
  Major,
  TRUE_SIMPLE,
  CborScanError,
  compareBytes,
  concat,
  encodeHead,
  entries as mapEntries,
  payloadStart,
  scan,
} from './cbor.js'
import { NonCanonicalEncoding, UnencodableValue } from './errors.js'
import { type Value, narrowInteger } from './values.js'

// --- Encoding ---------------------------------------------------------------------------------

/**
 * Encode one value under the deterministic profile.
 *
 * Throws `UnencodableValue` for anything outside the protocol's value space, rather than reaching
 * for a CBOR feature — a float, a tag, a bignum — that no message declares and that the decoder
 * would refuse on the way back in.
 */
export function encodeValue(value: Value): Uint8Array {
  if (typeof value === 'boolean') {
    return encodeHead(Major.SIMPLE, value ? TRUE_SIMPLE : FALSE_SIMPLE)
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      // A float is a CBOR value and not a Sandbox_Protocol one. Refusing it here is what keeps
      // `decode(encode(x))` total on the encoder's own output.
      throw new UnencodableValue(`nothing in this protocol encodes the non-integer ${value}`)
    }
    return encodeInteger(BigInt(value))
  }
  if (typeof value === 'bigint') {
    return encodeInteger(value)
  }
  if (typeof value === 'string') {
    const payload = encodeText(value)
    return concat([encodeHead(Major.TEXT, BigInt(payload.length)), payload])
  }
  if (value instanceof Uint8Array) {
    return concat([encodeHead(Major.BYTES, BigInt(value.length)), value])
  }
  if (Array.isArray(value)) {
    const items = (value as readonly Value[]).map(encodeValue)
    return concat([encodeHead(Major.ARRAY, BigInt(items.length)), ...items])
  }
  if (value instanceof Map) {
    return encodeMap(value as ReadonlyMap<Value, Value>)
  }
  throw new UnencodableValue(`nothing in this protocol encodes a ${describe(value)}`)
}

function describe(value: unknown): string {
  if (value === null) {
    return 'null'
  }
  if (typeof value === 'object') {
    return value.constructor?.name ?? 'plain object'
  }
  return typeof value
}

/** Major type 0 for a non-negative value, major type 1 for a negative one. */
function encodeInteger(value: bigint): Uint8Array {
  const major = value >= 0n ? Major.UINT : Major.NEGINT
  const argument = value >= 0n ? value : -1n - value
  if (argument > MAX_HEAD_ARGUMENT) {
    // Encodable only as a bignum, which is a tag, which this protocol does not declare.
    throw new UnencodableValue(`integer ${value} does not fit in a CBOR head`)
  }
  return encodeHead(major, argument)
}

/**
 * UTF-8, strictly. A text string with no UTF-8 encoding is not a text string.
 *
 * An unpaired surrogate is the case that reaches here, and it has to be detected rather than
 * encoded: `TextEncoder` substitutes U+FFFD for one silently, so encoding first and checking after
 * would emit a *different* string from the one handed in and call it a success. Refusing is not a
 * narrowing of R8.9 either — process output and filesystem names are byte-typed throughout the
 * catalogue precisely so the sequences with no UTF-8 encoding travel as major type 2, where nothing
 * interprets them.
 */
function encodeText(value: string): Uint8Array {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit < 0xd800 || unit > 0xdfff) {
      continue
    }
    const low = index + 1 < value.length ? value.charCodeAt(index + 1) : Number.NaN
    const paired = unit <= 0xdbff && low >= 0xdc00 && low <= 0xdfff
    if (!paired) {
      throw new UnencodableValue(
        `a text string must be UTF-8 encodable: unpaired surrogate ` +
          `U+${unit.toString(16).toUpperCase()} at index ${index}`,
      )
    }
    index += 1
  }
  return new TextEncoder().encode(value)
}

/**
 * A definite-length map whose entries ascend by encoded key bytes.
 *
 * Bytewise on the *encoded* key, which is what RFC 8949 §4.2.1 specifies and is not the same as
 * ordering by decoded value: key -1 encodes as `20` and sorts above key 256's `19 01 00`, though it
 * is the smaller number. Nor is it the same as ordering by length first, which is the rule RFC
 * 7049's canonical form used and this profile replaced.
 *
 * Two keys that encode to the same bytes are refused. A `Map` compares its keys by identity, so it
 * holds two entries for two distinct `Uint8Array` objects carrying the same bytes — a distinction
 * CBOR has no way to express, and one Python's `dict` collapses before an encoder ever sees it.
 * Emitting the duplicate would produce bytes this codec's own decoder refuses, so the value is not
 * an encodable one.
 */
function encodeMap(value: ReadonlyMap<Value, Value>): Uint8Array {
  const encoded = [...value].map(
    ([key, item]) => [encodeValue(key), encodeValue(item)] as const,
  )
  encoded.sort((left, right) => compareBytes(left[0], right[0]))
  for (let index = 1; index < encoded.length; index += 1) {
    const previous = encoded[index - 1]
    const current = encoded[index]
    if (previous === undefined || current === undefined) {
      continue
    }
    if (compareBytes(previous[0], current[0]) === 0) {
      throw new UnencodableValue('two map keys encode to the same bytes, which no CBOR map can carry')
    }
  }
  return concat([
    encodeHead(Major.MAP, BigInt(encoded.length)),
    ...encoded.flatMap(([key, item]) => [key, item]),
  ])
}

// --- Decoding ---------------------------------------------------------------------------------

/**
 * Decode one complete deterministic-profile CBOR value.
 *
 * Throws `NonCanonicalEncoding` for ill-formed CBOR, for any profile violation, and for trailing
 * bytes after the first item — a message is one item, and silently decoding the first of two would
 * leave the rest unaccounted for.
 */
export function decodeValue(wire: Uint8Array): Value {
  let root: Item
  try {
    root = scan(wire)
  } catch (error) {
    if (error instanceof CborScanError) {
      throw new NonCanonicalEncoding(error.message)
    }
    throw error
  }
  return materialise(wire, root)
}

function materialise(wire: Uint8Array, item: Item): Value {
  switch (item.major) {
    case Major.UINT:
      return narrowInteger(item.argument)
    case Major.NEGINT:
      return narrowInteger(-1n - item.argument)
    case Major.BYTES:
      // Copied rather than a view: a subarray keeps the whole representation alive and would let a
      // caller mutate the buffer a later re-encoding reads from.
      return wire.slice(payloadStart(item), item.end)
    case Major.TEXT:
      return materialiseText(wire, item)
    case Major.ARRAY:
      return item.children.map((child) => materialise(wire, child))
    case Major.MAP:
      return materialiseMap(wire, item)
    case Major.SIMPLE:
      // `scan` admits only false and true here.
      return item.argument === TRUE_SIMPLE
  }
}

/**
 * Strict UTF-8. Anything else is not re-encodable, so it cannot be accepted.
 *
 * `fatal` rejects overlong forms, surrogate encodings and truncated sequences, which is what makes
 * `decode` then `encode` the identity on text: every accepted payload has exactly one encoding, and
 * it is the one that arrived. `ignoreBOM` is on for the same reason and is not cosmetic — the
 * default strips a leading U+FEFF, so `ef bb bf` would decode to the empty string and re-encode to
 * nothing, silently losing three bytes.
 */
function materialiseText(wire: Uint8Array, item: Item): string {
  const payload = wire.subarray(payloadStart(item), item.end)
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(payload)
  } catch (error) {
    throw new NonCanonicalEncoding(
      `a text string must be valid UTF-8: ${error instanceof Error ? error.message : error}`,
      item.start,
    )
  }
}

function materialiseMap(wire: Uint8Array, item: Item): ReadonlyMap<Value, Value> {
  const built = new Map<Value, Value>()
  let previous: Uint8Array | null = null
  const pairs = mapEntries(item)
  for (const [keyItem, valueItem] of pairs) {
    const encodedKey = wire.subarray(keyItem.start, keyItem.end)
    if (previous !== null && compareBytes(encodedKey, previous) <= 0) {
      const detail =
        compareBytes(encodedKey, previous) === 0
          ? 'duplicate map key'
          : 'map keys must ascend by encoded bytes'
      throw new NonCanonicalEncoding(detail, keyItem.start)
    }
    previous = encodedKey
    built.set(materialise(wire, keyItem), materialise(wire, valueItem))
  }
  if (built.size !== pairs.length) {
    // Two keys distinct on the wire but equal once decoded. Unreachable on this side, because the
    // ordering rule above already refuses equal encoded keys and a `Map` keys by identity, so no
    // two distinct encodings collapse. It is asserted anyway: the Python half needs it — `00` is
    // integer 0 and `f4` is false, and a `dict` holds one entry for both — and a decoder that
    // returned fewer entries than arrived could not re-encode to the input either way.
    throw new NonCanonicalEncoding(
      `${pairs.length} map keys collapse to ${built.size} once decoded`,
      item.start,
    )
  }
  return built
}
