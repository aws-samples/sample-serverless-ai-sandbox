// kiro-classification: public
//
// `nonCanonicalVariant()`: parseable encodings that violate the deterministic profile.
//
// The fast-check half of `wire.py`. The design's generator for the second half of Property 2 rewrites
// one encoded item of a canonical encoding into an equivalent non-deterministic form: an
// indefinite-length string or map, a non-shortest integer or length encoding, or a map with keys out
// of sorted order. Each rewrite is *equivalent* — a permissive CBOR reader decodes the variant to the
// same value — which is what makes the property a statement about the profile rather than about
// well-formedness. A codec that accepted one would break R8.5, because re-encoding under the profile
// would produce different bytes than were received.
//
// Composition is the caller's, as the design states it: draw an encoding from `encode(message())` and
// chain it through here.
//
//     message().map(encode).chain(nonCanonicalVariant)
//
// This module reaches into `protocol/codec/cbor.ts` for the scanner, which is the direction the Python
// half also runs in: `_cbor.py` sits above both the codec and the generators there for the same
// reason. It is structural CBOR and nothing else — no schema, no codec, no fast-check — so a generator
// built on it borrows no judgement from the implementation it is used to test.

import fc from 'fast-check'

import {
  BREAK,
  INDEFINITE_INFO,
  type Item,
  Major,
  encodeHead,
  entries as mapEntries,
  hasArgument,
  isContainer,
  isString,
  payloadStart,
  replace,
  scan,
  walk,
  widerWidths,
} from '../codec/cbor.js'

/** Which rule of RFC 8949's deterministic encoding profile the variant breaks. */
export type Violation =
  /** A byte or text string re-expressed as an indefinite-length item with one chunk. */
  | 'indefinite-string'
  /** An array or map re-expressed as an indefinite-length container. */
  | 'indefinite-container'
  /** A head argument written in a wider form than the value requires. */
  | 'non-shortest-head'
  /** Two adjacent map entries transposed, so the keys no longer ascend by encoded bytes. */
  | 'unsorted-map-keys'

/** One rewritten encoding, with the rule it breaks and where. */
export interface NonCanonical {
  readonly canonical: Uint8Array
  readonly wire: Uint8Array
  readonly violation: Violation
  /** Offset of the item the rewrite addressed, for a failure message that says where. */
  readonly at: number
}

type Rewrite = (data: Uint8Array) => Uint8Array

interface Candidate {
  readonly violation: Violation
  readonly at: number
  readonly rewrite: Rewrite
}

/** `58 03 616263` becomes `5f 43 616263 ff`: same payload, indefinite head. */
function indefiniteString(item: Item): Rewrite {
  return (data) => {
    const payload = data.subarray(payloadStart(item), item.end)
    const chunked = concatBytes([
      new Uint8Array([(item.major << 5) | INDEFINITE_INFO]),
      encodeHead(item.major, BigInt(payload.length)),
      payload,
      new Uint8Array([BREAK]),
    ])
    return replace(data, item.start, item.end, chunked)
  }
}

/** The entries are untouched; only the head and the terminator change. */
function indefiniteContainer(item: Item): Rewrite {
  return (data) => {
    const payload = data.subarray(payloadStart(item), item.end)
    const opened = concatBytes([
      new Uint8Array([(item.major << 5) | INDEFINITE_INFO]),
      payload,
      new Uint8Array([BREAK]),
    ])
    return replace(data, item.start, item.end, opened)
  }
}

function nonShortestHead(item: Item, width: number): Rewrite {
  return (data) =>
    replace(data, item.start, payloadStart(item), encodeHead(item.major, item.argument, width))
}

/**
 * Swap entries `index` and `index + 1` of a map.
 *
 * The input is canonical, so every adjacent pair is in ascending encoded-byte order and any
 * transposition breaks the ordering rule.
 */
function transposedEntries(item: Item, index: number): Rewrite {
  const pairs = mapEntries(item)
  const first = pairs[index]
  const second = pairs[index + 1]
  if (first === undefined || second === undefined) {
    throw new RangeError(`a map with ${pairs.length} entries has no pair at ${index}`)
  }
  return (data) => {
    const left = data.subarray(first[0].start, first[1].end)
    const right = data.subarray(second[0].start, second[1].end)
    return replace(data, first[0].start, second[1].end, concatBytes([right, left]))
  }
}

/** Every single-item rewrite available in this encoding. */
function candidates(root: Item): Candidate[] {
  const found: Candidate[] = []
  for (const item of walk(root)) {
    if (isString(item)) {
      found.push({
        violation: 'indefinite-string',
        at: item.start,
        rewrite: indefiniteString(item),
      })
    }
    if (isContainer(item)) {
      found.push({
        violation: 'indefinite-container',
        at: item.start,
        rewrite: indefiniteContainer(item),
      })
    }
    if (hasArgument(item)) {
      for (const width of widerWidths(item.argument)) {
        found.push({
          violation: 'non-shortest-head',
          at: item.start,
          rewrite: nonShortestHead(item, width),
        })
      }
    }
    if (item.major === Major.MAP && item.argument >= 2n) {
      for (let index = 0; index < Number(item.argument) - 1; index += 1) {
        found.push({
          violation: 'unsorted-map-keys',
          at: item.start,
          rewrite: transposedEntries(item, index),
        })
      }
    }
  }
  return found
}

/**
 * Rewrite one item of `canonical` into an equivalent non-deterministic form.
 *
 * `canonical` must be one complete encoding in the deterministic profile; anything else throws
 * `CborScanError` rather than producing a variant whose only fault is the input's.
 */
export function nonCanonicalVariant(canonical: Uint8Array): fc.Arbitrary<NonCanonical> {
  const available = candidates(scan(canonical))
  if (available.length === 0) {
    // Every message is at least a four-entry map, so this is unreachable through `message()`.
    throw new Error('no deterministic-profile rule is reachable in this encoding')
  }
  return fc.constantFrom(...available).map((candidate) => {
    const wire = candidate.rewrite(canonical)
    if (sameBytes(wire, canonical)) {
      throw new Error(`${candidate.violation} at ${candidate.at} left the encoding unchanged`)
    }
    return { canonical, wire, violation: candidate.violation, at: candidate.at }
  })
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const joined = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    joined.set(part, offset)
    offset += part.length
  }
  return joined
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}
