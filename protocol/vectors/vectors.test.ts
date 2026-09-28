// kiro-classification: public
//
// The TypeScript half of the cross-implementation comparison.
//
// The same two assertions per vector that `test_vectors.py` makes, over the same three committed
// files, so the four legs of the claim are pinned to one artefact: Python's encoder wrote `wire`,
// Python's decoder reads it, and both halves of the TypeScript codec are checked against it here.
//
// - **Interpretation.** `decode(wire)` is compared field by field against the declared values, and
//   the *set* of decoded leaves is compared against the set of declared paths. Comparing only the
//   values would pass a decoder that dropped an optional field; comparing only the paths would pass
//   one that returned the right shape with the wrong bytes in it.
// - **Production.** The message is rebuilt from the declared fields and encoded, and those bytes are
//   asserted equal to `wire`. This is the reverse direction the corpus exists for: it is TypeScript
//   producing an encoding that Python's decoder is separately asserted to read, so the two agree
//   about what to emit and not merely about what to accept. Rebuilding from the file rather than
//   from `decode(wire)` is what makes it a comparison rather than a round-trip the codec would pass
//   against itself — `properties.test.ts` already asserts the round-trip.
//
// No fast-check, and no property tag. Properties 1 through 4 are claimed in `properties.test.ts`,
// this is not one of the 44, and a corpus check reads fixed vectors by design: fresh draws at assert
// time would not be the bytes the other language is reading.
//
// Equality is `valueIdentity`, never `toEqual`. JavaScript compares `Uint8Array` and `Map` by
// identity, so `toEqual` on a decoded message asserts something other than what it appears to.

import { describe, expect, it } from 'vitest'

import { loadCatalogue, messageTypes } from '../codec/catalogue.js'
import {
  DecodeError,
  NonCanonicalEncoding,
  type Value,
  VersionError,
  decode,
  decodeValue,
  encode,
  encodeValue,
  valueIdentity,
} from '../codec/index.js'
import {
  type MessageVector,
  type Path,
  asMessage,
  hex,
  leaves,
  loadMessages,
  loadRejections,
  loadValues,
  pathIdentity,
  rebuild,
  resolve,
} from './vectors.js'

const CATALOGUE = loadCatalogue()

const MESSAGES = loadMessages()
const VALUES = loadValues()
const REJECTIONS = loadRejections()

/** Head-width crossings a corpus has to reach, since a width-selection bug fails only at one. */
const HEAD_WIDTH_CROSSINGS = [0, 23, 24, 255, 256, 65535, 65536, 4294967295]

function label(vector: MessageVector, path: Path): string {
  const named = vector.fields.find((field) => pathIdentity(field.path) === pathIdentity(path))
  return `${vector.name}: ${named?.field ?? pathIdentity(path)}`
}

/** Every byte-string leaf the message vectors carry. */
function byteLeaves(): Set<string> {
  const seen = new Set<string>()
  for (const vector of MESSAGES) {
    for (const field of vector.fields) {
      if (field.expected instanceof Uint8Array) {
        seen.add(hex(field.expected))
      }
    }
  }
  return seen
}

describe('the vector corpus, decoded by the TypeScript codec', () => {
  it('is not empty, so every assertion below is not vacuous', () => {
    expect(MESSAGES.length).toBeGreaterThan(0)
    expect(VALUES.length).toBeGreaterThan(0)
    expect(REJECTIONS.length).toBeGreaterThan(0)
  })

  it('decodes every message vector to the declared fields, field by field', () => {
    for (const vector of MESSAGES) {
      const found = leaves(decode(vector.wire))
      const declared = new Set(vector.fields.map((field) => pathIdentity(field.path)))

      const unexpected = [...found.keys()].filter((identity) => !declared.has(identity))
      const missing = vector.fields
        .filter((field) => !found.has(pathIdentity(field.path)))
        .map((field) => field.field)
      expect(unexpected, `${vector.name}: decoded fields not in the corpus`).toEqual([])
      expect(missing, `${vector.name}: fields the corpus declares and the decode lost`).toEqual([])

      for (const field of vector.fields) {
        const leaf = found.get(pathIdentity(field.path))
        expect(leaf, label(vector, field.path)).toBeDefined()
        expect(
          valueIdentity((leaf as { value: Value }).value),
          label(vector, field.path),
        ).toBe(valueIdentity(field.expected))
      }
    }
  })

  it('finds every declared-absent field absent', () => {
    let checked = 0
    for (const vector of MESSAGES) {
      const decoded = decode(vector.wire)
      for (const entry of vector.absent) {
        checked += 1
        expect(
          resolve(decoded, entry.path).found,
          `${vector.name}: ${entry.field} is declared absent but decoded present`,
        ).toBe(false)
      }
    }
    expect(checked, 'no vector declares an absent field').toBeGreaterThan(0)
  })

  it('re-encodes every message vector to the committed wire', () => {
    for (const vector of MESSAGES) {
      const produced = encode(asMessage(rebuild(vector.fields)))
      expect(hex(produced), `${vector.name}: TypeScript encoded these bytes`).toBe(hex(vector.wire))
    }
  })

  it('agrees on every value-level encoding in both directions', () => {
    for (const vector of VALUES) {
      expect(hex(encodeValue(vector.value)), vector.name).toBe(hex(vector.wire))
      expect(valueIdentity(decodeValue(vector.wire)), vector.name).toBe(
        valueIdentity(vector.value),
      )
    }
  })

  it('refuses every rejection vector with the declared error', () => {
    for (const vector of REJECTIONS) {
      const where = `${vector.name} (${hex(vector.wire)})`
      if (vector.expect === 'non-canonical') {
        expect(() => decodeValue(vector.wire), where).toThrow(NonCanonicalEncoding)
        continue
      }
      let thrown: unknown
      try {
        decode(vector.wire)
      } catch (error) {
        thrown = error
      }
      if (vector.expect === 'version-error') {
        expect(thrown, where).toBeInstanceOf(VersionError)
        const error = thrown as VersionError
        expect(error.received, where).toBe(vector.received)
        expect(error.supportedMin, where).toBe(BigInt(CATALOGUE.supportedMin))
        expect(error.supportedMax, where).toBe(BigInt(CATALOGUE.supportedMax))
        continue
      }
      expect(thrown, where).toBeInstanceOf(DecodeError)
      // A decode error and not a version error: these vectors leave the version's value alone, so
      // a version error would mean the phase order rather than the profile had decided it.
      expect(thrown instanceof VersionError, where).toBe(false)
      const error = thrown as DecodeError
      expect(
        vector.fieldIdentities.includes(error.field),
        `${where} was refused against field '${error.field}', which is not in ` +
          `${[...vector.fieldIdentities].sort().join(', ')}`,
      ).toBe(true)
    }
  })
})

describe('the corpus contents the comparison depends on', () => {
  it('cover every message type the catalogue declares, from both halves', () => {
    const declared = [...messageTypes(CATALOGUE)].sort()
    expect([...new Set(MESSAGES.map((vector) => vector.t))].sort()).toEqual(declared)
    for (const t of declared) {
      for (const origin of ['explicit', 'sampled'] as const) {
        expect(
          MESSAGES.some((vector) => vector.t === t && vector.origin === origin),
          `${t}/${origin}`,
        ).toBe(true)
      }
    }
  })

  it('carry the empty byte string and every CBOR head-width crossing', () => {
    expect(byteLeaves().has('')).toBe(true)
    const integers = new Set<number>()
    for (const vector of MESSAGES) {
      for (const field of vector.fields) {
        if (typeof field.expected === 'number') {
          integers.add(field.expected)
        }
      }
    }
    expect(HEAD_WIDTH_CROSSINGS.filter((at) => !integers.has(at))).toEqual([])
  })

  it('carry nested maps whose keys differ in head width', () => {
    // Where RFC 8949 §4.2.1's bytewise ordering parts company with RFC 7049 §3.9's
    // shortest-encoding-first rule, which is what `cbor2` still emits and what an independently
    // written codec is most likely to have reimplemented by accident. A byte-string step in a path
    // is a nested-map key, and its head width is the encoding length less the payload length.
    const widths = new Set<number>()
    for (const vector of MESSAGES) {
      for (const field of vector.fields) {
        for (const step of field.path) {
          if (step instanceof Uint8Array) {
            widths.add(encodeValue(step).length - step.length)
          }
        }
      }
    }
    expect([...widths].sort((left, right) => left - right).length).toBeGreaterThanOrEqual(3)
  })

  it('carry the recorded counterexample on both sides of the wire', () => {
    // `{-1: 0, 24: 0}` is `a21818002000` under the profile and `a22000181800` under `cbor2`. The
    // first must encode and decode; the second must be refused. A TypeScript codec that took
    // `cbor-x`'s idea of canonical ordering for the profile's would fail both.
    const counterexample = VALUES.find((vector) => vector.name === 'map.keys.cbor2-counterexample')
    expect(counterexample).toBeDefined()
    expect(hex((counterexample as { wire: Uint8Array }).wire)).toBe('a21818002000')

    const library = REJECTIONS.find((vector) => vector.name === 'value/cbor2-key-order')
    expect(library).toBeDefined()
    expect(hex((library as { wire: Uint8Array }).wire)).toBe('a22000181800')
    expect(() => decodeValue((library as { wire: Uint8Array }).wire)).toThrow(
      NonCanonicalEncoding,
    )
  })

  it('reach the ordering trap inside a message, not only at value level', () => {
    // A value-level refusal proves the profile check works. A message-level one proves the phase
    // order lets it get that far: the version is readable, first and supported, so Phase 2 is what
    // objects. Those are different claims, and the second is the one a peer could actually send.
    const inMessage = REJECTIONS.filter((vector) =>
      vector.name.endsWith('/env.sorted-by-decoded-key'),
    )
    expect(inMessage.length).toBeGreaterThanOrEqual(2)
    for (const vector of inMessage) {
      expect(vector.expect).toBe('decode-error')
      expect(() => decode(vector.wire), vector.name).toThrow(DecodeError)
    }
  })
})
