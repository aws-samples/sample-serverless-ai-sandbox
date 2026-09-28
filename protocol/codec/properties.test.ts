// kiro-classification: public
//
// Properties 1 through 4 for the TypeScript Protocol_Codec, in fast-check over the shared generators.
//
// The design states these four in both languages, so the numbers here overlap with the Python suite's
// by design and uniqueness is asserted per language — `property-tags.test.ts` beside this file for the
// codec's half, `sdk/typescript/test/harness/property-tags.test.ts` for the SDK package's.
//
// Every generator is the shared one. `message()` and `outputBytes()` come from
// `protocol/generators/`, which reads the same `catalogue.json` and `byte_domains.json` mirrors the
// Python half reads, and `nonCanonicalVariant()` and `malformed()` are the TypeScript halves of
// `wire.py` and `faults.py`. That is what makes two implementations of one property mean something:
// they quantify over the same domain, so a case that catches one language would have been drawn in the
// other.
//
// All four run `CODEC_RUNS` iterations, which the design's Testing Strategy sets at 1,000 for the codec
// properties against the 100 the rest of the suite runs. The count is imported rather than written down,
// so the two halves of the TypeScript suite cannot disagree about it.
//
// Equality is `valuesEqual`, not `toEqual`. JavaScript compares `Uint8Array` and `Map` by identity, so
// `expect(decode(encode(m))).toEqual(m)` would be asserting something other than what Property 1 says.
// See `equal.ts`.

import fc from 'fast-check'
import { describe, expect, it } from 'vitest'

import { CODEC_RUNS } from '../../sdk/typescript/test/harness/config.js'
import { outputBytes } from '../generators/byteDomains.js'
import { malformed } from '../generators/faults.js'
import { type Envelope, message } from '../generators/messages.js'
import { nonCanonicalVariant } from '../generators/wire.js'
import {
  DecodeError,
  ENVELOPE_KEY_BODY,
  ENVELOPE_KEY_ID,
  ENVELOPE_KEY_TYPE,
  ENVELOPE_KEY_VERSION,
  NonCanonicalEncoding,
  VERSION_IDENTITY,
  type Value,
  VersionError,
  decode,
  decodeValue,
  encode,
  loadCatalogue,
  valueIdentity,
} from './index.js'

const CATALOGUE = loadCatalogue()

function hex(data: Uint8Array): string {
  return [...data].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

/** An `exec.chunk` carrying `data` as stdout: the message type Property 3 travels through. */
function chunkCarrying(data: Uint8Array): Envelope {
  return new Map<number, Value>([
    [ENVELOPE_KEY_VERSION, CATALOGUE.protocolVersion],
    [ENVELOPE_KEY_TYPE, 'exec.chunk'],
    [ENVELOPE_KEY_ID, new Uint8Array()],
    [
      ENVELOPE_KEY_BODY,
      new Map<Value, Value>([
        [1, 0],
        [2, data],
      ]),
    ],
  ])
}

describe('the Protocol_Codec', () => {
  // Feature: aws-serverless-agent-sandbox, Property 1: For any valid Sandbox_Protocol message,
  // serialising it and then deserialising the result produces a message equal to the original.
  it('round-trips any valid message', () => {
    fc.assert(
      fc.property(message(), (drawn) => {
        expect(valueIdentity(decode(encode(drawn)))).toBe(valueIdentity(drawn))
      }),
      { numRuns: CODEC_RUNS },
    )
  })

  // Feature: aws-serverless-agent-sandbox, Property 2: For all wire representations produced by the
  // codec, deserialising a representation and then serialising the result produces bytes identical to
  // the input; and for all parseable representations that violate the deterministic encoding profile,
  // the codec raises a decode error rather than accepting them.
  it('round-trips any wire representation and refuses every non-deterministic one', () => {
    fc.assert(
      fc.property(message().map((drawn) => encode(drawn)), (wire) => {
        expect(hex(encode(decode(wire)))).toBe(hex(wire))
      }),
      { numRuns: CODEC_RUNS },
    )

    // The second half. Each variant is an *equivalent* rewrite — a permissive reader decodes it to the
    // same value — so accepting one would break R8.5 on the way back out rather than on the way in,
    // which is why refusing it is the property and not a matter of taste.
    const reached = new Set<string>()
    fc.assert(
      fc.property(
        message().chain((drawn) => nonCanonicalVariant(encode(drawn))),
        (variant) => {
          reached.add(variant.violation)
          expect(() => decodeValue(variant.wire)).toThrow(NonCanonicalEncoding)
          // A decode error, never a version error: the rewrite leaves the version's value alone, so
          // Phase 1 has nothing to object to and the refusal is Phase 0's or Phase 2's.
          expect(
            () => decode(variant.wire),
            `${variant.violation} at byte ${variant.at} was accepted`,
          ).toThrow(DecodeError)
        },
      ),
      { numRuns: CODEC_RUNS },
    )
    // A rule never rewritten is a rule this half of the property never tested.
    expect([...reached].sort()).toEqual([
      'indefinite-container',
      'indefinite-string',
      'non-shortest-head',
      'unsorted-map-keys',
    ])
  })

  // Feature: aws-serverless-agent-sandbox, Property 3: For any byte sequence, including sequences that
  // are not valid UTF-8, carrying that sequence as process output through one serialise and deserialise
  // cycle yields a byte sequence identical to the input.
  it('carries process output bytes through a round trip unchanged', () => {
    fc.assert(
      fc.property(outputBytes(), (data) => {
        const body = decode(encode(chunkCarrying(data))).get(ENVELOPE_KEY_BODY)
        expect(body).toBeInstanceOf(Map)
        const carried = (body as ReadonlyMap<Value, Value>).get(2)
        expect(carried).toBeInstanceOf(Uint8Array)
        expect(hex(carried as Uint8Array)).toBe(hex(data))
      }),
      { numRuns: CODEC_RUNS },
    )
  })

  // Feature: aws-serverless-agent-sandbox, Property 4: For all malformed wire representations, the codec
  // raises the error determined by the phase order and no other: an unreadable or misplaced version
  // field raises a decode error naming field `1`; a readable but unsupported version raises a version
  // error carrying the received version and both bounds of the supported range; a supported version
  // with a schema violation raises a decode error naming the violated field; and a representation
  // carrying both an unsupported version and a schema violation raises a version error.
  it('selects the error the decode phase order determines', () => {
    const reached = new Set<string>()
    fc.assert(
      fc.property(malformed(), (fault) => {
        reached.add(fault.faultClass)
        const wire = fault.render(encode)
        let thrown: unknown
        try {
          decode(wire)
        } catch (error) {
          thrown = error
        }
        const where = `${fault.kind} on ${String(fault.message.get(ENVELOPE_KEY_TYPE))}`

        if (fault.expectation === 'version-error') {
          expect(thrown, where).toBeInstanceOf(VersionError)
          const error = thrown as VersionError
          expect(error.received, where).toBe(fault.version)
          expect(error.supportedMin, where).toBe(BigInt(CATALOGUE.supportedMin))
          expect(error.supportedMax, where).toBe(BigInt(CATALOGUE.supportedMax))
          return
        }

        expect(thrown, where).toBeInstanceOf(DecodeError)
        const error = thrown as DecodeError
        if (fault.faultClass === 'version-unreadable') {
          expect(error.field, where).toBe(VERSION_IDENTITY)
        }
        expect(
          fault.identifies(error.field),
          `${where} was reported as '${error.field}', which is not in ` +
            `${[...fault.acceptableFieldIdentities].sort().join(', ')}`,
        ).toBe(true)
      }),
      { numRuns: CODEC_RUNS },
    )
    // The fourth class is the one that discriminates a correct phase order from an accidental one, so a
    // run that never drew it would leave R8.8 unasserted however green it looked.
    expect([...reached].sort()).toEqual([
      'schema-violation',
      'version-unreadable',
      'version-unsupported',
      'version-unsupported-and-schema-violation',
    ])
  })
})
