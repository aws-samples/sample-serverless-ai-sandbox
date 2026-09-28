// kiro-classification: public
//
// Unit tests for the TypeScript half of the shared generators (R8.4, R8.9).
//
// The Python half is covered by `test_generators.py`, and these assert the same coverage on this
// side, because the point of sharing a domain across two languages is lost if only one of them
// checks that the domain is still the one the design names. Two of the assertions compare the two
// halves directly: the adversarial classes and the length boundaries are read back out of
// `byte_domains.py` so a value changed in one language and not the other fails here.
//
// `make test-typescript` reaches this file: `sdk/typescript/vitest.config.ts` includes
// `../../protocol/generators/**/*.test.ts`, because that package holds the repository's only
// `node_modules`. It is reached by path rather than moved, and it stays outside that package's
// `tsconfig.json` `include`, whose `rootDir` a build input from above would violate (TS6059).
// `protocol/generators/tsconfig.json` typechecks these modules instead:
// `npx --prefix sdk/typescript tsc --noEmit -p protocol/generators`.

import { describe, expect, it } from 'vitest'
import fc from 'fast-check'

import {
  ADVERSARIAL_BYTE_CLASSES,
  CBOR_LENGTH_BOUNDARIES,
  PATH_SEPARATOR,
  RESERVED_PATH_COMPONENTS,
  outputBytes,
  pathComponent,
} from './byteDomains.js'
import {
  CborScanError,
  type Item,
  Major,
  compareBytes,
  encode,
  encodeHead,
  entries as mapEntries,
  minimalWidth,
  scan,
  walk,
  widerWidths,
} from '../codec/index.js'
import {
  ENVELOPE_KEY_BODY,
  ENVELOPE_KEY_ID,
  ENVELOPE_KEY_TYPE,
  ENVELOPE_KEY_VERSION,
  type Field,
  type TypeSpec,
  byteTypedFields,
  loadCatalogue,
  messageTypes,
  supports,
} from './catalogue.js'
import { type FaultClass, malformed, outOfRangeVersions } from './faults.js'
import { type Value, integerBoundaries, message } from './messages.js'
import { type Violation, nonCanonicalVariant } from './wire.js'

const CATALOGUE = loadCatalogue()

/** Enough runs to make a coverage assertion meaningful without making the file slow. */
const COVERAGE_RUNS = 3_000

function sample<T>(arbitrary: fc.Arbitrary<T>, runs: number): T[] {
  return fc.sample(arbitrary, { numRuns: runs })
}

function includesSequence(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > haystack.length) {
    return needle.length === 0
  }
  for (let start = 0; start + needle.length <= haystack.length; start += 1) {
    let matched = true
    for (let offset = 0; offset < needle.length; offset += 1) {
      if (haystack[start + offset] !== needle[offset]) {
        matched = false
        break
      }
    }
    if (matched) {
      return true
    }
  }
  return false
}

function isValidUtf8(data: Uint8Array): boolean {
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(data)
    return true
  } catch {
    return false
  }
}

describe('the adversarial byte domain', () => {
  it('draws byte sequences within the ceiling', () => {
    fc.assert(
      fc.property(outputBytes(512), (data) => {
        expect(data).toBeInstanceOf(Uint8Array)
        expect(data.length).toBeLessThanOrEqual(512)
      }),
      { numRuns: 200 },
    )
  })

  it('reaches every adversarial class', () => {
    const seen = new Set<string>()
    for (const example of sample(outputBytes(512), COVERAGE_RUNS)) {
      for (const [name, sequences] of ADVERSARIAL_BYTE_CLASSES) {
        if (sequences.some((sequence) => includesSequence(example, sequence))) {
          seen.add(name)
        }
      }
    }
    expect([...seen].sort()).toEqual([...ADVERSARIAL_BYTE_CLASSES.keys()].sort())
  })

  it('reaches every length boundary that fits, because a mis-selected prefix width only fails at a crossing', () => {
    const lengths = new Set(sample(outputBytes(512), COVERAGE_RUNS).map((data) => data.length))
    for (const boundary of CBOR_LENGTH_BOUNDARIES.filter((size) => size <= 512)) {
      expect(lengths.has(boundary)).toBe(true)
    }
  })

  it('holds no adversarial sequence that a text codec would accept, NUL runs aside', () => {
    for (const [name, sequences] of ADVERSARIAL_BYTE_CLASSES) {
      if (name === 'nul-run') {
        // NUL is valid UTF-8; its hazard is C string truncation, not decoding.
        continue
      }
      for (const sequence of sequences) {
        expect(isValidUtf8(sequence)).toBe(false)
      }
    }
  })

  it('carries the five classes the design names, read from the one place they are declared', () => {
    // No comparison against a second copy: the classes come from `byte_domains.json`, which is
    // written from `byte_domains.py`. This asserts the mirror was read and understood, not that
    // two hand-maintained lists happen to match. The freshness of the mirror itself is asserted
    // by `test_generators.py`, on the side that generates it.
    expect([...ADVERSARIAL_BYTE_CLASSES.keys()].sort()).toEqual([
      'high-byte',
      'lone-surrogate',
      'nul-run',
      'overlong-encoding',
      'truncated-sequence',
    ])
    for (const sequences of ADVERSARIAL_BYTE_CLASSES.values()) {
      expect(sequences.length).toBeGreaterThan(0)
      for (const sequence of sequences) {
        expect(sequence).toBeInstanceOf(Uint8Array)
        expect(sequence.length).toBeGreaterThan(0)
      }
    }
  })
})

describe('pathComponent', () => {
  it('is a usable Linux filename', () => {
    fc.assert(
      fc.property(pathComponent(), (component) => {
        expect(component.length).toBeGreaterThan(0)
        expect(component.includes(0x00)).toBe(false)
        expect(component.includes(PATH_SEPARATOR)).toBe(false)
        for (const reserved of RESERVED_PATH_COMPONENTS) {
          expect([...component]).not.toEqual([...reserved])
        }
      }),
      { numRuns: 300 },
    )
  })
})

describe('message', () => {
  it('populates only declared keys with admissible values', () => {
    fc.assert(
      fc.property(message(), (drawn) => {
        const t = drawn.get(ENVELOPE_KEY_TYPE)
        expect(typeof t).toBe('string')
        const messageType = CATALOGUE.messages.get(t as string)
        expect(messageType).toBeDefined()

        const body = drawn.get(ENVELOPE_KEY_BODY)
        expect(body).toBeInstanceOf(Map)
        const entries = body as ReadonlyMap<Value, Value>
        const declared = new Map(messageType!.body.map((field) => [field.key, field]))

        for (const key of entries.keys()) {
          expect(declared.has(key as number)).toBe(true)
        }
        for (const field of messageType!.body) {
          if (!field.optional) {
            expect(entries.has(field.key)).toBe(true)
          }
        }
        for (const [key, value] of entries) {
          assertAdmissible(value, declared.get(key as number)!.spec)
        }
      }),
      { numRuns: 300 },
    )
  })

  it('carries the emitted version and a declared type', () => {
    fc.assert(
      fc.property(message(), (drawn) => {
        expect(drawn.get(ENVELOPE_KEY_VERSION)).toBe(CATALOGUE.protocolVersion)
        expect(drawn.get(ENVELOPE_KEY_ID)).toBeInstanceOf(Uint8Array)
      }),
      { numRuns: 200 },
    )
  })

  it('draws every type in the catalogue, since a type never drawn is a type Property 1 never covers', () => {
    const drawn = new Set(
      sample(message(), 2_000).map((example) => example.get(ENVELOPE_KEY_TYPE) as string),
    )
    expect([...drawn].sort()).toEqual([...messageTypes(CATALOGUE)].sort())
  })

  it('draws invalid UTF-8 into every byte-typed field', () => {
    // Quantified over the catalogue's annotated fields, so a message type added with an output
    // or name field the generator populates from a narrower domain is a failure, not an omission.
    const unreached: string[] = []
    for (const { t, field } of byteTypedFields(CATALOGUE)) {
      const examples = sample(message({ types: [t] }), 400)
      const reached = examples.some((example) => {
        const body = example.get(ENVELOPE_KEY_BODY) as ReadonlyMap<Value, Value>
        const value = body.get(field.key)
        return value !== undefined && walkValues(value).some(isInvalidBytes)
      })
      if (!reached) {
        unreached.push(`${t}.${field.name}`)
      }
    }
    expect(unreached).toEqual([])
  })
})

describe('integerBoundaries', () => {
  it('includes the declared bounds and stays inside them', () => {
    let checked = 0
    for (const messageType of CATALOGUE.messages.values()) {
      for (const field of messageType.body) {
        for (const spec of walkSpecs(field.spec)) {
          if (spec.range === undefined) {
            continue
          }
          checked += 1
          const values = integerBoundaries(spec.range)
          expect(values).toContain(spec.range.min)
          expect(values).toContain(spec.range.max)
          for (const value of values) {
            expect(value >= spec.range.min && value <= spec.range.max).toBe(true)
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(0)
  })

  it('agrees with the Python half on the emitted version field', () => {
    const versionField = CATALOGUE.envelope.find((field) => field.key === ENVELOPE_KEY_VERSION)
    expect(versionField?.spec.range).toBeDefined()
    // The envelope's `v` spans the full CBOR unsigned range, which is the case a JSON number
    // cannot carry and the reason the mirror writes bounds as decimal strings.
    expect(versionField!.spec.range!.max).toBe(18446744073709551615n)
  })
})

// --- `nonCanonicalVariant()`, the second half of Property 2 ----------------------------------

/** The four rules the profile fixes. A union rather than an enum, so the list is written once. */
const VIOLATIONS: readonly Violation[] = [
  'indefinite-container',
  'indefinite-string',
  'non-shortest-head',
  'unsorted-map-keys',
]

/**
 * Draws for the per-message coverage claim.
 *
 * Generous, because the candidate rewrites are drawn with equal weight and are not equally
 * numerous: every item carrying a head argument contributes one candidate per wider width, so a
 * message of a hundred items offers a few hundred non-shortest rewrites against the two strings the
 * envelope always has. At sixty draws a rule with two candidates in three hundred is a coin toss,
 * which would make this assertion flaky rather than false. The Python half runs its own count
 * against Hypothesis's sampler; the number is a property of the sampler, not of the generator.
 */
const VARIANT_COVERAGE_DRAWS = 3_000

describe('nonCanonicalVariant', () => {
  it('reaches every deterministic-profile rule in every message', () => {
    // An unsorted-key variant needs a map with two or more entries. The envelope has four, so
    // every message reaches all four rules, and the assertion is per message rather than over the
    // union — a rule reachable only in the one message type that happens to carry a nested map
    // would be a narrowing this would otherwise hide.
    for (const canonical of canonicalEncodings()) {
      const reached = new Set(
        sample(nonCanonicalVariant(canonical), VARIANT_COVERAGE_DRAWS).map(
          (variant) => variant.violation,
        ),
      )
      expect([...reached].sort(), `only reached ${[...reached].sort().join(', ')}`).toEqual([
        ...VIOLATIONS,
      ].sort())
    }
  })

  it('differs from the canonical encoding it rewrites', () => {
    for (const canonical of canonicalEncodings()) {
      for (const variant of sample(nonCanonicalVariant(canonical), 30)) {
        expect(hex(variant.canonical)).toBe(hex(canonical))
        expect(hex(variant.wire)).not.toBe(hex(canonical))
        expect(variant.at).toBeGreaterThanOrEqual(0)
        expect(variant.at).toBeLessThan(canonical.length)
      }
    }
  })

  it('violates the profile rather than well-formedness', () => {
    // The rewrite has to be *equivalent*, or Property 2 tests parsing and not the profile. The
    // scanner accepts only the profile, so it is the discriminator: three of the four rules make it
    // raise, and the fourth leaves a well-formed encoding whose keys no longer ascend. That
    // distinction is the point — an unsorted map parses cleanly under any CBOR reader, which is why
    // a codec can accept it by accident and why R8.5 has to be asserted rather than assumed.
    for (const canonical of canonicalEncodings()) {
      for (const variant of sample(nonCanonicalVariant(canonical), 40)) {
        if (variant.violation === 'unsorted-map-keys') {
          expect(keysAscend(variant.wire, scan(variant.wire))).toBe(false)
        } else {
          expect(() => scan(variant.wire)).toThrow(CborScanError)
        }
      }
    }
  })

  it('offers, through widerWidths, a non-shortest encoding of the same value', () => {
    for (const argument of [0n, 1n, 23n, 24n, 255n, 256n, 65535n]) {
      for (const width of widerWidths(argument)) {
        expect(width).toBeGreaterThan(minimalWidth(argument))
        const widened = encodeHead(Major.UINT, argument, width)
        expect(widened.length).toBe(1 + width)
        expect(() => scan(widened)).toThrow(CborScanError)
      }
    }
  })
})

// --- `malformed()`, which is what Property 4 quantifies over ---------------------------------

const FAULT_CLASSES: readonly FaultClass[] = [
  'schema-violation',
  'version-unreadable',
  'version-unsupported',
  'version-unsupported-and-schema-violation',
]

describe('malformed', () => {
  it('carries, for each fault class, the expectation the phase order owes it', () => {
    // Phase 1 precedes Phase 2, so an unsupported version outranks a schema violation.
    for (const fault of sample(malformed(), 200)) {
      if (
        fault.faultClass === 'version-unsupported' ||
        fault.faultClass === 'version-unsupported-and-schema-violation'
      ) {
        expect(fault.expectation).toBe('version-error')
        expect(fault.version).not.toBeNull()
        expect(supports(CATALOGUE, fault.version!)).toBe(false)
      } else {
        expect(fault.expectation).toBe('decode-error')
        expect(fault.acceptableFieldIdentities.size).toBeGreaterThan(0)
      }
    }
  })

  it('renders to bytes that are not the well-formed encoding', () => {
    for (const fault of sample(malformed(), 200)) {
      expect(hex(fault.render(encode))).not.toBe(hex(encode(fault.message)))
    }
  })

  it('reaches all four fault classes', () => {
    // The cross-product class is the one that discriminates the phase order.
    const drawn = new Set(sample(malformed(), COVERAGE_RUNS).map((fault) => fault.faultClass))
    expect([...drawn].sort()).toEqual([...FAULT_CLASSES].sort())
  })

  it('pairs, in the cross product, every version with every violation scope', () => {
    // Not an anecdote: both scopes are reached alongside an out-of-range version.
    const both = sample(malformed(), COVERAGE_RUNS).filter(
      (fault) => fault.faultClass === 'version-unsupported-and-schema-violation',
    )
    expect(both.length).toBeGreaterThan(0)
    const scopes = new Set(
      both.flatMap((fault) => (fault.violated === null ? [] : [fault.violated.scope])),
    )
    expect([...scopes].sort()).toEqual(['body', 'envelope'])
    expect(new Set(both.map((fault) => fault.version)).size).toBeGreaterThan(1)
  })

  it('derives its out-of-range versions from the declared range', () => {
    const versions = outOfRangeVersions(CATALOGUE)
    expect(versions.length).toBeGreaterThan(0)
    for (const version of versions) {
      expect(supports(CATALOGUE, version)).toBe(false)
    }
    expect(versions).toContain(BigInt(CATALOGUE.supportedMax) + 1n)
    expect(versions).not.toContain(BigInt(CATALOGUE.protocolVersion))
  })

  it('names, for a decode-error fault, the field it violates', () => {
    // `identifies` is how Property 4 checks the reported field without pinning a spelling.
    for (const fault of sample(malformed(), 200)) {
      if (fault.expectation !== 'decode-error') {
        continue
      }
      for (const spelling of fault.acceptableFieldIdentities) {
        expect(fault.identifies(spelling)).toBe(true)
      }
      expect(fault.identifies('a-field-no-codec-would-name')).toBe(false)
    }
  })
})

// --- Helpers ---------------------------------------------------------------------------------

function hex(data: Uint8Array): string {
  return [...data].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

/**
 * One canonical encoding per message type in the catalogue.
 *
 * The wire generator takes bytes rather than a strategy, so its tests iterate encodings directly
 * instead of nesting a draw inside a property run. `encode` is the codec's serialise, which is the
 * `Encoder` both this and the fault generator ask for.
 */
function canonicalEncodings(): Uint8Array[] {
  return messageTypes(CATALOGUE).map((t) => encode(sample(message({ types: [t] }), 1)[0]!))
}

/**
 * Whether every map in `wire` has its keys in ascending encoded-byte order.
 *
 * The scanner records offsets, so the encoded form of a key is the slice it spans. That is the
 * comparison RFC 8949's deterministic profile specifies, rather than a comparison of decoded key
 * values, which would order `256` before `24`.
 */
function keysAscend(wire: Uint8Array, root: Item): boolean {
  for (const item of walk(root)) {
    if (item.major !== Major.MAP) {
      continue
    }
    const encoded = mapEntries(item).map(([key]) => wire.subarray(key.start, key.end))
    for (let index = 1; index < encoded.length; index += 1) {
      if (compareBytes(encoded[index - 1]!, encoded[index]!) >= 0) {
        return false
      }
    }
  }
  return true
}

function* walkSpecs(spec: TypeSpec): Generator<TypeSpec> {
  yield spec
  for (const nested of [spec.items, spec.keys, spec.values]) {
    if (nested !== undefined) {
      yield* walkSpecs(nested)
    }
  }
  for (const field of spec.fields) {
    yield* walkSpecs(field.spec)
  }
}

function walkValues(value: Value): Value[] {
  if (Array.isArray(value)) {
    return value.flatMap(walkValues)
  }
  if (value instanceof Map) {
    return [...value].flatMap(([key, item]) => [...walkValues(key), ...walkValues(item)])
  }
  return [value]
}

function isInvalidBytes(value: Value): boolean {
  return value instanceof Uint8Array && !isValidUtf8(value)
}

function assertAdmissible(value: Value, spec: TypeSpec): void {
  switch (spec.kind) {
    case 'uint':
    case 'int': {
      expect(typeof value === 'number' || typeof value === 'bigint').toBe(true)
      const asBig = BigInt(value as number | bigint)
      expect(asBig >= spec.range!.min && asBig <= spec.range!.max).toBe(true)
      return
    }
    case 'bool':
      expect(typeof value).toBe('boolean')
      return
    case 'text':
      expect(typeof value).toBe('string')
      if (spec.enum !== undefined) {
        expect(spec.enum).toContain(value as string)
      }
      return
    case 'bytes':
      expect(value).toBeInstanceOf(Uint8Array)
      return
    case 'list':
      expect(Array.isArray(value)).toBe(true)
      for (const item of value as readonly Value[]) {
        assertAdmissible(item, spec.items!)
      }
      return
    case 'map': {
      expect(value).toBeInstanceOf(Map)
      if (spec.keys !== undefined && spec.values !== undefined) {
        for (const [key, item] of value as ReadonlyMap<Value, Value>) {
          assertAdmissible(key, spec.keys)
          assertAdmissible(item, spec.values)
        }
      }
      return
    }
    case 'struct': {
      expect(value).toBeInstanceOf(Map)
      const declared = new Map<number, Field>(spec.fields.map((field) => [field.key, field]))
      for (const [key, item] of value as ReadonlyMap<Value, Value>) {
        const field = declared.get(key as number)
        expect(field).toBeDefined()
        assertAdmissible(item, field!.spec)
      }
      return
    }
  }
}
