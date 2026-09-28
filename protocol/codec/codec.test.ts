// kiro-classification: public
//
// Unit tests for the TypeScript Protocol_Codec (R8.2, R8.3, R8.9).
//
// None of these is a property test and none carries a property tag: nothing here drives fast-check.
// The four properties are `properties.test.ts`. What is asserted here is what an example-based test is
// better at than a sampled one — the exact bytes the deterministic profile requires, taken from RFC
// 8949's own test vectors, and one instance of each way a representation can be refused — and it is
// deliberately the same list `protocol/codec/test_codec.py` asserts on the Python half, so the two
// implementations are pinned to the same vectors rather than to each other.
//
// Three of the groups below deserve a note.
//
// *Quantified over the catalogue.* The round-trip and encoding-shape tests build one message per
// declared message type from the schema rather than listing messages, so a type added to
// `messages.yaml` is covered with no edit here. The builder is deliberately dull — the low end of every
// declared range, the first value of every closed enum — because the interesting distributions are the
// generators' job.
//
// *Agreement with the shared fault generator.* `protocol/generators/faults.ts` fixes the spellings a
// decode error may use for the field it names and leaves the choice among them to the codec. Property 4
// checks the codec's choice by sampling; the tests here enumerate every single-field schema violation
// the generator can build against every message type, and every out-of-range version against every one
// of those violations, and check the same thing exhaustively. That is also what stops the two languages
// from disagreeing about field identity, because `faults.py` and `faults.ts` fix the same set.
//
// *Cases JavaScript has and Python does not.* A `TextDecoder` that strips a byte-order mark, a
// `TextEncoder` that substitutes U+FFFD for an unpaired surrogate rather than failing, and a `Map` that
// keys two byte-equal `Uint8Array` objects separately are three ways this half could lose bytes that
// the Python half cannot reach. Each has a test.

import { describe, expect, it } from 'vitest'
import { Encoder, decode as cborXDecode } from 'cbor-x'

import {
  Fault,
  type FaultKind,
  outOfRangeVersions,
  violationTargets,
} from '../generators/faults.js'
import {
  BREAK,
  INDEFINITE_INFO,
  Major,
  ROOT_IDENTITY,
  VERSION_IDENTITY,
  DecodeError,
  ENVELOPE_KEY_BODY,
  ENVELOPE_KEY_ID,
  ENVELOPE_KEY_TYPE,
  ENVELOPE_KEY_VERSION,
  type Field,
  type Message,
  NonCanonicalEncoding,
  SchemaViolation,
  type TypeSpec,
  UnencodableValue,
  type Value,
  VersionError,
  decode,
  decodeValue,
  encode,
  encodeValue,
  entries,
  loadCatalogue,
  narrowInteger,
  readVersion,
  requireSupported,
  scan,
  valueIdentity,
  validate,
} from './index.js'

const CATALOGUE = loadCatalogue()

/**
 * Bytes that are not valid UTF-8, carried through every byte-typed field the builder populates, so the
 * round-trip tests exercise R8.9 rather than only ASCII.
 */
const INVALID_UTF8 = new Uint8Array([0xff, 0xfe, 0x00, 0x80])

const CORRELATION_ID = new Uint8Array([0x00, 0xff])

function hex(data: Uint8Array): string {
  return [...data].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function fromHex(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

// --- Building one message per declared type, from the schema ---------------------------------

function exampleValue(spec: TypeSpec): Value {
  switch (spec.kind) {
    case 'uint':
    case 'int':
      return narrowInteger(spec.range!.min)
    case 'bool':
      return true
    case 'text':
      return spec.enum !== undefined ? spec.enum[0]! : 'example'
    case 'bytes':
      return INVALID_UTF8
    case 'list':
      return [exampleValue(spec.items!)]
    case 'map':
      return spec.keys === undefined || spec.values === undefined
        ? new Map<Value, Value>()
        : new Map<Value, Value>([[exampleValue(spec.keys), exampleValue(spec.values)]])
    case 'struct':
      return exampleBody(spec.fields, true)
  }
}

function exampleBody(fields: readonly Field[], includeOptional: boolean): ReadonlyMap<Value, Value> {
  return new Map<Value, Value>(
    fields
      .filter((field) => includeOptional || !field.optional)
      .map((field) => [field.key, exampleValue(field.spec)] as const),
  )
}

function exampleMessage(t: string, includeOptional = true): Message {
  return new Map<number, Value>([
    [ENVELOPE_KEY_VERSION, CATALOGUE.protocolVersion],
    [ENVELOPE_KEY_TYPE, t],
    [ENVELOPE_KEY_ID, CORRELATION_ID],
    [ENVELOPE_KEY_BODY, exampleBody(CATALOGUE.messages.get(t)!.body, includeOptional)],
  ])
}

/** One message per declared type, and a second omitting the optional fields. */
function exampleMessages(): Message[] {
  const built: Message[] = []
  for (const t of CATALOGUE.messages.keys()) {
    built.push(exampleMessage(t))
    if (CATALOGUE.messages.get(t)!.body.some((field) => field.optional)) {
      built.push(exampleMessage(t, false))
    }
  }
  return built
}

const EXAMPLES = exampleMessages()

function bodyOf(message: Message): ReadonlyMap<Value, Value> {
  return message.get(ENVELOPE_KEY_BODY) as ReadonlyMap<Value, Value>
}

function typeOf(message: Message): string {
  return message.get(ENVELOPE_KEY_TYPE) as string
}

describe('the catalogue this file quantifies over', () => {
  it('declares message types, so no test below passes vacuously', () => {
    expect(CATALOGUE.messages.size).toBeGreaterThan(0)
    expect(EXAMPLES.length).toBeGreaterThan(CATALOGUE.messages.size)
  })
})

// --- Round-trips (R8.2, R8.3) ----------------------------------------------------------------

describe('round-trips', () => {
  it('carries every declared message type there and back', () => {
    for (const message of EXAMPLES) {
      expect(valueIdentity(decode(encode(message)))).toBe(valueIdentity(message))
    }
  })

  it('re-encodes every wire representation to the bytes it arrived as', () => {
    // The R8.5 direction, on the codec's own output. Property 2 states this over sampled messages and
    // adds the half about non-canonical input; this is what would fail first if the encoder stopped
    // emitting the profile.
    for (const message of EXAMPLES) {
      const wire = encode(message)
      expect(hex(encode(decode(wire)))).toBe(hex(wire))
    }
  })

  it('preserves process output bytes unchanged (R8.9)', () => {
    const payloads: Uint8Array[] = [
      new Uint8Array(),
      new Uint8Array([0xff]),
      new Uint8Array([0xfe, 0xff]),
      fromHex('eda080'), // A lone surrogate, encoded as bytes.
      fromHex('c080'), // An overlong NUL.
      fromHex('e282'), // A truncated three-byte sequence.
      fromHex('efbbbf'), // A byte-order mark, which a text decoder would swallow.
      new Uint8Array(8),
      new Uint8Array(256).map((_, index) => index),
      new Uint8Array(23).fill(0xff),
      new Uint8Array(24).fill(0xff),
      new Uint8Array(255).fill(0xff),
      new Uint8Array(256).fill(0xff),
      new Uint8Array(65_536).fill(0xff),
    ]
    for (const payload of payloads) {
      const message = new Map<number, Value>([
        [ENVELOPE_KEY_VERSION, CATALOGUE.protocolVersion],
        [ENVELOPE_KEY_TYPE, 'exec.chunk'],
        [ENVELOPE_KEY_ID, CORRELATION_ID],
        [
          ENVELOPE_KEY_BODY,
          new Map<Value, Value>([
            [1, 1],
            [2, payload],
          ]),
        ],
      ])
      expect(hex(bodyOf(decode(encode(message))).get(2) as Uint8Array)).toBe(hex(payload))
    }
  })

  it('keeps a byte-order mark inside a text string, which the default decoder would strip', () => {
    // JavaScript-only hazard: `new TextDecoder('utf-8')` removes a leading U+FEFF unless `ignoreBOM`
    // is set, so `63 ef bb bf` would decode to the empty string and re-encode to `60`. Three bytes lost
    // and R8.5 broken, with nothing in the value to show it happened.
    const wire = fromHex('63efbbbf')
    expect(decodeValue(wire)).toBe('\ufeff')
    expect(hex(encodeValue(decodeValue(wire)))).toBe(hex(wire))
  })
})

// --- The encoding is the deterministic profile ------------------------------------------------

describe('the emitted encoding', () => {
  it('is the profile the scanner accepts', () => {
    for (const message of EXAMPLES) {
      const root = scan(encode(message))
      expect(root.major).toBe(Major.MAP)
      expect(root.argument).toBe(4n)
    }
  })

  it('puts the protocol version first, which is the mechanism R8.8 rests on', () => {
    for (const message of EXAMPLES) {
      const [key, value] = entries(scan(encode(message)))[0]!
      expect(key.major).toBe(Major.UINT)
      expect(key.argument).toBe(BigInt(ENVELOPE_KEY_VERSION))
      expect(value.argument).toBe(BigInt(CATALOGUE.protocolVersion))
    }
  })

  it.each([
    [0, '00'],
    [1, '01'],
    [23, '17'],
    [24, '1818'],
    [255, '18ff'],
    [256, '190100'],
    [1_000_000, '1a000f4240'],
    [(1n << 64n) - 1n, '1bffffffffffffffff'],
    [-1, '20'],
    [-24, '37'],
    [-25, '3818'],
    [-256, '38ff'],
    [false, 'f4'],
    [true, 'f5'],
    [new Uint8Array(), '40'],
    [new Uint8Array([1, 2, 3, 4]), '4401020304'],
    ['', '60'],
    ['a', '6161'],
    ['\u00fc', '62c3bc'],
    [[], '80'],
    [[1, [2, 3]], '8201820203'],
    [new Map(), 'a0'],
    [
      new Map([
        [1, 2],
        [3, 4],
      ]),
      'a201020304',
    ],
  ] as readonly (readonly [Value, string])[])(
    'matches the RFC 8949 vector for %s',
    (value, expected) => {
      expect(hex(encodeValue(value))).toBe(expected)
    },
  )

  it('sorts map entries by encoded key bytes, not by decoded value', () => {
    // -1 is the smallest number here and sorts last, because major type 1 puts its head byte at `20`,
    // above `01`, `1818` and `190100`.
    const keys = new Map<Value, Value>([
      [-1, 0],
      [256, 0],
      [24, 0],
      [1, 0],
    ])
    expect(hex(encodeValue(keys))).toBe('a40100181800190100002000')
  })

  it('sorts keys of different major types by their heads', () => {
    // `01` then `40` then `60`: an integer key, a byte-string key, a text key.
    const keys = new Map<Value, Value>([
      ['', 0],
      [new Uint8Array(), 0],
      [1, 0],
    ])
    expect(hex(encodeValue(keys))).toBe('a3010040006000')
  })
})

describe('the encoder', () => {
  it.each([
    ['a float', 1.5],
    ['null', null],
    ['undefined', undefined],
    ['a Set', new Set([1])],
    ['a plain object', { a: 1 }],
    ['a Date', new Date(0)],
    ['an integer above the head range', 1n << 64n],
    ['an integer below the head range', -(1n << 64n) - 1n],
    ['an unpaired high surrogate', '\ud800'],
    ['an unpaired low surrogate', 'a\udc00b'],
  ])('refuses %s, which is outside the protocol value space', (_name, value) => {
    expect(() => encodeValue(value as Value)).toThrow(UnencodableValue)
  })

  it('refuses a map holding two byte-equal keys, which no CBOR map can carry', () => {
    // A `Map` keys by object identity, so these are two entries. CBOR has no way to say that, and the
    // profile's ordering rule would have to emit them as equal rather than ascending — bytes this
    // codec's own decoder refuses. Python cannot reach the case: a `dict` collapses the pair.
    const collides = new Map<Value, Value>([
      [new Uint8Array([1]), 0],
      [new Uint8Array([1]), 1],
    ])
    expect(collides.size).toBe(2)
    expect(() => encodeValue(collides)).toThrow(UnencodableValue)
  })

  it('refuses a version outside the supported range, so only byte surgery can build one', () => {
    const message = new Map(exampleMessage('fs.ack'))
    message.set(ENVELOPE_KEY_VERSION, CATALOGUE.supportedMax + 1)
    expect(() => encode(message)).toThrow(SchemaViolation)
    try {
      encode(message)
    } catch (error) {
      expect((error as SchemaViolation).field).toBe('v')
    }
  })

  it('refuses a message the catalogue does not declare', () => {
    const message = new Map(exampleMessage('fs.ack'))
    message.set(ENVELOPE_KEY_TYPE, 'exec.undeclared')
    expect(() => encode(message)).toThrow(SchemaViolation)
  })
})

// --- Non-deterministic and ill-formed representations are refused (R8.5) ----------------------

function indefinite(major: Major, payload: Uint8Array): Uint8Array {
  const wrapped = new Uint8Array(payload.length + 2)
  wrapped[0] = (major << 5) | INDEFINITE_INFO
  wrapped.set(payload, 1)
  wrapped[wrapped.length - 1] = BREAK
  return wrapped
}

describe('the decoder', () => {
  it.each([
    ['indefinite byte string', indefinite(Major.BYTES, fromHex('43616263'))],
    ['indefinite text string', indefinite(Major.TEXT, fromHex('63616263'))],
    ['indefinite array', indefinite(Major.ARRAY, fromHex('010203'))],
    ['indefinite map', indefinite(Major.MAP, fromHex('0102'))],
    ['non-shortest one-byte head', fromHex('1817')],
    ['non-shortest two-byte head', fromHex('190018')],
    ['non-shortest eight-byte head', fromHex('1b0000000000000001')],
    ['non-shortest byte-string length', fromHex('5801ff')],
    // `a2 1818 00 01 00`: key 24 before key 1, which the profile orders the other way.
    ['map keys out of sorted order', fromHex('a21818000100')],
    ['duplicate map keys', fromHex('a201000100')],
    ['a tag', fromHex('c11a514b67b0')],
    ['a half-precision float', fromHex('f90000')],
    ['a double-precision float', fromHex('fb3ff199999999999a')],
    ['the null simple value', fromHex('f6')],
    ['an unassigned simple value', fromHex('f818')],
    ['a bare break', fromHex('ff')],
    ['a truncated head', fromHex('19')],
    ['a truncated byte-string payload', fromHex('43ab')],
    ['a truncated map', fromHex('a201')],
    ['trailing bytes', fromHex('000000')],
    ['no bytes at all', new Uint8Array()],
    ['invalid UTF-8 in a text string', fromHex('61ff')],
    ['an overlong NUL in a text string', fromHex('62c080')],
    ['a surrogate encoded in a text string', fromHex('63eda080')],
  ])('refuses %s', (_name, wire) => {
    expect(() => decodeValue(wire)).toThrow(NonCanonicalEncoding)
  })

  it('refuses representations that a permissive reader would find perfectly ordinary', () => {
    // That is the point of refusing them: re-encoding the value under the profile would produce
    // different bytes than arrived, which is exactly what R8.5 forbids. The check is the weaker,
    // self-contained one — the canonical encoding of the same value differs from the input — so it does
    // not depend on a second CBOR library.
    const equivalents: readonly (readonly [Uint8Array, Value])[] = [
      [indefinite(Major.BYTES, fromHex('43616263')), new Uint8Array([0x61, 0x62, 0x63])],
      [fromHex('1817'), 23],
      [fromHex('5801ff'), new Uint8Array([0xff])],
      [
        fromHex('a21818000100'),
        new Map<Value, Value>([
          [24, 0],
          [1, 0],
        ]),
      ],
    ]
    for (const [wire, value] of equivalents) {
      expect(hex(encodeValue(value))).not.toBe(hex(wire))
    }
  })

  it('reports the offset of the item at fault where there is one', () => {
    try {
      decodeValue(fromHex('a21818000100'))
      expect.unreachable('the representation is not canonical')
    } catch (error) {
      // The out-of-order key itself: `a2` then key 24 across bytes 1 and 2, its value at 3.
      expect((error as NonCanonicalEncoding).at).toBe(4)
    }
  })
})

// --- Schema validation names the offending field (R8.6's material) ----------------------------

function violation(value: Value | Message): SchemaViolation {
  try {
    validate(value)
  } catch (error) {
    if (error instanceof SchemaViolation) {
      return error
    }
    throw error
  }
  throw new Error('the value validated, so there is no violation to inspect')
}

function withBody(t: string, body: ReadonlyMap<Value, Value>): Message {
  const message = new Map(exampleMessage(t))
  message.set(ENVELOPE_KEY_BODY, body)
  return message
}

describe('schema validation', () => {
  it('names the root when the value is not a map', () => {
    expect(violation(7).field).toBe(ROOT_IDENTITY)
  })

  it('names a missing envelope key', () => {
    const message = new Map(exampleMessage('fs.ack'))
    message.delete(ENVELOPE_KEY_ID)
    expect(violation(message).field).toBe('id')
  })

  it('names an undeclared envelope key by its number', () => {
    const message = new Map(exampleMessage('fs.ack'))
    message.set(5, 0)
    expect(violation(message).field).toBe('5')
  })

  it('refuses a non-integer envelope key', () => {
    const envelope = new Map<Value, Value>(exampleMessage('fs.ack'))
    envelope.set('v', 1)
    expect(violation(envelope).field).toBe("'v'")
  })

  it.each([
    ['fs.ack', ENVELOPE_KEY_TYPE, 0, 't'],
    ['fs.ack', ENVELOPE_KEY_TYPE, 'exec.undeclared', 't'],
    ['fs.ack', ENVELOPE_KEY_BODY, 0, 'b'],
    ['fs.ack', ENVELOPE_KEY_ID, 'not-bytes', 'id'],
  ] as readonly (readonly [string, number, Value, string])[])(
    'names an inadmissible envelope value on %s key %s',
    (t, key, replacement, expected) => {
      const message = new Map(exampleMessage(t))
      message.set(key, replacement)
      expect(violation(message).field).toBe(expected)
    },
  )

  it.each([
    // An undeclared body key, named by its number under the body.
    ['fs.ack', new Map<Value, Value>([[1, 0]]), 'b.1'],
    [
      'fs.read',
      new Map<Value, Value>([
        [1, INVALID_UTF8],
        [2, 0],
      ]),
      'b.2',
    ],
    // A required field absent.
    ['fs.read', new Map<Value, Value>(), 'b.path'],
    // A field of the wrong type.
    ['fs.read', new Map<Value, Value>([[1, 'a text path']]), 'b.path'],
    [
      'exec.chunk',
      new Map<Value, Value>([
        [1, 0],
        [2, 'text output'],
      ]),
      'b.data',
    ],
    // A boolean where an integer belongs: simple value 21 is not integer 1.
    [
      'exec.chunk',
      new Map<Value, Value>([
        [1, true],
        [2, new Uint8Array()],
      ]),
      'b.stream',
    ],
    // An integer outside its declared range.
    [
      'exec.chunk',
      new Map<Value, Value>([
        [1, 2],
        [2, new Uint8Array()],
      ]),
      'b.stream',
    ],
    [
      'exec.result',
      new Map<Value, Value>([
        [1, 256],
        [2, new Uint8Array()],
        [3, new Uint8Array()],
      ]),
      'b.exitCode',
    ],
    // A text value outside its closed enum.
    [
      'proc.status',
      new Map<Value, Value>([
        [1, INVALID_UTF8],
        [2, 'sleeping'],
      ]),
      'b.state',
    ],
    // A text value with no UTF-8 encoding.
    ['port.url', new Map<Value, Value>([[1, '\ud800']]), 'b.url'],
    // Nested: inside a list of structs, and inside a map's keys and values.
    [
      'fs.listing',
      new Map<Value, Value>([
        [
          1,
          [
            new Map<Value, Value>([
              [1, INVALID_UTF8],
              [2, 'block-device'],
              [3, 0],
            ]),
          ],
        ],
      ]),
      'b.entries[0].kind',
    ],
    [
      'fs.listing',
      new Map<Value, Value>([
        [
          1,
          [
            new Map<Value, Value>([
              [1, INVALID_UTF8],
              [2, 'file'],
              [3, 0],
            ]),
            'not a struct',
          ],
        ],
      ]),
      'b.entries[1]',
    ],
    [
      'exec.request',
      new Map<Value, Value>([
        [1, [INVALID_UTF8]],
        [2, INVALID_UTF8],
        [3, new Map<Value, Value>([['text key', new Uint8Array()]])],
        [4, 0],
        [5, true],
      ]),
      'b.env[0].key',
    ],
    [
      'exec.request',
      new Map<Value, Value>([
        [1, [INVALID_UTF8]],
        [2, INVALID_UTF8],
        [3, new Map<Value, Value>([[new Uint8Array(), 0]])],
        [4, 0],
        [5, true],
      ]),
      'b.env[0].value',
    ],
    [
      'exec.request',
      new Map<Value, Value>([
        [1, [0]],
        [2, INVALID_UTF8],
        [3, new Map<Value, Value>()],
        [4, 0],
        [5, true],
      ]),
      'b.argv[0]',
    ],
  ] as readonly (readonly [string, ReadonlyMap<Value, Value>, string])[])(
    'names an inadmissible %s body field as %s',
    (t, body, expected) => {
      expect(violation(withBody(t, body)).field).toBe(expected)
    },
  )

  it('admits an omitted optional field', () => {
    // `proc.status.exitCode` is absent while the process is running.
    const message = exampleMessage('proc.status', false)
    expect(bodyOf(message).has(3)).toBe(false)
    expect(valueIdentity(decode(encode(message)))).toBe(valueIdentity(message))
  })
})

// --- Why the pinned CBOR library is a cross-check and not the codec ---------------------------

describe('the pinned cbor-x', () => {
  it('does not order map keys at all, which is the first reason it is not the codec', () => {
    // RFC 8949 §4.2.1 fixes one order for a map's entries. `cbor-x` preserves insertion order, so the
    // same two entries encode two ways depending on how the caller built the `Map` — a weaker failure
    // than the Python half found in `cbor2`, which at least orders keys, by RFC 7049 §3.9's superseded
    // shortest-encoding-first rule.
    const encoder = new Encoder({ mapsAsObjects: false, useRecords: false })
    const ascending = new Map<unknown, unknown>([
      [-1n, 0],
      [24, 0],
    ])
    const descending = new Map<unknown, unknown>([
      [24, 0],
      [-1n, 0],
    ])
    expect(hex(encoder.encode(ascending))).not.toBe(hex(encoder.encode(descending)))
    // And this codec emits one answer for both, keyed bytewise on the encoded form.
    const keys = new Map<Value, Value>([
      [-1, 0],
      [24, 0],
    ])
    expect(hex(encodeValue(keys))).toBe('a21818002000')
  })

  it('does not always write shortest-form heads, which is the second reason', () => {
    const encoder = new Encoder({ mapsAsObjects: false, useRecords: false })
    expect(hex(encoder.encode(-1n))).not.toBe('20')
    expect(hex(encodeValue(-1))).toBe('20')
  })

  it.each([
    ['a non-shortest head', fromHex('1817')],
    ['map keys out of order', fromHex('a21818000100')],
    ['a duplicate map key', fromHex('a201000100')],
    ['a double-precision float', fromHex('fb3ff199999999999a')],
    ['the null simple value', fromHex('f6')],
    ['invalid UTF-8 inside a text string', fromHex('61ff')],
  ])('accepts %s, which is the third reason and the one that matters for R8.5', (_name, wire) => {
    // A permissive reader. It is not permissive about everything — indefinite-length strings and
    // trailing bytes it refuses — but it is permissive about every rule the deterministic profile adds
    // on top of well-formedness, which is precisely the set R8.5 needs enforced.
    expect(() => cborXDecode(wire)).not.toThrow()
    expect(() => decodeValue(wire)).toThrow(NonCanonicalEncoding)
  })

  it('replaces invalid UTF-8 in a text string rather than refusing it, which loses the bytes', () => {
    // The destructive case, and the reason a permissive reader is not merely lenient here: the invalid
    // sequence comes back as U+FFFD, so what arrived is gone and no re-encoding could reproduce it. A
    // codec built on this would satisfy R8.3 and quietly fail R8.5, with nothing in the value to show it.
    expect(cborXDecode(fromHex('61ff'))).toBe('\ufffd')
    expect(() => decodeValue(fromHex('61ff'))).toThrow(NonCanonicalEncoding)
  })
})

// --- Agreement with the shared fault generator on field identity ------------------------------

describe('field identity', () => {
  it('is one the shared fault generator accepts, for every single-field violation', () => {
    // Enumerated rather than sampled: every violation target the generator can build, against every
    // declared message type, with the optional fields both present and absent. Property 4 checks the
    // same agreement by sampling, and adds the version faults and the phase ordering this says nothing
    // about.
    let checked = 0
    for (const message of EXAMPLES) {
      const messageType = CATALOGUE.messages.get(typeOf(message))!
      for (const violated of violationTargets(messageType, message)) {
        const fault = new Fault({ kind: 'schema-violation', message, violated })
        let error: unknown
        try {
          decode(fault.render(encode))
        } catch (thrown) {
          error = thrown
        }
        expect(error, `${messageType.t}: ${violated.violation} on ${violated.name}`).toBeInstanceOf(
          DecodeError,
        )
        const reported = (error as DecodeError).field
        expect(
          fault.identifies(reported),
          `${messageType.t}: ${violated.violation} on ${violated.name} was reported as ` +
            `'${reported}', which is not in ${[...fault.acceptableFieldIdentities].sort().join(', ')}`,
        ).toBe(true)
        checked += 1
      }
    }
    expect(checked).toBeGreaterThan(0)
  })
})

// --- Phase 0: the version is readable from the front, or it is not readable at all ------------

function decodeError(wire: Uint8Array): DecodeError {
  try {
    decode(wire)
  } catch (error) {
    if (error instanceof DecodeError) {
      return error
    }
    throw error
  }
  throw new Error('the representation decoded, so there is no decode error to inspect')
}

describe('Phase 0', () => {
  it('reads the version of every declared message type', () => {
    for (const message of EXAMPLES) {
      expect(readVersion(encode(message))).toBe(BigInt(CATALOGUE.protocolVersion))
    }
  })

  it('reads a version no encoder here would emit', () => {
    // Byte surgery over a canonical encoding, which is the only way such an input exists. Phase 0 is
    // structural extraction, not admissibility: it reports what the representation says and leaves the
    // judgement to Phase 1. A Phase 0 that refused an unsupported version would make R8.7's error
    // unreachable, because there would be no received version to report.
    for (const version of outOfRangeVersions(CATALOGUE)) {
      const fault = new Fault({
        kind: 'unsupported-version',
        message: exampleMessage('fs.ack'),
        version,
      })
      expect(readVersion(fault.render(encode))).toBe(version)
    }
  })

  it.each([
    ['no bytes at all', 'empty-wire', undefined],
    ['the map head alone', 'truncated-wire', 1],
    ['the map head and the version key', 'truncated-wire', 2],
    // Three bytes is `a4 01 01`: a readable version on an unfinished representation, which is why
    // Phase 0 establishes that the whole item is there before trusting what it read.
    ['a readable version on a truncated envelope', 'truncated-wire', 3],
    ['an indefinite-length envelope', 'indefinite-envelope', undefined],
    ['the version key not first', 'version-key-misplaced', undefined],
    ['a version that is not an integer', 'version-not-an-integer', undefined],
  ] as readonly (readonly [string, FaultKind, number | undefined])[])(
    'fails on %s with a decode error naming the version key',
    (_name, kind, keepBytes) => {
      // R8.6 for the case where the version itself is unreadable. Deliberately not a version error: no
      // version was received, so there is none to report.
      const fault =
        keepBytes === undefined
          ? new Fault({ kind, message: exampleMessage('fs.ack') })
          : new Fault({ kind, message: exampleMessage('fs.ack'), keepBytes })
      expect(fault.faultClass).toBe('version-unreadable')
      const error = decodeError(fault.render(encode))
      expect(error.field).toBe(VERSION_IDENTITY)
      expect(fault.identifies(error.field)).toBe(true)
    },
  )

  it.each([
    ['a value that is not a map', encodeValue(7)],
    ['an empty map', encodeValue(new Map())],
    // Key 2 sorts after key 1, so a map that starts at 2 has no version entry to read.
    ['a map whose first key is not the version', encodeValue(new Map<Value, Value>([[2, 0]]))],
    // A byte-string key sorts after every integer key, so it is first only if it is alone.
    [
      'a map whose first key is not an integer',
      encodeValue(new Map<Value, Value>([[new Uint8Array(), 0]])),
    ],
    [
      'a map whose version is a byte string',
      encodeValue(new Map<Value, Value>([[1, new Uint8Array([1])]])),
    ],
    ['a map whose version is negative', encodeValue(new Map<Value, Value>([[1, -1]]))],
    ['a map whose version is a boolean', encodeValue(new Map<Value, Value>([[1, true]]))],
    [
      'trailing bytes after the envelope',
      new Uint8Array([...encodeValue(new Map<Value, Value>([[1, 1]])), 0]),
    ],
  ])('refuses %s, which carries no version to read', (_name, wire) => {
    try {
      readVersion(wire)
      expect.unreachable('the version is not readable')
    } catch (error) {
      expect(error).toBeInstanceOf(DecodeError)
      expect((error as DecodeError).field).toBe(VERSION_IDENTITY)
    }
  })
})

// --- Phase 1: admissibility, and the version error it raises (R8.7) ---------------------------

describe('Phase 1', () => {
  it('admits every version in the declared range', () => {
    requireSupported(BigInt(CATALOGUE.protocolVersion))
    for (let version = CATALOGUE.supportedMin; version <= CATALOGUE.supportedMax; version += 1) {
      requireSupported(BigInt(version))
    }
  })

  it('reports the received version and both bounds', () => {
    for (const version of outOfRangeVersions(CATALOGUE)) {
      try {
        requireSupported(version)
        expect.unreachable(`${version} is outside the supported range`)
      } catch (thrown) {
        const error = thrown as VersionError
        expect(error).toBeInstanceOf(VersionError)
        expect(error.received).toBe(version)
        expect(error.supportedMin).toBe(BigInt(CATALOGUE.supportedMin))
        expect(error.supportedMax).toBe(BigInt(CATALOGUE.supportedMax))
        expect(error.supported).toEqual([
          BigInt(CATALOGUE.supportedMin),
          BigInt(CATALOGUE.supportedMax),
        ])
        expect(error.message).toContain(String(version))
        expect(error.message).toContain(String(CATALOGUE.supportedMax))
      }
    }
  })

  it('makes the two error shapes distinguishable', () => {
    // R8.8 is a claim about which of the two arrives, so neither may be the other. A `VersionError`
    // that were also a `DecodeError` would make the criterion untestable.
    const versionError = new VersionError(9n, 1n, 1n)
    const decodeErrorInstance = new DecodeError('v', 'detail')
    expect(versionError).not.toBeInstanceOf(DecodeError)
    expect(decodeErrorInstance).not.toBeInstanceOf(VersionError)
  })
})

// --- R8.8: the phase order decides which error arrives ----------------------------------------

describe('the phase order', () => {
  it('raises a version error when the version and a field are both wrong, for every combination', () => {
    // R8.8, on exactly the input the design says a test should construct directly. The full cross
    // product: every out-of-range version against every single-field violation the shared fault
    // generator can build, on every declared message type. A codec that validated before checking the
    // version would satisfy R8.6 and R8.7 and fail here, which is the entire reason the criterion
    // exists. Property 4 samples the same domain; this enumerates it.
    const versions = outOfRangeVersions(CATALOGUE)
    expect(versions.length).toBeGreaterThan(0)
    let checked = 0
    for (const message of EXAMPLES) {
      const messageType = CATALOGUE.messages.get(typeOf(message))!
      for (const violated of violationTargets(messageType, message)) {
        for (const version of versions) {
          const fault = new Fault({
            kind: 'unsupported-version-and-schema-violation',
            message,
            version,
            violated,
          })
          expect(fault.expectation).toBe('version-error')
          let error: unknown
          try {
            decode(fault.render(encode))
          } catch (thrown) {
            error = thrown
          }
          expect(
            error,
            `${messageType.t}: version ${version} with ${violated.violation} on ${violated.name}`,
          ).toBeInstanceOf(VersionError)
          expect((error as VersionError).received).toBe(version)
          checked += 1
        }
      }
    }
    expect(checked).toBeGreaterThan(0)
  })

  it('reports the root when the profile is violated below the version', () => {
    // The design calls a non-deterministic encoding a decode error, so `decode` raises one. It names
    // the root rather than a field, because no field is at fault: the representation as a whole is one
    // this codec could not have emitted.
    for (const t of CATALOGUE.messages.keys()) {
      const wire = encode(exampleMessage(t))
      const root = scan(wire)
      const spans = entries(root).map(([key, value]) => wire.subarray(key.start, value.end))
      const [first, second, third, fourth] = spans
      const transposed = new Uint8Array([
        ...wire.subarray(root.start, root.start + root.headLength),
        ...first!,
        ...third!,
        ...second!,
        ...fourth!,
      ])
      // Phase 0 and Phase 1 both pass on it; only the profile check in Phase 2 objects.
      expect(readVersion(transposed)).toBe(BigInt(CATALOGUE.protocolVersion))
      expect(() => decodeValue(transposed)).toThrow(NonCanonicalEncoding)
      expect(decodeError(transposed).field).toBe(ROOT_IDENTITY)
    }
  })

  it('reports the field validation named, because the mapping is a re-throw', () => {
    const message = withBody('fs.read', new Map<Value, Value>([[1, 'a text path']]))
    const wire = encodeValue(message as ReadonlyMap<Value, Value>)
    expect(violation(decodeValue(wire)).field).toBe('b.path')
    expect(decodeError(wire).field).toBe('b.path')
  })
})
