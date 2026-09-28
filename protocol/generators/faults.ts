// kiro-classification: public
//
// `malformed()`: the four fault classes Property 4's phase order must discriminate.
//
// The fast-check half of `faults.py`. The design's decode algorithm fixes three phases, and the order
// is the mechanism for R8.8. A generator for that property therefore has to produce inputs that make
// the order *observable*, which means four classes:
//
// | Class | Input | Error the codec owes |
// | --- | --- | --- |
// | `version-unreadable` | the version is absent, unreadable or not the first key | decode error naming field `1` |
// | `version-unsupported` | a readable version outside the supported range | version error carrying that version and both bounds |
// | `schema-violation` | a supported version and one violated field | decode error naming that field |
// | `version-unsupported-and-schema-violation` | both at once | version error, since Phase 1 precedes Phase 2 |
//
// The fourth class is the whole point, and the cross product is what makes it more than an anecdote:
// every out-of-range version is paired with every single-field violation, so a codec that happened to
// validate in the right order for one combination and not another is caught.
//
// A `Fault` is a declaration, not bytes. `render(encode)` applies it to the caller's canonical encoder,
// which keeps this module independent of the codec and lets the same fault be rendered by the Python
// encoder and the TypeScript one. Everything it does is byte surgery over the canonical encoding plus a
// handful of literal replacement values, because an encoder able to emit an unsupported version or a
// wrongly typed field would be a defect in the codec.

import fc from 'fast-check'

import {
  BREAK,
  INDEFINITE_INFO,
  type Item,
  Major,
  encodeHead,
  entries as mapEntries,
  payloadStart,
  replace,
  scan,
} from '../codec/cbor.js'
import {
  type Catalogue,
  ENVELOPE_KEY_BODY,
  ENVELOPE_KEY_TYPE,
  ENVELOPE_KEY_VERSION,
  type MessageType,
  type TypeKind,
  loadCatalogue,
  messageTypes,
  supports,
} from './catalogue.js'
import { type Envelope, type Value, message, messageOf } from './messages.js'

/** A canonical encoder: the Protocol_Codec's serialise, injected rather than imported. */
export type Encoder = (message: Envelope) => Uint8Array

const UNSUPPORTED_MESSAGE_TYPE = 'exec.undeclared'

const NOT_A_DECLARED_ENUM_VALUE = 'not-a-declared-value'

function textLiteral(value: string): Uint8Array {
  const payload = new TextEncoder().encode(value)
  const head = encodeHead(Major.TEXT, BigInt(payload.length))
  const joined = new Uint8Array(head.length + payload.length)
  joined.set(head, 0)
  joined.set(payload, head.length)
  return joined
}

/**
 * The value a wrongly typed field is replaced with, chosen per expected kind so the replacement is
 * always a *different* major type rather than an out-of-domain value.
 */
const TEXT_LITERAL = textLiteral('x')
const UINT_LITERAL = encodeHead(Major.UINT, 0n)

const WRONG_TYPE_FOR_KIND: ReadonlyMap<TypeKind, Uint8Array> = new Map([
  ['uint', TEXT_LITERAL],
  ['int', TEXT_LITERAL],
  ['bool', UINT_LITERAL],
  ['text', UINT_LITERAL],
  ['bytes', TEXT_LITERAL],
  ['list', UINT_LITERAL],
  ['map', UINT_LITERAL],
  ['struct', UINT_LITERAL],
])

/**
 * The widest integer a CBOR head can carry. Beyond it an encoder needs a bignum tag, which this
 * protocol does not use, so an out-of-range value above it is unreachable by surgery.
 */
const MAX_HEAD_INTEGER = (1n << 64n) - 1n

/** Which of the codec's two error types the fault must produce. */
export type Expectation = 'decode-error' | 'version-error'

/** The four classes the design's Property 4 names. */
export type FaultClass =
  | 'version-unreadable'
  | 'version-unsupported'
  | 'schema-violation'
  | 'version-unsupported-and-schema-violation'

/** How a fault is built. Several kinds share one `FaultClass`. */
export type FaultKind =
  /** Zero bytes: there is no map head, so Phase 0 cannot begin. */
  | 'empty-wire'
  /** Cut short inside the head or the first entry. */
  | 'truncated-wire'
  /** Key 1 is present and first, but its value is a text string. */
  | 'version-not-an-integer'
  /** Key 1 is present but not first, which Phase 0 must reject rather than search for. */
  | 'version-key-misplaced'
  /** An indefinite-length envelope, so there is no definite map head to read. */
  | 'indefinite-envelope'
  /** A readable version outside the supported range. */
  | 'unsupported-version'
  /** A supported version and one violated field. */
  | 'schema-violation'
  /** Both, which is the case that discriminates the phase order. */
  | 'unsupported-version-and-schema-violation'

export const UNREADABLE_KINDS: readonly FaultKind[] = [
  'empty-wire',
  'indefinite-envelope',
  'truncated-wire',
  'version-key-misplaced',
  'version-not-an-integer',
]

const CLASS_FOR_KIND: ReadonlyMap<FaultKind, FaultClass> = new Map([
  ['unsupported-version', 'version-unsupported'],
  ['schema-violation', 'schema-violation'],
  ['unsupported-version-and-schema-violation', 'version-unsupported-and-schema-violation'],
] as const)

/** Whether the violated field is an envelope key or a body field. */
export type Scope = 'envelope' | 'body'

/** How one field is made inadmissible. */
export type SchemaViolationKind =
  /** The value is replaced with one of a different CBOR major type. */
  | 'wrong-type'
  /** An integer outside its declared range. */
  | 'out-of-range'
  /** A text value outside its declared enum. */
  | 'not-in-enum'
  /** A required field removed from the body. */
  | 'missing-required-field'
  /** A body key the message type does not declare. */
  | 'unknown-body-key'
  /** A `t` value the catalogue does not declare, so no body schema selects. */
  | 'unknown-message-type'

/** One single-field schema violation, resolved against a drawn message. */
export interface Violated {
  readonly violation: SchemaViolationKind
  readonly scope: Scope
  /** The envelope key, or the body field key. */
  readonly key: number
  /** The catalogue's name for the field, for a failure message that reads. */
  readonly name: string
  /** The encoded value that substitutes for the field's, where the violation substitutes. */
  readonly replacement?: Uint8Array
}

/** Canonically encode one integer, which is all the surgery here ever writes. */
function encodeInteger(value: bigint): Uint8Array {
  return value >= 0n ? encodeHead(Major.UINT, value) : encodeHead(Major.NEGINT, -1n - value)
}

/**
 * Versions the codec must reject in Phase 1, ascending.
 *
 * Derived from the declared range rather than listed, so widening `supportedMax` narrows this set
 * instead of leaving a stale value that would now be admissible.
 */
export function outOfRangeVersions(catalogue: Catalogue): readonly bigint[] {
  const candidates = new Set<bigint>([
    BigInt(catalogue.supportedMin) - 1n,
    BigInt(catalogue.supportedMax) + 1n,
    0n,
    2n,
    255n,
    256n,
    65536n,
    1n << 32n,
    MAX_HEAD_INTEGER,
  ])
  return [...candidates]
    .filter(
      (version) =>
        0n <= version && version <= MAX_HEAD_INTEGER && !supports(catalogue, version),
    )
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
}

/** A value outside `[low, high]` that a CBOR head can carry, or null if there is none. */
function outsideRange(low: bigint, high: bigint): bigint | null {
  if (high + 1n <= MAX_HEAD_INTEGER) {
    return high + 1n
  }
  if (low - 1n >= -MAX_HEAD_INTEGER - 1n) {
    return low - 1n
  }
  // No catalogue range spans the whole encodable domain.
  return null
}

/**
 * Every single-field violation reachable in this drawn message.
 *
 * Resolved against the message rather than against the schema alone, because a violation that
 * substitutes or removes a field needs that field to be present, and an optional field may have been
 * omitted.
 */
export function violationTargets(
  messageType: MessageType,
  drawn: Envelope,
): readonly Violated[] {
  const undeclaredKey = messageType.body.length + 1
  const targets: Violated[] = [
    {
      violation: 'unknown-message-type',
      scope: 'envelope',
      key: ENVELOPE_KEY_TYPE,
      name: 't',
      replacement: textLiteral(UNSUPPORTED_MESSAGE_TYPE),
    },
    {
      violation: 'wrong-type',
      scope: 'envelope',
      key: ENVELOPE_KEY_TYPE,
      name: 't',
      replacement: wrongTypeFor('text'),
    },
    {
      violation: 'wrong-type',
      scope: 'envelope',
      key: ENVELOPE_KEY_BODY,
      name: 'b',
      replacement: wrongTypeFor('map'),
    },
    // A key beyond the declared block. Keys are contiguous from 1, so one past the last declared key
    // is undeclared, and it still sorts last under the deterministic profile.
    {
      violation: 'unknown-body-key',
      scope: 'body',
      key: undeclaredKey,
      name: String(undeclaredKey),
      replacement: UINT_LITERAL,
    },
  ]

  const body = drawn.get(ENVELOPE_KEY_BODY)
  const present =
    body instanceof Map
      ? new Set<Value>((body as ReadonlyMap<Value, Value>).keys())
      : new Set<Value>()

  for (const field of messageType.body) {
    if (!present.has(field.key)) {
      continue
    }
    const spec = field.spec
    targets.push({
      violation: 'wrong-type',
      scope: 'body',
      key: field.key,
      name: field.name,
      replacement: wrongTypeFor(spec.kind),
    })
    if (!field.optional) {
      targets.push({
        violation: 'missing-required-field',
        scope: 'body',
        key: field.key,
        name: field.name,
      })
    }
    if (spec.enum !== undefined) {
      targets.push({
        violation: 'not-in-enum',
        scope: 'body',
        key: field.key,
        name: field.name,
        replacement: textLiteral(NOT_A_DECLARED_ENUM_VALUE),
      })
    }
    if (spec.range !== undefined) {
      const outside = outsideRange(spec.range.min, spec.range.max)
      if (outside !== null) {
        targets.push({
          violation: 'out-of-range',
          scope: 'body',
          key: field.key,
          name: field.name,
          replacement: encodeInteger(outside),
        })
      }
    }
  }
  return targets
}

function wrongTypeFor(kind: TypeKind): Uint8Array {
  const replacement = WRONG_TYPE_FOR_KIND.get(kind)
  if (replacement === undefined) {
    throw new RangeError(`no wrong-type replacement is declared for ${kind}`)
  }
  return replacement
}

/** One malformed wire representation, declared rather than encoded. */
export class Fault {
  readonly kind: FaultKind

  /** The well-formed message the fault is applied to. */
  readonly message: Envelope

  /** The version the rendered wire carries, when the fault rewrites it. */
  readonly version: bigint | null

  readonly violated: Violated | null

  /** For `truncated-wire`: how many bytes of the encoding survive. */
  readonly keepBytes: number | null

  constructor(options: {
    readonly kind: FaultKind
    readonly message: Envelope
    readonly version?: bigint
    readonly violated?: Violated
    readonly keepBytes?: number
  }) {
    this.kind = options.kind
    this.message = options.message
    this.version = options.version ?? null
    this.violated = options.violated ?? null
    this.keepBytes = options.keepBytes ?? null
  }

  get faultClass(): FaultClass {
    if (UNREADABLE_KINDS.includes(this.kind)) {
      return 'version-unreadable'
    }
    const resolved = CLASS_FOR_KIND.get(this.kind)
    if (resolved === undefined) {
      throw new RangeError(`no fault class is declared for ${this.kind}`)
    }
    return resolved
  }

  get expectation(): Expectation {
    const resolved = this.faultClass
    return resolved === 'version-unsupported' ||
      resolved === 'version-unsupported-and-schema-violation'
      ? 'version-error'
      : 'decode-error'
  }

  /**
   * The spellings a decode error may use for the field it names.
   *
   * The design fixes the envelope case — field `1` when the version is unreadable — and leaves the
   * body case to the codec, so a body field is accepted under its integer key, its catalogue name, or
   * either qualified by the body key. Pinning one spelling here would be this module deciding an
   * interface that belongs to the codec.
   */
  get acceptableFieldIdentities(): ReadonlySet<string> {
    if (this.expectation !== 'decode-error') {
      return new Set()
    }
    if (this.violated === null) {
      return new Set([String(ENVELOPE_KEY_VERSION), 'v'])
    }
    const { key, name, scope } = this.violated
    if (scope === 'envelope') {
      return new Set([String(key), name])
    }
    return new Set([
      String(key),
      name,
      `${ENVELOPE_KEY_BODY}.${key}`,
      `b.${key}`,
      `b.${name}`,
    ])
  }

  /** Whether `reported` names the field this fault violates. */
  identifies(reported: string): boolean {
    return this.acceptableFieldIdentities.has(reported)
  }

  /** Apply the fault to `encode(this.message)` and return the malformed bytes. */
  render(encode: Encoder): Uint8Array {
    let wire = encode(this.message)
    if (this.kind === 'empty-wire') {
      return new Uint8Array()
    }
    if (this.kind === 'truncated-wire') {
      const keep = this.keepBytes ?? 1
      return wire.subarray(0, Math.min(keep, wire.length - 1))
    }

    let root = scan(wire)
    if (this.kind === 'indefinite-envelope') {
      return concatBytes([
        new Uint8Array([(Major.MAP << 5) | INDEFINITE_INFO]),
        wire.subarray(payloadStart(root), root.end),
        new Uint8Array([BREAK]),
      ])
    }
    if (this.kind === 'version-key-misplaced') {
      return transposeFirstTwoEntries(wire, root)
    }
    if (this.kind === 'version-not-an-integer') {
      return replaceEnvelopeValue(wire, root, ENVELOPE_KEY_VERSION, TEXT_LITERAL)
    }

    if (this.version !== null) {
      wire = replaceEnvelopeValue(
        wire,
        root,
        ENVELOPE_KEY_VERSION,
        encodeInteger(this.version),
      )
      root = scan(wire)
    }
    if (this.violated !== null) {
      wire = apply(wire, root, this.violated)
    }
    return wire
  }
}

function entryForKey(root: Item, key: number): readonly [Item, Item] {
  for (const pair of mapEntries(root)) {
    if (pair[0].major === Major.UINT && pair[0].argument === BigInt(key)) {
      return pair
    }
  }
  throw new RangeError(`the encoding carries no entry keyed ${key}`)
}

function replaceEnvelopeValue(
  wire: Uint8Array,
  root: Item,
  key: number,
  replacement: Uint8Array,
): Uint8Array {
  const [, valueItem] = entryForKey(root, key)
  return replace(wire, valueItem.start, valueItem.end, replacement)
}

function transposeFirstTwoEntries(wire: Uint8Array, root: Item): Uint8Array {
  const pairs = mapEntries(root)
  const first = pairs[0]
  const second = pairs[1]
  if (first === undefined || second === undefined) {
    throw new RangeError('the envelope carries fewer than two entries')
  }
  const left = wire.subarray(first[0].start, first[1].end)
  const right = wire.subarray(second[0].start, second[1].end)
  return replace(wire, first[0].start, second[1].end, concatBytes([right, left]))
}

function apply(wire: Uint8Array, root: Item, violated: Violated): Uint8Array {
  if (violated.scope === 'envelope') {
    return replaceEnvelopeValue(wire, root, violated.key, required(violated.replacement))
  }

  const [, body] = entryForKey(root, ENVELOPE_KEY_BODY)
  if (violated.violation === 'unknown-body-key') {
    const entry = concatBytes([
      encodeHead(Major.UINT, BigInt(violated.key)),
      required(violated.replacement),
    ])
    // Append before re-heading, so the head's offsets stay valid.
    const appended = replace(wire, body.end, body.end, entry)
    return replace(
      appended,
      body.start,
      payloadStart(body),
      encodeHead(Major.MAP, body.argument + 1n),
    )
  }

  const [keyItem, valueItem] = entryForKey(body, violated.key)
  if (violated.violation === 'missing-required-field') {
    const removed = replace(wire, keyItem.start, valueItem.end, new Uint8Array())
    return replace(
      removed,
      body.start,
      payloadStart(body),
      encodeHead(Major.MAP, body.argument - 1n),
    )
  }

  return replace(wire, valueItem.start, valueItem.end, required(violated.replacement))
}

function required(replacement: Uint8Array | undefined): Uint8Array {
  if (replacement === undefined) {
    throw new RangeError('this violation substitutes a value and declares none')
  }
  return replacement
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

// --- Strategies ------------------------------------------------------------------------------

function violatedMessage(
  catalogue: Catalogue,
): fc.Arbitrary<readonly [Envelope, Violated]> {
  return fc.constantFrom(...messageTypes(catalogue)).chain((t) =>
    messageOf(t, catalogue).chain((drawn) => {
      const messageType = catalogue.messages.get(t)
      if (messageType === undefined) {
        throw new Error(`the catalogue declares no message type ${t}`)
      }
      return fc
        .constantFrom(...violationTargets(messageType, drawn))
        .map((violated) => [drawn, violated] as const)
    }),
  )
}

function versionUnreadable(catalogue: Catalogue): fc.Arbitrary<Fault> {
  return fc
    .tuple(
      message({ catalogue }),
      fc.constantFrom(...UNREADABLE_KINDS),
      // One byte through the first entry's head: enough to be a plausible prefix, never enough to
      // carry a version.
      fc.integer({ min: 1, max: 3 }),
    )
    .map(([drawn, kind, keepBytes]) =>
      kind === 'truncated-wire'
        ? new Fault({ kind, message: drawn, keepBytes })
        : new Fault({ kind, message: drawn }),
    )
}

function versionUnsupported(catalogue: Catalogue): fc.Arbitrary<Fault> {
  return fc
    .tuple(message({ catalogue }), fc.constantFrom(...outOfRangeVersions(catalogue)))
    .map(
      ([drawn, version]) =>
        new Fault({ kind: 'unsupported-version', message: drawn, version }),
    )
}

function schemaViolation(catalogue: Catalogue): fc.Arbitrary<Fault> {
  return violatedMessage(catalogue).map(
    ([drawn, violated]) =>
      new Fault({ kind: 'schema-violation', message: drawn, violated }),
  )
}

/** The cross product: every out-of-range version against every single-field violation. */
function both(catalogue: Catalogue): fc.Arbitrary<Fault> {
  return fc
    .tuple(violatedMessage(catalogue), fc.constantFrom(...outOfRangeVersions(catalogue)))
    .map(
      ([[drawn, violated], version]) =>
        new Fault({
          kind: 'unsupported-version-and-schema-violation',
          message: drawn,
          version,
          violated,
        }),
    )
}

/**
 * The four fault classes, drawn with equal weight (R8.6, R8.7, R8.8).
 *
 * Equal weight rather than proportional to the number of ways each class can be built, so the
 * cross-product class — the one that discriminates a correct phase order from an accidental one —
 * gets a quarter of the draws rather than a residue.
 */
export function malformed(
  options: { readonly catalogue?: Catalogue } = {},
): fc.Arbitrary<Fault> {
  const catalogue = options.catalogue ?? loadCatalogue()
  return fc.oneof(
    versionUnreadable(catalogue),
    versionUnsupported(catalogue),
    schemaViolation(catalogue),
    both(catalogue),
  )
}
