// kiro-classification: public
//
// `message()`: valid Sandbox_Protocol messages, derived from the schema catalogue (R8.4).
//
// The fast-check half of `messages.py`, and the same generator the design's Property 1 names: it
// draws a message type from the catalogue and populates its body from that type's schema, with
// byte-string fields drawn from arbitrary byte sequences including empty and integer fields drawn
// from the boundaries of their declared ranges. It walks `TypeSpec` rather than restating any
// message shape, so a field added to `messages.yaml` is populated here with no edit.
//
// The bounds, the container ceilings and the boundary sets are the same values as the Python
// half's. A domain that differed between the two languages would make a passing round-trip in one
// of them mean less than it claims, and the vector corpus (task 2.10) would be left to discover
// the difference as a wire disagreement.

import fc from 'fast-check'

import { MAX_OUTPUT_BYTES, outputBytes } from './byteDomains.js'
import {
  type Catalogue,
  ENVELOPE_KEY_BODY,
  ENVELOPE_KEY_ID,
  ENVELOPE_KEY_TYPE,
  ENVELOPE_KEY_VERSION,
  type Field,
  type IntRange,
  type MessageType,
  type TypeSpec,
  loadCatalogue,
  messageTypes,
} from './catalogue.js'

export type Value =
  | number
  | bigint
  | boolean
  | string
  | Uint8Array
  | readonly Value[]
  | ReadonlyMap<Value, Value>

/** One message: the definite-length four-key CBOR map from the design's message shape table. */
export type Envelope = ReadonlyMap<number, Value>

/**
 * Containers stay small. A message carrying a hundred-element list exercises the same code path as
 * one carrying three, and it costs a thousand-run codec property real time.
 */
export const MAX_CONTAINER_SIZE = 4

/**
 * Byte fields nested inside a list or a map get a lower ceiling than a top-level one, so an `env`
 * map cannot multiply its per-entry ceiling by its entry count into a megabyte message.
 */
export const MAX_NESTED_BYTES = 256

export const MAX_CORRELATION_ID_BYTES = 16

export const MAX_TEXT_LENGTH = 32

/**
 * The CBOR head-width crossings, as integer values rather than as lengths. An integer field whose
 * declared range spans one of these reaches a width the codec must select correctly.
 */
const CBOR_ARGUMENT_BOUNDARIES: readonly bigint[] = [
  23n,
  24n,
  255n,
  256n,
  65535n,
  65536n,
  4294967295n,
  4294967296n,
]

/** Values where an encoder's sign or zero handling changes. */
const SIGN_BOUNDARIES: readonly bigint[] = [-1n, 0n, 1n]

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER)

/**
 * A drawn integer, as `number` when that is exact and `bigint` when it is not.
 *
 * The catalogue declares ranges up to 2^64 - 1, which no JavaScript number holds, and down to
 * small signed ranges that a reader will see as ordinary numbers. Emitting whichever of the two a
 * conformant CBOR reader produces for that value is what lets Property 1 compare a decoded message
 * with the drawn one by value; a generator that emitted `1n` where the codec decodes `1` would fail
 * the round-trip on the representation rather than on the protocol.
 */
function narrow(value: bigint): number | bigint {
  return value >= -MAX_SAFE && value <= MAX_SAFE ? Number(value) : value
}

/**
 * The values an integer field of this range is drawn from, ascending.
 *
 * The declared bounds, which is what the design's generator names, plus the values inside them
 * where an encoding decision changes: the sign transition, and each CBOR head-width crossing and
 * its neighbour. A field declared 0 to 4,294,967,295 encodes across four head widths, and a codec
 * that mis-selects one fails only at a crossing.
 */
export function integerBoundaries(range: IntRange): readonly bigint[] {
  const candidates = new Set<bigint>([range.min, range.max, ...SIGN_BOUNDARIES])
  for (const crossing of CBOR_ARGUMENT_BOUNDARIES) {
    candidates.add(crossing)
    candidates.add(-crossing)
  }
  return [...candidates]
    .filter((value) => range.min <= value && value <= range.max)
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
}

function integer(spec: TypeSpec): fc.Arbitrary<number | bigint> {
  if (spec.range === undefined) {
    // The loader rejects such a catalogue, so reaching this means the mirror was hand-edited.
    throw new Error(`a ${spec.kind} field must declare its range`)
  }
  const { min, max } = spec.range
  return fc
    .oneof(
      fc.constantFrom(...integerBoundaries(spec.range)),
      fc.bigInt({ min, max }),
    )
    .map(narrow)
}

function text(spec: TypeSpec): fc.Arbitrary<string> {
  if (spec.enum !== undefined) {
    return fc.constantFrom(...spec.enum)
  }
  // Surrogates are excluded because CBOR major type 3 is a UTF-8 text string and a lone surrogate
  // has no UTF-8 encoding. That is not a narrowing of R8.9: process output and filesystem names
  // are byte-typed precisely so the unencodable cases live there, and `outputBytes()` covers them.
  return fc.string({ unit: 'grapheme', maxLength: MAX_TEXT_LENGTH })
}

/** The envelope's `id`: an opaque correlation handle, empty included. */
export function correlationId(): fc.Arbitrary<Uint8Array> {
  return fc.uint8Array({ maxLength: MAX_CORRELATION_ID_BYTES })
}

/** A value admissible for `spec`, drawn from the domain its kind declares. */
export function valueFor(spec: TypeSpec, nested = false): fc.Arbitrary<Value> {
  switch (spec.kind) {
    case 'uint':
    case 'int':
      return integer(spec)
    case 'bool':
      return fc.boolean()
    case 'text':
      return text(spec)
    case 'bytes':
      // Every byte field is drawn from the adversarial domain whether or not it is annotated: the
      // catalogue types them as bytes because the protocol carries them verbatim, and a field the
      // annotation happens not to cover is carried no differently.
      return outputBytes(nested ? MAX_NESTED_BYTES : MAX_OUTPUT_BYTES)
    case 'list': {
      if (spec.items === undefined) {
        throw new Error('a list must declare items')
      }
      return fc.array(valueFor(spec.items, true), { maxLength: MAX_CONTAINER_SIZE })
    }
    case 'map': {
      if (spec.keys === undefined || spec.values === undefined) {
        // The envelope's `b` declares neither, because its schema is selected by `t`.
        return fc.constant(new Map<Value, Value>())
      }
      return fc
        .array(fc.tuple(valueFor(spec.keys, true), valueFor(spec.values, true)), {
          maxLength: MAX_CONTAINER_SIZE,
        })
        .map(deduplicateKeys)
    }
    case 'struct':
      return fields(spec.fields, true)
  }
}

/**
 * The identity two map keys share when CBOR cannot tell them apart.
 *
 * A byte string's identity is its bytes, and it needs saying because a `Map` does not agree: it keys
 * by object identity, so two distinct `Uint8Array` objects carrying the same bytes are two entries.
 * Python's `dict` keys `bytes` by value and collapses them before anything downstream can see the
 * pair, which is why the Python half of this generator needs no equivalent.
 *
 * Tagged per type rather than stringified flat, so a byte string and the text string that happens to
 * render the same way are not conflated — they are different major types on the wire.
 */
function mapKeyIdentity(value: Value): string {
  if (value instanceof Uint8Array) {
    return `bytes:${[...value].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`
  }
  if (typeof value === 'string') {
    return `text:${value}`
  }
  if (typeof value === 'boolean') {
    return `bool:${value}`
  }
  if (typeof value === 'number' || typeof value === 'bigint') {
    return `int:${value}`
  }
  if (Array.isArray(value)) {
    return `list:[${(value as readonly Value[]).map(mapKeyIdentity).join(',')}]`
  }
  return `map:{${[...(value as ReadonlyMap<Value, Value>)]
    .map(([key, item]) => `${mapKeyIdentity(key)}=${mapKeyIdentity(item)}`)
    .sort()
    .join(',')}}`
}

/**
 * Build a map, keeping the last entry for each distinct key.
 *
 * A CBOR map has no way to carry two entries whose keys encode to the same bytes, and the
 * deterministic profile makes that explicit by ordering entries by encoded key: duplicates would
 * compare equal rather than ascend. So a drawn value with two byte-equal keys is not a valid message
 * and drawing one would make Property 1 fail on the generator rather than on the codec. Last entry
 * wins, which is what `new Map(entries)` already does for keys it recognises as equal.
 */
function deduplicateKeys(entries: readonly (readonly [Value, Value])[]): ReadonlyMap<Value, Value> {
  const byIdentity = new Map<string, readonly [Value, Value]>()
  for (const entry of entries) {
    byIdentity.set(mapKeyIdentity(entry[0]), entry)
  }
  return new Map<Value, Value>([...byIdentity.values()])
}

/**
 * A map keyed by the declared integer keys, omitting optional fields sometimes.
 *
 * Omission is drawn independently of every other field. The catalogue declares optionality per
 * field and states no cross-field rule — `proc.status.exitCode` is absent while the process is
 * running, but nothing in the schema ties the two — so a generator that inferred one would be
 * asserting a constraint the codec does not validate.
 */
function fields(
  declared: readonly Field[],
  nested: boolean,
): fc.Arbitrary<ReadonlyMap<Value, Value>> {
  if (declared.length === 0) {
    return fc.constant(new Map<Value, Value>())
  }
  const perField = declared.map((field) =>
    fc
      .tuple(
        valueFor(field.spec, nested),
        field.optional ? fc.boolean() : fc.constant(false),
      )
      .map(([value, omitted]) => ({ key: field.key, value, omitted })),
  )
  return fc.tuple(...perField).map(
    (drawn) =>
      new Map<Value, Value>(
        drawn
          .filter((entry) => !entry.omitted)
          .map((entry) => [entry.key, entry.value] as const),
      ),
  )
}

/** The body map for one message type, keyed by the catalogue's integer field keys. */
export function body(messageType: MessageType): fc.Arbitrary<ReadonlyMap<Value, Value>> {
  return fields(messageType.body, false)
}

/** A valid message of exactly one type. */
export function messageOf(t: string, catalogue: Catalogue = loadCatalogue()): fc.Arbitrary<Envelope> {
  const messageType = catalogue.messages.get(t)
  if (messageType === undefined) {
    throw new Error(`the catalogue declares no message type ${t}`)
  }
  return fc.tuple(correlationId(), body(messageType)).map(
    ([id, drawnBody]) =>
      new Map<number, Value>([
        // The emitted version, not a drawn one: a message carrying an unsupported version is not a
        // valid message, and Property 4's fault generator owns that domain.
        [ENVELOPE_KEY_VERSION, catalogue.protocolVersion],
        [ENVELOPE_KEY_TYPE, messageType.t],
        [ENVELOPE_KEY_ID, id],
        [ENVELOPE_KEY_BODY, drawnBody],
      ]),
  )
}

/**
 * Any valid Sandbox_Protocol message (R8.4).
 *
 * Draws a message type from the catalogue and populates its body from that type's schema. `types`
 * narrows the draw, which is what a property needing a message with a non-empty body uses rather
 * than filtering after the fact.
 */
export function message(options: {
  readonly types?: readonly string[]
  readonly catalogue?: Catalogue
} = {}): fc.Arbitrary<Envelope> {
  const catalogue = options.catalogue ?? loadCatalogue()
  const chosen = options.types ?? messageTypes(catalogue)
  if (chosen.length === 0) {
    throw new Error('message() needs at least one message type to draw from')
  }
  return fc.oneof(...chosen.map((t) => messageOf(t, catalogue)))
}
