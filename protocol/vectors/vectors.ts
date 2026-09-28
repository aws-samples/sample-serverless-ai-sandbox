// kiro-classification: public
//
// The TypeScript reader for the vector corpus.
//
// The corpus is written by `export_vectors.py` and read here, which is the whole arrangement: one
// artefact, two independent readers, and the bytes belong to the Python codec. This module is
// deliberately only a reader — it constructs no wire representation and knows nothing about CBOR, so
// a defect in it cannot make a disagreement look like agreement. Everything that touches bytes is
// `protocol/codec/`.
//
// It reads three things back out of the JSON that Python wrote:
//
// - **Tagged values.** A scalar is `"bytes:ff"`, `"int:-1"`, `"text:hello"`, `"bool:true"`; a
//   container is `{"list": [...]}` or `{"map": [[key, value], ...]}`. Integers arrive as decimal
//   strings and are narrowed with the codec's own `narrowInteger`, because the codec narrows a
//   *decoded* integer by that rule and a reader that chose differently would report a
//   representation difference as a protocol disagreement.
// - **Paths.** A sequence of map keys and list indices from the envelope to one leaf. An integer key
//   is a bare JSON number; a list index is `{"index": n}`; anything else is a tagged scalar.
// - **Field labels.** Taken from the file rather than recomputed. The schema's name for a path is a
//   label on a failure message, and a second implementation of the naming would be a second opinion
//   about it with nothing to gain.
//
// Map lookup goes through `valueIdentity` rather than `Map.get`. A decoded map keyed by `Uint8Array`
// cannot be indexed by a freshly parsed `Uint8Array` — JavaScript compares them by identity — and
// the one nested map the catalogue declares, `env`, is keyed by byte strings, so this is the ordinary
// case here rather than an edge one.

import { readFileSync } from 'node:fs'

import { valueIdentity } from '../codec/equal.js'
import { type Message, type Value, narrowInteger } from '../codec/values.js'

export const MESSAGES_JSON_PATH = new URL('./messages.json', import.meta.url)
export const VALUES_JSON_PATH = new URL('./values.json', import.meta.url)
export const REJECTIONS_JSON_PATH = new URL('./rejections.json', import.meta.url)

/** A list index, wrapped so it cannot be confused with an integer map key. */
export interface Index {
  readonly index: number
}

/** One step of a path: a map key, or a list index. */
export type Step = number | bigint | boolean | string | Uint8Array | Index

/** A path from the envelope map to one part of a message. The empty path is the message itself. */
export type Path = readonly Step[]

/** What a rejection vector requires of the decoder. */
export type Expect = 'decode-error' | 'version-error' | 'non-canonical'

export interface FieldExpectation {
  readonly path: Path
  /** The schema's name for `path`, as the corpus records it: `b.env[0x2f]`, `b.entries[0].size`. */
  readonly field: string
  readonly expected: Value
}

export interface MessageVector {
  readonly name: string
  readonly t: string
  readonly origin: 'explicit' | 'sampled'
  readonly wire: Uint8Array
  /** Every leaf of the message, in the order it was built. Serves both directions. */
  readonly fields: readonly FieldExpectation[]
  /** Optional fields this vector omits, named so a failure says which one reappeared. */
  readonly absent: readonly { readonly path: Path; readonly field: string }[]
}

export interface ValueVector {
  readonly name: string
  readonly note: string
  readonly wire: Uint8Array
  readonly value: Value
}

export interface RejectionVector {
  readonly name: string
  readonly note: string
  readonly wire: Uint8Array
  readonly expect: Expect
  /** For `decode-error`: the spellings the codec may use for the field it names. */
  readonly fieldIdentities: readonly string[]
  /** For `version-error`: the version the representation carries. */
  readonly received?: bigint
}

// --- Tagged values -----------------------------------------------------------------------------

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let at = 0; at < bytes.length; at += 1) {
    bytes[at] = Number.parseInt(hex.slice(at * 2, at * 2 + 2), 16)
  }
  return bytes
}

/** Render a byte string the way a failure message wants it. */
export function hex(data: Uint8Array): string {
  return [...data].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

interface TaggedContainer {
  readonly list?: readonly unknown[]
  readonly map?: readonly (readonly [unknown, unknown])[]
}

/** Read a tagged value into the protocol's value space. */
export function fromTagged(tagged: unknown): Value {
  if (typeof tagged === 'string') {
    const at = tagged.indexOf(':')
    // The *first* colon, so `"text:int:5"` is the string `int:5` rather than the integer 5.
    const kind = at === -1 ? tagged : tagged.slice(0, at)
    const body = at === -1 ? '' : tagged.slice(at + 1)
    switch (kind) {
      case 'bool':
        return body === 'true'
      case 'int':
        return narrowInteger(BigInt(body))
      case 'bytes':
        return fromHex(body)
      case 'text':
        return body
      default:
        throw new Error(`'${kind}' is not a scalar kind the protocol declares`)
    }
  }
  if (tagged === null || typeof tagged !== 'object') {
    throw new Error(`${JSON.stringify(tagged)} is not a tagged value`)
  }
  const container = tagged as TaggedContainer
  if (container.list !== undefined) {
    return container.list.map(fromTagged)
  }
  if (container.map !== undefined) {
    return new Map<Value, Value>(
      container.map.map(([key, item]) => [fromTagged(key), fromTagged(item)]),
    )
  }
  throw new Error(`${JSON.stringify(tagged)} names no container kind the protocol declares`)
}

function isIndex(step: Step): step is Index {
  return typeof step === 'object' && step !== null && !(step instanceof Uint8Array)
}

function stepFromJson(raw: unknown): Step {
  if (typeof raw === 'number') {
    return raw
  }
  if (raw !== null && typeof raw === 'object' && 'index' in raw) {
    return { index: Number((raw as { index: number }).index) }
  }
  const read = fromTagged(raw)
  // Narrowed by what a key *can* be rather than by excluding what it cannot: the value space is a
  // union with two container arms, and excluding both leaves the compiler holding `Value` still.
  if (
    typeof read === 'number' ||
    typeof read === 'bigint' ||
    typeof read === 'boolean' ||
    typeof read === 'string' ||
    read instanceof Uint8Array
  ) {
    return read
  }
  throw new Error('a map key the protocol can carry is never a container')
}

// --- Paths -------------------------------------------------------------------------------------

/** A total rendering of a path, equal exactly when two paths address the same part of a value. */
export function pathIdentity(path: Path): string {
  return path
    .map((step) => (isIndex(step) ? `#${step.index}` : `k${valueIdentity(step)}`))
    .join('/')
}

/** A path as the corpus's own field labels are not available for: value vectors and failures. */
export function pathText(path: Path): string {
  return path
    .map((step) => (isIndex(step) ? `[${step.index}]` : `[${valueIdentity(step)}]`))
    .join('')
}

/**
 * Every scalar and every empty container in `value`, by path identity.
 *
 * Total over the value: each part of it is named by exactly one path, so comparing two values leaf
 * by leaf *and* comparing their path sets is a complete comparison rather than a sample. An empty
 * map or list is a leaf in its own right — `fs.ack` has an empty body, and without that rule the
 * field would have no path and nothing would be compared.
 */
export function leaves(value: Value, prefix: Path = []): Map<string, { path: Path; value: Value }> {
  const found = new Map<string, { path: Path; value: Value }>()
  if (value instanceof Map) {
    if (value.size === 0) {
      found.set(pathIdentity(prefix), { path: prefix, value })
      return found
    }
    for (const [key, item] of value) {
      if (Array.isArray(key) || key instanceof Map) {
        throw new Error('a map key the protocol can carry is never a container')
      }
      for (const [identity, leaf] of leaves(item, [...prefix, key as Step])) {
        found.set(identity, leaf)
      }
    }
    return found
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      found.set(pathIdentity(prefix), { path: prefix, value })
      return found
    }
    for (const [at, item] of value.entries()) {
      for (const [identity, leaf] of leaves(item, [...prefix, { index: at }])) {
        found.set(identity, leaf)
      }
    }
    return found
  }
  found.set(pathIdentity(prefix), { path: prefix, value })
  return found
}

/** Follow `path` into `value`, reporting absence rather than throwing on it. */
export function resolve(value: Value, path: Path): { found: boolean; value?: Value } {
  let current: Value = value
  for (const step of path) {
    if (isIndex(step)) {
      if (!Array.isArray(current) || step.index < 0 || step.index >= current.length) {
        return { found: false }
      }
      current = current[step.index] as Value  // nosemgrep: prototype-pollution-loop — CBOR traversal
      continue
    }
    if (!(current instanceof Map)) {
      return { found: false }
    }
    const wanted = valueIdentity(step)
    const entry = [...current].find(([key]) => valueIdentity(key) === wanted)
    if (entry === undefined) {
      return { found: false }
    }
    current = entry[1]
  }
  return { found: true, value: current }
}

/**
 * The value whose leaves are exactly `fields`, containers created in declaration order.
 *
 * The inverse of `leaves` and the input to the production direction. Whether a container is a map
 * or a list is read off the step that enters it, so no separate shape declaration is needed and the
 * two cannot disagree.
 *
 * Declaration order is load-bearing. Entries are inserted in the order the paths arrive, so a
 * vector whose nested map keys are declared in reverse canonical order hands the encoder a map it
 * has to sort. A rebuild that sorted the keys itself would quietly do the encoder's job, and a
 * codec that never ordered map keys at all would pass.
 */
export function rebuild(fields: readonly FieldExpectation[]): Value {
  const root = fields.find((field) => field.path.length === 0)
  if (root !== undefined) {
    return root.expected
  }
  if (fields.length === 0) {
    throw new Error('a vector with no fields describes no value')
  }
  const first = fields[0]?.path[0]
  const container: Value = first !== undefined && isIndex(first) ? [] : new Map<Value, Value>()
  for (const field of fields) {
    place(container, field.path, field.expected)
  }
  return container
}

function place(container: Value, path: Path, leaf: Value): void {
  const [step, ...rest] = path
  if (step === undefined) {
    throw new Error('an empty path has no place to be assigned')
  }
  if (rest.length === 0) {
    assign(container, step, leaf)
    return
  }
  let existing = lookup(container, step)
  if (existing === undefined) {
    const next = rest[0]
    existing = next !== undefined && isIndex(next) ? [] : new Map<Value, Value>()
    assign(container, step, existing)
  }
  place(existing, rest, leaf)
}

function assign(container: Value, step: Step, item: Value): void {
  if (isIndex(step)) {
    if (!Array.isArray(container) || step.index !== container.length) {
      throw new Error(`list index ${step.index} is out of order for a rebuild`)
    }
    ;(container as Value[]).push(item)
    return
  }
  if (!(container instanceof Map)) {
    throw new Error(`key ${valueIdentity(step)} addresses a map, but a list is here`)
  }
  ;(container as Map<Value, Value>).set(step, item)
}

function lookup(container: Value, step: Step): Value | undefined {
  if (isIndex(step)) {
    if (!Array.isArray(container) || step.index >= container.length) {
      return undefined
    }
    return container[step.index] as Value
  }
  if (!(container instanceof Map)) {
    throw new Error(`key ${valueIdentity(step)} addresses a map, but a list is here`)
  }
  const wanted = valueIdentity(step)
  return [...container].find(([key]) => valueIdentity(key) === wanted)?.[1]
}

/** A rebuilt message, narrowed to what `encode` takes. */
export function asMessage(value: Value): Message {
  if (!(value instanceof Map)) {
    throw new Error('a message is the envelope map')
  }
  const envelope = new Map<number, Value>()
  for (const [key, item] of value) {
    if (typeof key !== 'number') {
      throw new Error(`envelope key ${valueIdentity(key)} is not one of the four integers`)
    }
    envelope.set(key, item)
  }
  return envelope
}

// --- Reading the committed corpus ----------------------------------------------------------------

function document(path: URL): Record<string, unknown> {
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
}

function readPath(raw: readonly unknown[]): Path {
  return raw.map(stepFromJson)
}

interface RawField {
  readonly path: readonly unknown[]
  readonly field: string
  readonly expected?: unknown
}

export function loadMessages(path: URL = MESSAGES_JSON_PATH): readonly MessageVector[] {
  const raw = document(path).vectors as readonly Record<string, unknown>[]
  return raw.map((vector) => ({
    name: vector.name as string,
    t: vector.t as string,
    origin: vector.origin as 'explicit' | 'sampled',
    wire: fromHex(vector.wire as string),
    fields: (vector.fields as readonly RawField[]).map((field) => ({
      path: readPath(field.path),
      field: field.field,
      expected: fromTagged(field.expected),
    })),
    absent: (vector.absent as readonly RawField[]).map((entry) => ({
      path: readPath(entry.path),
      field: entry.field,
    })),
  }))
}

export function loadValues(path: URL = VALUES_JSON_PATH): readonly ValueVector[] {
  const raw = document(path).vectors as readonly Record<string, unknown>[]
  return raw.map((vector) => ({
    name: vector.name as string,
    note: vector.note as string,
    wire: fromHex(vector.wire as string),
    value: fromTagged(vector.value),
  }))
}

export function loadRejections(path: URL = REJECTIONS_JSON_PATH): readonly RejectionVector[] {
  const raw = document(path).vectors as readonly Record<string, unknown>[]
  return raw.map((vector) => {
    const received = vector.received as string | undefined
    return {
      name: vector.name as string,
      note: vector.note as string,
      wire: fromHex(vector.wire as string),
      expect: vector.expect as Expect,
      fieldIdentities: (vector.fieldIdentities as readonly string[] | undefined) ?? [],
      ...(received !== undefined ? { received: BigInt(received) } : {}),
    }
  })
}
