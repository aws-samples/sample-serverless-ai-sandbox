// kiro-classification: public
//
// The TypeScript view of the schema catalogue (R8.1).
//
// `messages.yaml` is the schema source and `protocol/schema.py` is its only reader. This module
// reads `catalogue.json`, the mirror that reader generates, so there is one parse of the YAML
// document in the repository and one validated shape flowing out of it. See
// `export_catalogue.py` for why the mirror exists rather than a second YAML parser, and for how
// a stale mirror is caught.
//
// Integer range bounds arrive as decimal strings and are read as `bigint`, because the
// envelope's `v` admits the full CBOR unsigned range and a JSON number cannot carry it.

import { readFileSync } from 'node:fs'

export const CATALOGUE_JSON_PATH = new URL('./catalogue.json', import.meta.url)

export type TypeKind =
  | 'uint'
  | 'int'
  | 'bool'
  | 'text'
  | 'bytes'
  | 'list'
  | 'map'
  | 'struct'

/** What a byte-typed field carries, and why it must be byte-typed (R8.9). */
export type Carries = 'output' | 'name'

export type Direction =
  | 'client-to-runtime'
  | 'runtime-to-client'
  | 'orchestrator-to-runtime'
  | 'both'

/** The inclusive interval an integer field admits. */
export interface IntRange {
  readonly min: bigint
  readonly max: bigint
}

export interface TypeSpec {
  readonly kind: TypeKind
  readonly range?: IntRange
  readonly enum?: readonly string[]
  readonly carries?: Carries
  readonly items?: TypeSpec
  readonly keys?: TypeSpec
  readonly values?: TypeSpec
  readonly fields: readonly Field[]
}

export interface Field {
  readonly key: number
  readonly name: string
  readonly spec: TypeSpec
  readonly optional: boolean
}

export interface MessageType {
  readonly t: string
  readonly direction: Direction
  readonly requirements: readonly string[]
  readonly body: readonly Field[]
}

export interface Catalogue {
  readonly schemaVersion: number
  readonly protocolVersion: number
  readonly supportedMin: number
  readonly supportedMax: number
  readonly envelope: readonly Field[]
  readonly messages: ReadonlyMap<string, MessageType>
}

/** The four envelope keys, fixed by the design's message shape table. */
export const ENVELOPE_KEY_VERSION = 1
export const ENVELOPE_KEY_TYPE = 2
export const ENVELOPE_KEY_ID = 3
export const ENVELOPE_KEY_BODY = 4

interface RawRange {
  readonly min: string
  readonly max: string
}

interface RawSpec {
  readonly type: TypeKind
  readonly range?: RawRange
  readonly enum?: readonly string[]
  readonly carries?: Carries
  readonly items?: RawSpec
  readonly keys?: RawSpec
  readonly values?: RawSpec
  readonly fields?: readonly RawField[]
}

interface RawField extends RawSpec {
  readonly key: number
  readonly name: string
  readonly optional?: boolean
}

interface RawCatalogue {
  readonly schemaVersion: number
  readonly protocol: {
    readonly version: number
    readonly supportedMin: number
    readonly supportedMax: number
  }
  readonly envelope: { readonly fields: readonly RawField[] }
  readonly messages: readonly {
    readonly t: string
    readonly direction: Direction
    readonly requirements: readonly string[]
    readonly body: readonly RawField[]
  }[]
}

function readSpec(raw: RawSpec): TypeSpec {
  const spec: {
    kind: TypeKind
    range?: IntRange
    enum?: readonly string[]
    carries?: Carries
    items?: TypeSpec
    keys?: TypeSpec
    values?: TypeSpec
    fields: readonly Field[]
  } = { kind: raw.type, fields: raw.fields?.map(readField) ?? [] }
  if (raw.range !== undefined) {
    spec.range = { min: BigInt(raw.range.min), max: BigInt(raw.range.max) }
  }
  if (raw.enum !== undefined) {
    spec.enum = raw.enum
  }
  if (raw.carries !== undefined) {
    spec.carries = raw.carries
  }
  if (raw.items !== undefined) {
    spec.items = readSpec(raw.items)
  }
  if (raw.keys !== undefined) {
    spec.keys = readSpec(raw.keys)
  }
  if (raw.values !== undefined) {
    spec.values = readSpec(raw.values)
  }
  return spec
}

function readField(raw: RawField): Field {
  return {
    key: raw.key,
    name: raw.name,
    spec: readSpec(raw),
    optional: raw.optional === true,
  }
}

let cached: Catalogue | undefined

/**
 * Read, parse and cache the catalogue mirror.
 *
 * Cached because the catalogue is immutable for the life of the process and the generators
 * reach for it once per drawn example.
 */
export function loadCatalogue(): Catalogue {
  if (cached !== undefined) {
    return cached
  }
  const raw = JSON.parse(readFileSync(CATALOGUE_JSON_PATH, 'utf8')) as RawCatalogue
  const messages = new Map<string, MessageType>()
  for (const message of raw.messages) {
    messages.set(message.t, {
      t: message.t,
      direction: message.direction,
      requirements: message.requirements,
      body: message.body.map(readField),
    })
  }
  cached = {
    schemaVersion: raw.schemaVersion,
    protocolVersion: raw.protocol.version,
    supportedMin: raw.protocol.supportedMin,
    supportedMax: raw.protocol.supportedMax,
    envelope: raw.envelope.fields.map(readField),
    messages,
  }
  return cached
}

/** Whether `version` is admissible in Phase 1 of the decode algorithm (R8.7). */
export function supports(catalogue: Catalogue, version: number | bigint): boolean {
  const value = BigInt(version)
  return BigInt(catalogue.supportedMin) <= value && value <= BigInt(catalogue.supportedMax)
}

export function messageTypes(catalogue: Catalogue): readonly string[] {
  return [...catalogue.messages.keys()]
}

export function fieldByName(message: MessageType, name: string): Field {
  const field = message.body.find((candidate) => candidate.name === name)
  if (field === undefined) {
    throw new Error(`${message.t} has no body field named ${name}`)
  }
  return field
}

/** This spec and every spec nested inside it, outermost first. */
export function* walkSpec(spec: TypeSpec): Generator<TypeSpec> {
  yield spec
  for (const nested of [spec.items, spec.keys, spec.values]) {
    if (nested !== undefined) {
      yield* walkSpec(nested)
    }
  }
  for (const field of spec.fields) {
    yield* walkSpec(field.spec)
  }
}

/**
 * Every annotated spec, with the message and the field it sits under.
 *
 * The generators and the byte-typing assertion both quantify over this, so a message type added
 * with a text-typed output field is a failure rather than an omission.
 */
export function* byteTypedFields(
  catalogue: Catalogue,
): Generator<{ t: string; field: Field; spec: TypeSpec }> {
  for (const message of catalogue.messages.values()) {
    for (const field of message.body) {
      for (const spec of walkSpec(field.spec)) {
        if (spec.carries !== undefined) {
          yield { t: message.t, field, spec }
        }
      }
    }
  }
}
