// kiro-classification: public
//
// Validating a value against the message catalogue, field by field.
//
// This is the *schema* half of the codec, and it is deliberately separate from the *profile* half:
// `profile.ts` decides whether the bytes are one deterministic-profile CBOR value, and this module
// decides whether that value is a message `protocol/messages.yaml` declares. The two fail
// differently and a caller cares which — a peer sending non-canonical bytes has a broken encoder, a
// peer sending a well-encoded but wrongly shaped map has a broken schema assumption.
//
// Everything is read out of the catalogue rather than restated. The envelope's four keys, every body
// field, every declared range and every closed enum come from the catalogue, so a message type added
// to `messages.yaml` is validated with no edit here, and a field whose type changes is checked
// against the new type or fails loudly. A validator that listed the fields it knew about would go
// quietly out of date, and a round-trip property over a field it had never heard of would still pass.
//
// The field identities are the Python half's, spelling for spelling — `v`, `b.argv`,
// `b.entries[2].kind` — because `protocol/generators/faults.py` fixes the set a decode error may use
// and the vector corpus compares the two codecs' reports. This is the one part of the port where a
// difference in wording is a difference in behaviour.
//
// The version field is checked for *type* here and not for admissibility. Admissibility is a separate
// question that the decode algorithm asks earlier, before any other field is inspected, so that a
// representation carrying both an unsupported version and a schema violation reports the version
// (R8.8). Answering it here as well would put the ordering in two places and let them disagree.

import {
  type Catalogue,
  ENVELOPE_KEY_BODY,
  ENVELOPE_KEY_TYPE,
  type Field,
  loadCatalogue,
  type TypeSpec,
} from './catalogue.js'
import { SchemaViolation } from './errors.js'
import type { Message, Value } from './values.js'

/**
 * The identity a violation reports when there is no field to name, because the value is not a map at
 * all. Unreachable through the decode algorithm, whose first phase reads a definite map head and
 * fails before this module is asked anything; reachable by calling `validate` directly.
 */
export const ROOT_IDENTITY = 'message'

/**
 * Check `value` against the catalogue and return it as a message.
 *
 * Returns the envelope keyed by its integer keys, with nothing rewritten: validation establishes that
 * the value already is a message, and rebuilding its contents would invite the rebuilt form and the
 * validated form to differ. Throws `SchemaViolation` naming the first offending field.
 */
export function validate(value: Value | Message, catalogue: Catalogue = loadCatalogue()): Message {
  if (!(value instanceof Map)) {
    throw new SchemaViolation(ROOT_IDENTITY, `a message is a map, got ${renderType(value)}`)
  }
  const map = value as ReadonlyMap<Value, Value>

  const declared = new Map<number, Field>(catalogue.envelope.map((field) => [field.key, field]))
  for (const key of map.keys()) {
    if (!isInteger(key) || !declared.has(Number(key))) {
      throw new SchemaViolation(renderKey(key), 'the envelope declares no such key')
    }
  }
  for (const field of catalogue.envelope) {
    if (!map.has(field.key)) {
      throw new SchemaViolation(field.name, 'required envelope key is absent')
    }
  }

  const envelope = new Map<number, Value>()
  for (const [key, item] of map) {
    if (isInteger(key)) {
      envelope.set(Number(key), item)
    }
  }
  for (const field of catalogue.envelope) {
    if (field.key === ENVELOPE_KEY_BODY) {
      continue
    }
    check(envelope.get(field.key) as Value, field.spec, field.name)
  }

  // `check` has already established that the discriminator is a text string.
  const discriminator = envelope.get(ENVELOPE_KEY_TYPE)
  const messageType =
    typeof discriminator === 'string' ? catalogue.messages.get(discriminator) : undefined
  const typeField = declared.get(ENVELOPE_KEY_TYPE)
  if (messageType === undefined || typeField === undefined) {
    throw new SchemaViolation(
      typeField?.name ?? String(ENVELOPE_KEY_TYPE),
      `the catalogue declares no message type ${renderValue(discriminator)}`,
    )
  }

  const bodyField = declared.get(ENVELOPE_KEY_BODY)
  if (bodyField === undefined) {
    throw new SchemaViolation(ROOT_IDENTITY, 'the envelope declares no body key')
  }
  const body = envelope.get(ENVELOPE_KEY_BODY)
  if (!(body instanceof Map)) {
    throw new SchemaViolation(bodyField.name, `a body is a map, got ${renderType(body)}`)
  }
  checkFields(body as ReadonlyMap<Value, Value>, messageType.body, bodyField.name)

  return envelope
}

/**
 * The catalogue's name for one envelope key.
 *
 * The identity a violation reports is the schema's name for the field, so it is read out of the
 * catalogue rather than written down here as a literal.
 */
export function envelopeFieldName(catalogue: Catalogue, key: number): string {
  const field = catalogue.envelope.find((candidate) => candidate.key === key)
  if (field === undefined) {
    throw new RangeError(`the envelope declares no key ${key}`)
  }
  return field.name
}

/** Check a body or a struct against its declared field block. */
function checkFields(
  mapping: ReadonlyMap<Value, Value>,
  fields: readonly Field[],
  prefix: string,
): void {
  const declared = new Map<number, Field>(fields.map((field) => [field.key, field]))
  for (const key of mapping.keys()) {
    if (!isInteger(key) || !declared.has(Number(key))) {
      throw new SchemaViolation(`${prefix}.${renderKey(key)}`, 'the schema declares no such field')
    }
  }
  for (const field of fields) {
    const path = `${prefix}.${field.name}`
    if (!mapping.has(field.key)) {
      if (field.optional) {
        continue
      }
      throw new SchemaViolation(path, 'required field is absent')
    }
    check(mapping.get(field.key) as Value, field.spec, path)
  }
}

/** Check one value against one declared type, recursing into containers. */
function check(value: Value, spec: TypeSpec, path: string): void {
  switch (spec.kind) {
    case 'uint':
    case 'int':
      checkInteger(value, spec, path)
      return
    case 'bool':
      if (typeof value !== 'boolean') {
        throw wrongType(path, 'a boolean', value)
      }
      return
    case 'text':
      checkText(value, spec, path)
      return
    case 'bytes':
      if (!(value instanceof Uint8Array)) {
        throw wrongType(path, 'a byte string', value)
      }
      return
    case 'list':
      checkList(value, spec, path)
      return
    case 'map':
      checkMap(value, spec, path)
      return
    case 'struct':
      if (!(value instanceof Map)) {
        throw wrongType(path, 'a struct', value)
      }
      checkFields(value as ReadonlyMap<Value, Value>, spec.fields, path)
      return
  }
}

function checkInteger(value: Value, spec: TypeSpec, path: string): void {
  if (!isInteger(value)) {
    throw wrongType(path, 'an integer', value)
  }
  if (spec.range === undefined) {
    throw new Error(`${path}: a ${spec.kind} field declares no range`)
  }
  const asBig = BigInt(value)
  if (asBig < spec.range.min || asBig > spec.range.max) {
    throw new SchemaViolation(
      path,
      `${value} is outside the declared range [${spec.range.min}, ${spec.range.max}]`,
    )
  }
}

function checkText(value: Value, spec: TypeSpec, path: string): void {
  if (typeof value !== 'string') {
    throw wrongType(path, 'a text string', value)
  }
  if (spec.enum !== undefined && !spec.enum.includes(value)) {
    throw new SchemaViolation(path, `${renderValue(value)} is not one of ${spec.enum.join(', ')}`)
  }
  const surrogate = unpairedSurrogateAt(value)
  if (surrogate !== null) {
    // An unpaired surrogate has no UTF-8 encoding, so it is not a value major type 3 can carry, and
    // refusing it here names the field rather than failing anonymously in the encoder.
    throw new SchemaViolation(
      path,
      `a text string must be UTF-8 encodable: unpaired surrogate at index ${surrogate}`,
    )
  }
}

function checkList(value: Value, spec: TypeSpec, path: string): void {
  if (!Array.isArray(value)) {
    throw wrongType(path, 'a list', value)
  }
  if (spec.items === undefined) {
    throw new Error(`${path}: a list declares no item type`)
  }
  const items = value as readonly Value[]
  for (let index = 0; index < items.length; index += 1) {
    check(items[index] as Value, spec.items, `${path}[${index}]`)
  }
}

function checkMap(value: Value, spec: TypeSpec, path: string): void {
  if (!(value instanceof Map)) {
    throw wrongType(path, 'a map', value)
  }
  if (spec.keys === undefined || spec.values === undefined) {
    // The envelope's `b` declares neither, because its schema is selected by `t`; `validate`
    // dispatches that one on the message type instead of reaching here.
    return
  }
  let index = 0
  for (const [key, item] of value as ReadonlyMap<Value, Value>) {
    check(key, spec.keys, `${path}[${index}].key`)
    check(item, spec.values, `${path}[${index}].value`)
    index += 1
  }
}

function wrongType(path: string, expected: string, value: Value): SchemaViolation {
  return new SchemaViolation(path, `expected ${expected}, got ${renderType(value)}`)
}

/**
 * Whether `value` is an integer rather than a boolean.
 *
 * Both `number` and `bigint` count, because the catalogue's ranges span more than a number holds and
 * the codec decodes to whichever is exact. A non-integral `number` does not: 1.5 is a CBOR float,
 * which this protocol does not declare.
 */
function isInteger(value: unknown): value is number | bigint {
  return typeof value === 'bigint' || (typeof value === 'number' && Number.isInteger(value))
}

/** The index of the first unpaired surrogate code unit, or null if the string is encodable. */
function unpairedSurrogateAt(value: string): number | null {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index)
    if (unit < 0xd800 || unit > 0xdfff) {
      continue
    }
    const low = index + 1 < value.length ? value.charCodeAt(index + 1) : Number.NaN
    if (unit <= 0xdbff && low >= 0xdc00 && low <= 0xdfff) {
      index += 1
      continue
    }
    return index
  }
  return null
}

/** How an undeclared key is named. An integer key is named by its number. */
function renderKey(key: Value): string {
  return isInteger(key) ? String(key) : renderValue(key)
}

function renderValue(value: Value | undefined): string {
  return typeof value === 'string' ? `'${value}'` : String(value)
}

function renderType(value: Value | undefined): string {
  if (typeof value === 'boolean') {
    return 'a boolean'
  }
  if (typeof value === 'bigint' || typeof value === 'number') {
    return 'an integer'
  }
  if (typeof value === 'string') {
    return 'a text string'
  }
  if (value instanceof Uint8Array) {
    return 'a byte string'
  }
  if (Array.isArray(value)) {
    return 'a list'
  }
  if (value instanceof Map) {
    return 'a map'
  }
  return `a ${typeof value}`
}
