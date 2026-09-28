// kiro-classification: public
//
// Structural equality for protocol values, which JavaScript does not have.
//
// Python needs nothing like this: `{1: b"\xff"} == {1: b"\xff"}` is true, and Property 1 can be
// written as `decode(encode(m)) == m`. JavaScript compares `Uint8Array` and `Map` by object identity,
// so the same statement is false for every message, and a round-trip property written with `toEqual`
// would be asserting something other than what it says.
//
// So equality is defined here, once, in the terms the wire uses:
//
// - A byte string is its bytes. Length and contents, not identity.
// - A map is its entries, keyed by value. Two maps are equal when the same set of key identities maps
//   to equal values, in any insertion order — CBOR fixes an order for the *encoding* and the decoder
//   restores entries in that order, but a caller who built the map in another order built the same
//   message.
// - An integer is its value *and* its representation. `1` and `1n` compare unequal, deliberately:
//   `protocol/generators/messages.ts` narrows a drawn integer to whichever of the two is exact, the
//   codec narrows a decoded one by the same rule, and a codec that returned `1n` for a drawn `1` would
//   hand its caller a value that fails `===` against what was sent. Treating the two as equal here
//   would hide exactly that.
//
// `valueIdentity` is the whole implementation and is exported because a failure message wants it: a
// diff of two rendered identities says which field differs, where a diff of two `Map` objects does not.

import type { Value } from './values.js'

/** A total, order-insensitive rendering of a value, equal exactly when the values are equal. */
export function valueIdentity(value: Value): string {
  if (value instanceof Uint8Array) {
    return `bytes:${[...value].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`
  }
  if (typeof value === 'string') {
    return `text:${JSON.stringify(value)}`
  }
  if (typeof value === 'boolean') {
    return `bool:${value}`
  }
  if (typeof value === 'number') {
    return `number:${value}`
  }
  if (typeof value === 'bigint') {
    return `bigint:${value}`
  }
  if (Array.isArray(value)) {
    return `list:[${(value as readonly Value[]).map(valueIdentity).join(',')}]`
  }
  if (value instanceof Map) {
    const rendered = [...(value as ReadonlyMap<Value, Value>)].map(
      ([key, item]) => `${valueIdentity(key)}=>${valueIdentity(item)}`,
    )
    // Sorted, so two maps built in different orders render the same. The encoder's ordering rule is
    // bytewise on encoded keys and is not this one; it does not need to be, because this establishes
    // equality of values and the encoder establishes the order of an encoding.
    return `map:{${rendered.sort().join(',')}}`
  }
  return `unencodable:${String(value)}`
}

/** Whether two protocol values are the same value. */
export function valuesEqual(left: Value, right: Value): boolean {
  return valueIdentity(left) === valueIdentity(right)
}
