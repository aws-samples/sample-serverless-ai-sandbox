// kiro-classification: public
//
// The value space a Sandbox_Protocol message inhabits, in TypeScript.
//
// One definition, imported by the codec, the generators and the vector corpus. The alternative —
// each of them spelling the same union out — type-checks identically because the alias is
// structural, and drifts silently the first time the catalogue admits something new.
//
// The union is closed deliberately. It is exactly what the catalogue's type vocabulary can
// declare, so a value outside it is a value no message can carry: no floats, no null, no tags, no
// bignums. `encodeValue` refuses anything else rather than inventing an encoding for it.
//
// It is the same union `protocol/generators/messages.ts` declares, and deliberately assignable
// both ways, so a drawn message is a codec input without a cast. Two spellings appear where
// Python needs one:
//
// - `number | bigint` for an integer. The catalogue declares ranges up to 2^64 - 1, which no
//   JavaScript number holds, and small signed ranges an ordinary reader sees as numbers. The
//   codec decodes to whichever of the two is exact for the value, which is what
//   `protocol/generators/messages.ts` narrows a drawn integer to, so a decoded message compares
//   equal to the drawn one by value.
// - `readonly` on the containers, because the generators hand over frozen shapes and the codec
//   only ever reads them.

export type Value =
  | number
  | bigint
  | boolean
  | string
  | Uint8Array
  | readonly Value[]
  | ReadonlyMap<Value, Value>

/**
 * One message: the definite-length four-key envelope map of the design's message shape table,
 * keyed by the small unsigned integers the catalogue names. A message *is* that map; there is no
 * wrapper class, because a second representation would be one more thing to keep in step with the
 * catalogue for no gain.
 */
export type Message = ReadonlyMap<number, Value>

/** The largest integer a JavaScript number holds exactly, as the comparison wants it. */
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER)

/**
 * A decoded integer, as `number` when that is exact and `bigint` when it is not.
 *
 * The same rule `protocol/generators/messages.ts` applies when it narrows a drawn integer, and it
 * has to be the same rule: a codec that decoded `1n` where the generator drew `1` would fail
 * Property 1 on the representation of the value rather than on the protocol.
 */
export function narrowInteger(value: bigint): number | bigint {
  return value >= -MAX_SAFE && value <= MAX_SAFE ? Number(value) : value
}
