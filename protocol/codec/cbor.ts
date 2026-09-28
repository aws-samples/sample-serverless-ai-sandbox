// kiro-classification: public
//
// Structural CBOR primitives, shared by the TypeScript Protocol_Codec and the adversarial
// generators. The TypeScript half of `protocol/_cbor.py`, item for item.
//
// Nothing here knows about messages, and nothing here is a codec on its own. Three capabilities:
// `encodeHead`, which writes an item head at a chosen width; `scan`, which locates every item in
// an encoding and accepts only RFC 8949's deterministic profile; and `replace`, which substitutes
// one located span for another.
//
// Both consumers need the same subset, from opposite directions. `profile.ts` builds its encoder
// on `encodeHead` at the shortest width and its decoder on `scan`, so the profile is enforced
// structurally in one place rather than restated. `protocol/generators/wire.ts` and
// `protocol/generators/faults.ts` take a canonical encoding apart with `scan` and put it back
// together wrongly, which is exactly what the codec must refuse to emit and must refuse to accept.
//
// Head arguments are `bigint`. A CBOR head carries up to 2^64 - 1, which no JavaScript number
// holds exactly, and the envelope's `v` field declares that full range precisely so that an
// unsupported version is expressible. Narrowing to `number` here would make a declared length of
// 2^60 read as an approximation, and the truncation check would then be comparing the wrong
// number against the buffer.
//
// `scan` deliberately does not check map key ordering. Ordering is a property of a whole map
// rather than of an item's head, and the codec's decoder checks it while materialising values,
// where it has the decoded keys to hand and can report which map offends.

/** The bytes handed to `scan` are not in the subset the Protocol_Codec emits. */
export class CborScanError extends Error {
  override readonly name = 'CborScanError'
}

/** The CBOR major types this protocol uses. */
export const Major = {
  UINT: 0,
  NEGINT: 1,
  BYTES: 2,
  TEXT: 3,
  ARRAY: 4,
  MAP: 5,
  SIMPLE: 7,
} as const

export type Major = (typeof Major)[keyof typeof Major]

const MAJORS: readonly Major[] = Object.values(Major)

/** Additional information 31, which marks an indefinite-length item. */
export const INDEFINITE_INFO = 31

/** The break code that closes an indefinite-length item. */
export const BREAK = 0xff

/**
 * Widths in bytes of the argument that follows the head byte. 0 means the argument is the head
 * byte's own additional information.
 */
const WIDTHS: readonly number[] = [0, 1, 2, 4, 8]

const INFO_FOR_WIDTH: ReadonlyMap<number, number> = new Map([
  [1, 24],
  [2, 25],
  [4, 26],
  [8, 27],
])

const WIDTH_FOR_INFO: ReadonlyMap<number, number> = new Map([
  [24, 1],
  [25, 2],
  [26, 4],
  [27, 8],
])

/** Simple values 20 and 21: false and true. No other simple value appears in this protocol. */
export const FALSE_SIMPLE = 20n
export const TRUE_SIMPLE = 21n

/**
 * The widest argument a CBOR head carries. Beyond it an encoder needs a bignum tag, and this
 * protocol declares none.
 */
export const MAX_HEAD_ARGUMENT = (1n << 64n) - 1n

/** The narrowest width the deterministic profile permits for `argument`. */
export function minimalWidth(argument: bigint): number {
  if (argument < 0n) {
    throw new RangeError(`a CBOR head argument is never negative, got ${argument}`)
  }
  for (const width of WIDTHS) {
    if (argument < (width === 0 ? 24n : 1n << BigInt(8 * width))) {
      return width
    }
  }
  throw new RangeError(`argument ${argument} does not fit in a CBOR head`)
}

/**
 * Every width above the minimal one that still holds `argument`.
 *
 * Each is a non-shortest encoding of the same value, which is the deterministic-profile violation
 * Property 2's second half quantifies over.
 */
export function widerWidths(argument: bigint): readonly number[] {
  const minimum = minimalWidth(argument)
  return WIDTHS.filter((width) => width > minimum)
}

/** Write an item head. An omitted `width` writes the shortest form the profile requires. */
export function encodeHead(major: Major, argument: bigint, width?: number): Uint8Array {
  const chosen = width ?? minimalWidth(argument)
  if (!WIDTHS.includes(chosen)) {
    throw new RangeError(`width ${chosen} is not a CBOR head width`)
  }
  if (chosen === 0) {
    if (argument >= 24n) {
      throw new RangeError(`argument ${argument} needs an explicit width`)
    }
    return new Uint8Array([(major << 5) | Number(argument)])
  }
  if (argument >= 1n << BigInt(8 * chosen)) {
    throw new RangeError(`argument ${argument} does not fit in ${chosen} bytes`)
  }
  const head = new Uint8Array(1 + chosen)
  const info = INFO_FOR_WIDTH.get(chosen)
  if (info === undefined) {
    throw new RangeError(`width ${chosen} has no additional information value`)
  }
  head[0] = (major << 5) | info
  for (let index = chosen; index >= 1; index -= 1) {
    head[index] = Number((argument >> BigInt(8 * (chosen - index))) & 0xffn)
  }
  return head
}

/** One CBOR item located inside an encoding, with its children if it has any. */
export interface Item {
  readonly major: Major
  /**
   * The head's decoded argument: the value for an unsigned integer, the byte length for a string,
   * the entry count for a container, the simple value for a simple.
   */
  readonly argument: bigint
  readonly start: number
  readonly headLength: number
  readonly end: number
  /** Array elements, or a map's keys and values interleaved in encoded order. */
  readonly children: readonly Item[]
}

export function payloadStart(item: Item): number {
  return item.start + item.headLength
}

export function isString(item: Item): boolean {
  return item.major === Major.BYTES || item.major === Major.TEXT
}

export function isContainer(item: Item): boolean {
  return item.major === Major.ARRAY || item.major === Major.MAP
}

/**
 * Whether the head carries a widenable argument.
 *
 * A simple value does not: `false` and `true` are the head byte and nothing else.
 */
export function hasArgument(item: Item): boolean {
  return item.major !== Major.SIMPLE
}

/** A map's key and value pairs, in encoded order. */
export function entries(item: Item): readonly [Item, Item][] {
  if (item.major !== Major.MAP) {
    throw new TypeError(`a major type ${item.major} item has no entries`)
  }
  const paired: [Item, Item][] = []
  for (let index = 0; index + 1 < item.children.length; index += 2) {
    const key = item.children[index]
    const value = item.children[index + 1]
    if (key === undefined || value === undefined) {
      throw new TypeError('a map item has an odd number of children')
    }
    paired.push([key, value])
  }
  return paired
}

/** This item and every item nested inside it, outermost first. */
export function* walk(item: Item): Generator<Item> {
  yield item
  for (const child of item.children) {
    yield* walk(child)
  }
}

interface Head {
  readonly major: Major
  readonly argument: bigint
  readonly headLength: number
}

function readHead(data: Uint8Array, offset: number): Head {
  if (offset >= data.length) {
    throw new CborScanError(`offset ${offset} is past the end of ${data.length} bytes`)
  }
  const head = data[offset]
  if (head === undefined) {
    throw new CborScanError(`offset ${offset} is past the end of ${data.length} bytes`)
  }
  const majorBits = head >> 5
  if (!MAJORS.includes(majorBits as Major)) {
    throw new CborScanError(`offset ${offset}: unsupported major type ${majorBits}`)
  }
  const major = majorBits as Major
  const info = head & 0x1f
  if (info < 24) {
    return { major, argument: BigInt(info), headLength: 1 }
  }
  if (info === INDEFINITE_INFO) {
    throw new CborScanError(`offset ${offset}: indefinite length is not canonical`)
  }
  const width = WIDTH_FOR_INFO.get(info)
  if (width === undefined) {
    throw new CborScanError(`offset ${offset}: reserved additional information ${info}`)
  }
  if (offset + 1 + width > data.length) {
    throw new CborScanError(`offset ${offset}: head truncated`)
  }
  let argument = 0n
  for (let index = 0; index < width; index += 1) {
    argument = (argument << 8n) | BigInt(data[offset + 1 + index] ?? 0)
  }
  if (minimalWidth(argument) !== width) {
    throw new CborScanError(`offset ${offset}: argument ${argument} is not shortest-form`)
  }
  return { major, argument, headLength: 1 + width }
}

function scanItem(data: Uint8Array, offset: number): Item {
  const { major, argument, headLength } = readHead(data, offset)
  let cursor = offset + headLength

  if (major === Major.SIMPLE) {
    if (argument !== FALSE_SIMPLE && argument !== TRUE_SIMPLE) {
      throw new CborScanError(`offset ${offset}: simple value ${argument} is not used here`)
    }
    return { major, argument, start: offset, headLength, end: cursor, children: [] }
  }

  if (major === Major.BYTES || major === Major.TEXT) {
    if (argument > BigInt(data.length - cursor)) {
      throw new CborScanError(`offset ${offset}: string payload truncated`)
    }
    const end = cursor + Number(argument)
    return { major, argument, start: offset, headLength, end, children: [] }
  }

  if (major === Major.ARRAY || major === Major.MAP) {
    const count = major === Major.MAP ? argument * 2n : argument
    // Each child is at least one byte, so a count beyond the remaining bytes is truncation and
    // there is no point allocating for it. The check also keeps `Number(count)` exact below.
    if (count > BigInt(data.length - cursor)) {
      throw new CborScanError(`offset ${offset}: container truncated`)
    }
    const children: Item[] = []
    for (let remaining = Number(count); remaining > 0; remaining -= 1) {
      const child = scanItem(data, cursor)
      children.push(child)
      cursor = child.end
    }
    return { major, argument, start: offset, headLength, end: cursor, children }
  }

  return { major, argument, start: offset, headLength, end: cursor, children: [] }
}

/**
 * Locate every item in one canonically encoded CBOR value.
 *
 * Raises `CborScanError` on trailing bytes, so a caller cannot silently address the first of two
 * concatenated items when it meant the whole encoding.
 */
export function scan(data: Uint8Array): Item {
  const root = scanItem(data, 0)
  if (root.end !== data.length) {
    throw new CborScanError(`${data.length - root.end} trailing byte(s) after the root item`)
  }
  return root
}

/**
 * Substitute `data[start:end]` with `replacement`.
 *
 * Safe for the rewrites here because a container's definite length counts entries rather than
 * bytes, and no byte string in this protocol carries an embedded CBOR encoding, so resizing a
 * nested item never invalidates an enclosing head.
 */
export function replace(
  data: Uint8Array,
  start: number,
  end: number,
  replacement: Uint8Array,
): Uint8Array {
  if (!(0 <= start && start <= end && end <= data.length)) {
    throw new RangeError(`span ${start}:${end} is outside ${data.length} bytes`)
  }
  return concat([data.subarray(0, start), replacement, data.subarray(end)])
}

/** Join byte sequences. Spelled once because every encoder branch below needs it. */
export function concat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0
  for (const part of parts) {
    total += part.length
  }
  const joined = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    joined.set(part, offset)
    offset += part.length
  }
  return joined
}

/**
 * Bytewise comparison, which is what RFC 8949 §4.2.1 orders map keys by.
 *
 * Negative, zero or positive as `left` sorts before, with, or after `right`. A prefix sorts
 * before the sequence that extends it, which is Python's `bytes` comparison and is what the two
 * implementations have to agree on for the vector corpus to mean anything.
 */
export function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const shared = Math.min(left.length, right.length)
  for (let index = 0; index < shared; index += 1) {
    const a = left[index] ?? 0
    const b = right[index] ?? 0
    if (a !== b) {
      return a < b ? -1 : 1
    }
  }
  return left.length - right.length
}
