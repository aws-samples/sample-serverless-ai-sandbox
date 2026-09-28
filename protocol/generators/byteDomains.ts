// kiro-classification: public
//
// The adversarial byte domains the design's generators for Properties 3 and 5 name, in fast-check.
//
// The domains themselves are not declared here. `byte_domains.py` holds them, together with the
// reasoning for each class, and `export_byte_domains.py` writes `byte_domains.json` from it; this
// module reads that mirror. A hand-written second copy of the sequences would have needed a test
// asserting the two agree, and a check that two copies of a constant match is a check that the
// copy should not exist — a byte changed in one language and not the other would make a passing
// property in that language mean less than it claims.
//
// What does live here is the fast-check shape of the four branches, which has no Python
// counterpart to drift from: `fc.Arbitrary` is not `SearchStrategy`, and the weighting is
// expressed differently in each library even though the resulting distribution is the same.

import { readFileSync } from 'node:fs'

import fc from 'fast-check'

export const BYTE_DOMAINS_JSON_PATH = new URL('./byte_domains.json', import.meta.url)

interface RawByteDomains {
  readonly adversarialByteClasses: Readonly<Record<string, readonly string[]>>
  readonly cborLengthBoundaries: readonly number[]
  readonly maxOutputBytes: number
  readonly maxPathComponentBytes: number
  readonly pathSeparator: number
  readonly reservedPathComponents: readonly string[]
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

const raw = JSON.parse(readFileSync(BYTE_DOMAINS_JSON_PATH, 'utf8')) as RawByteDomains

/**
 * The named adversarial classes, keyed as in `byte_domains.py`: lone surrogates, truncated
 * multi-byte sequences, overlong encodings, high bytes and NUL runs. Grouped rather than
 * flattened so that a class dropped by a future edit is a visible omission.
 */
export const ADVERSARIAL_BYTE_CLASSES: ReadonlyMap<string, readonly Uint8Array[]> = new Map(
  Object.entries(raw.adversarialByteClasses).map(([name, sequences]) => [
    name,
    sequences.map(fromHex),
  ]),
)

export const ADVERSARIAL_BYTE_SEQUENCES: readonly Uint8Array[] = [
  ...ADVERSARIAL_BYTE_CLASSES.values(),
].flat()

/**
 * The sizes either side of each CBOR length-prefix width change: an argument below 24 is
 * immediate, then one, two and four additional bytes. A codec that emits a wider prefix than the
 * length needs still round-trips, but it violates the deterministic profile, and the fault is only
 * reachable at a crossing.
 */
export const CBOR_LENGTH_BOUNDARIES: readonly number[] = raw.cborLengthBoundaries

export const MAX_OUTPUT_BYTES = raw.maxOutputBytes

export const MAX_PATH_COMPONENT_BYTES = raw.maxPathComponentBytes

export const PATH_SEPARATOR = raw.pathSeparator

const NUL = 0x00

/**
 * `.` and `..` are byte sequences a filesystem holds, but they name an existing directory rather
 * than a new entry, so a generator that produced them would make "a written file reads back
 * byte-identically and appears in its directory listing" untestable rather than false.
 */
export const RESERVED_PATH_COMPONENTS: readonly Uint8Array[] =
  raw.reservedPathComponents.map(fromHex)

/** Enough arbitrary bytes to surround a spliced adversarial run without dominating it. */
const SPLICE_MARGIN = 64

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const joined = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    joined.set(part, offset)
    offset += part.length
  }
  return joined
}

function fitting(sequences: readonly Uint8Array[], maxSize: number): Uint8Array[] {
  const fitted = sequences.filter((sequence) => sequence.length <= maxSize)
  if (fitted.length === 0) {
    throw new Error(`no adversarial sequence fits in ${maxSize} bytes`)
  }
  return fitted
}

function exactLength(size: number): fc.Arbitrary<Uint8Array> {
  return fc.uint8Array({ minLength: size, maxLength: size })
}

/** Byte sequences whose length sits on a CBOR length-prefix width boundary. */
function boundaryLengths(maxSize: number): fc.Arbitrary<Uint8Array> {
  const boundaries = CBOR_LENGTH_BOUNDARIES.filter((size) => size <= maxSize)
  return fc.constantFrom(...boundaries).chain(exactLength)
}

/**
 * Arbitrary bytes with one adversarial run embedded at a drawn offset.
 *
 * The mixed case rather than the pure one: real process output is mostly ordinary text with an
 * invalid sequence somewhere inside it, and a codec that transcodes only when the whole payload is
 * invalid would pass against the pure cases alone.
 */
function spliced(maxSize: number): fc.Arbitrary<Uint8Array> {
  const margin = Math.min(SPLICE_MARGIN, maxSize)
  return fc
    .tuple(
      fc.uint8Array({ maxLength: margin }),
      fc.constantFrom(...fitting(ADVERSARIAL_BYTE_SEQUENCES, maxSize)),
      fc.uint8Array({ maxLength: margin }),
    )
    .map(([prefix, run, suffix]) => concat([prefix, run, suffix]).subarray(0, maxSize))
}

/**
 * Byte sequences a process may write, adversarial cases at raised weight (R8.9).
 *
 * Four branches, drawn with roughly equal weight, so three quarters of the domain is adversarial
 * rather than the vanishing fraction an unweighted `uint8Array()` would give: arbitrary bytes
 * including empty, the named adversarial sequences, sequences whose length crosses a CBOR
 * length-prefix width boundary, and arbitrary bytes with an adversarial run spliced in.
 */
export function outputBytes(maxSize: number = MAX_OUTPUT_BYTES): fc.Arbitrary<Uint8Array> {
  const shortest = Math.min(...ADVERSARIAL_BYTE_SEQUENCES.map((sequence) => sequence.length))
  if (maxSize < shortest) {
    throw new Error(`maxSize ${maxSize} is too small to carry any adversarial case`)
  }
  return fc.oneof(
    fc.uint8Array({ maxLength: Math.min(maxSize, 256) }),
    fc.constantFrom(...fitting(ADVERSARIAL_BYTE_SEQUENCES, maxSize)),
    boundaryLengths(maxSize),
    spliced(maxSize),
  )
}

/** Drop the two bytes a path component cannot contain, keeping the rest verbatim. */
function scrub(data: Uint8Array): Uint8Array {
  return data.filter((byte) => byte !== NUL && byte !== PATH_SEPARATOR)
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}

function isUsableComponent(component: Uint8Array): boolean {
  return (
    component.length > 0 &&
    !RESERVED_PATH_COMPONENTS.some((reserved) => sameBytes(component, reserved))
  )
}

/**
 * One filesystem name: arbitrary bytes excluding NUL and the path separator.
 *
 * Drawn from the same adversarial domain as process output, so filenames that are not valid UTF-8
 * are covered — a filename on a Linux filesystem is a byte sequence, and a generator restricted to
 * text would never reach the names the Sandbox can create. NUL and `/` are excluded because the
 * kernel cannot represent them inside a component, not as a simplification.
 */
export function pathComponent(
  maxSize: number = MAX_PATH_COMPONENT_BYTES,
): fc.Arbitrary<Uint8Array> {
  return fc
    .oneof(
      fc.uint8Array({ minLength: 1, maxLength: maxSize }),
      fc.constantFrom(...fitting(ADVERSARIAL_BYTE_SEQUENCES, maxSize)),
      spliced(maxSize),
    )
    .map(scrub)
    .filter(isUsableComponent)
}
