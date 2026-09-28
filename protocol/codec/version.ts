// kiro-classification: public
//
// Phases 0 and 1 of the decode algorithm: read the protocol version, then admit it.
//
// These two phases exist to give R8.8 a mechanism rather than a convention. The criterion requires
// the version to be evaluated *before any other field is validated*, so that a representation
// carrying both an unsupported version and a schema violation reports the version. An implementation
// that validated the whole message and then looked at the version would satisfy R8.6 and R8.7 and
// fail R8.8 in exactly the case that matters, and no amount of care in the error messages would fix
// it. The order is therefore structural: `readVersion` and `requireSupported` run to completion
// before `validate` is asked anything at all.
//
// What makes that possible is the wire format rather than this module. CBOR is self-describing, and
// under the deterministic profile map entries ascend by encoded key bytes, so envelope key 1 is
// always the first entry. The version is readable from the front of the representation without
// interpreting any other field.
//
// Two shapes, and they are not interchangeable:
//
// - Phase 0 fails when the version is *unreadable* — no map, no first entry, a first entry keyed
//   something other than 1, or a version that is not an unsigned integer. That is a decode error
//   naming the version key (R8.6), and deliberately not a version error, because no version was
//   received and a version error reporting one would be fiction.
// - Phase 1 fails when the version reads cleanly and is outside the supported range. That is a
//   version error carrying the received version and both bounds (R8.7).
//
// ## Why Phase 0 scans the whole representation
//
// The design's pseudocode reads the map head and the first entry and stops. This implementation
// calls `scan` first, which walks every item's head. The reason is that the narrower reading admits
// a representation that is not one complete CBOR item — three bytes of a truncated envelope carry a
// perfectly readable `a4 01 01` — and would then report a *version* for it, or admit its version and
// leave the truncation to be reported later as something else. Whether a version was received at all
// is not answerable from the first entry alone, and "the version was readable" is a claim about the
// representation, not about its first three bytes.
//
// Scanning does not weaken R8.8. `scan` locates items and rejects the profile violations visible in a
// head — indefinite lengths, non-shortest arguments, reserved additional information, truncation,
// trailing bytes. It decodes nothing, consults no schema and cannot tell a valid field from an invalid
// one, so no field is *validated* before Phase 1 runs. The cost is that Phase 2's `decodeValue` scans
// a second time; that is one walk over the item heads, string payloads are skipped rather than read,
// and paying it keeps `decodeValue` a function of the bytes alone instead of one that trusts a
// caller-supplied parse.

import {
  CborScanError,
  type Item,
  Major,
  entries as mapEntries,
  scan,
} from './cbor.js'
import { type Catalogue, ENVELOPE_KEY_VERSION, loadCatalogue, supports } from './catalogue.js'
import { DecodeError, VersionError } from './errors.js'

/**
 * The field identity a Phase 0 decode error reports: the version key's number as text, which is the
 * identity the design's decode algorithm fixes for this case. Phase 2 names the same key `v`, because
 * there it has a decoded envelope and the catalogue's name for the field; here it has neither, and the
 * key's position on the wire is the only identity that is certainly true.
 */
export const VERSION_IDENTITY = String(ENVELOPE_KEY_VERSION)

/**
 * Phase 0: extract the protocol version, and nothing else, from `wire`.
 *
 * Throws `DecodeError` naming `VERSION_IDENTITY` if the version cannot be read. The version is a
 * `bigint` because the envelope declares the full CBOR unsigned range for it, and Phase 1 has to be
 * able to report back exactly what arrived.
 */
export function readVersion(wire: Uint8Array): bigint {
  let root: Item
  try {
    root = scan(wire)
  } catch (error) {
    if (!(error instanceof CborScanError)) {
      throw error
    }
    throw unreadable(
      `the representation is not one deterministic-profile CBOR item: ${error.message}`,
    )
  }

  if (root.major !== Major.MAP) {
    throw unreadable(`a message is a map, got ${major(root)}`)
  }
  if (root.argument === 0n) {
    throw unreadable('the envelope carries no entries')
  }

  const first = mapEntries(root)[0]
  if (first === undefined) {
    throw unreadable('the envelope carries no entries')
  }
  const [keyItem, valueItem] = first
  if (keyItem.major !== Major.UINT || keyItem.argument !== BigInt(ENVELOPE_KEY_VERSION)) {
    throw unreadable(
      `the protocol version must be the first map key, and the first key is ${renderKey(keyItem)}`,
    )
  }
  if (valueItem.major !== Major.UINT) {
    throw unreadable(`the protocol version is an unsigned integer, got ${major(valueItem)}`)
  }
  return valueItem.argument
}

/**
 * Phase 1: admit `version`, or throw `VersionError` reporting it and both bounds (R8.7).
 *
 * Runs before any other field is inspected, which is R8.8.
 */
export function requireSupported(version: bigint, catalogue: Catalogue = loadCatalogue()): void {
  if (!supports(catalogue, version)) {
    throw new VersionError(
      version,
      BigInt(catalogue.supportedMin),
      BigInt(catalogue.supportedMax),
    )
  }
}

function unreadable(detail: string): DecodeError {
  return new DecodeError(VERSION_IDENTITY, `protocol version unreadable: ${detail}`)
}

/**
 * How a structurally wrong item is described: by major type, not by value.
 *
 * Phase 0 has located items and decoded none of them, so the major type is all it honestly knows
 * about an item whose type is already wrong.
 */
function major(item: Item): string {
  return `CBOR major type ${item.major}`
}

/**
 * The first map key, named by its number where it has one.
 *
 * An unsigned integer is the case where Phase 0 can say more than the major type, because such a
 * key's value *is* its head argument. Saying which key came first is what turns this failure from
 * "the bytes are wrong" into something a peer can fix.
 */
function renderKey(item: Item): string {
  return item.major === Major.UINT ? `key ${item.argument}` : `of ${major(item)}`
}
