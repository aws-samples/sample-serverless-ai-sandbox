// kiro-classification: public
//
// The per-property tagging convention, enforced over the codec's TypeScript half.
//
// `sdk/typescript/test/harness/property-tags.test.ts` runs the same three checks over that package, and
// this file runs them here, because the collector is rooted at a directory and the TypeScript suite has
// two: the SDK package, and the halves of the protocol that live beside their Python counterparts. A
// property test in this directory is invisible to the package's scan, and an unenforced convention is a
// convention that lapses at the first hurried edit.
//
// The collector, the tag grammar and the property ceiling are the harness's, imported rather than
// restated — a second parser for the tag form would be a second opinion about what a well-formed tag is.
//
// The scan is deliberately not widened to all of `protocol/`. `protocol/generators/generators.test.ts`
// drives fast-check from unit tests that assert the *generators'* coverage rather than implementing a
// numbered property, and they carry no tag correctly. Collecting them here would report them as untagged
// property tests, which would be false.

import { describe, expect, it } from 'vitest'

import {
  collectPropertyTests,
  isWellFormed,
} from '../../sdk/typescript/test/harness/property-tags.js'

/** This directory: the TypeScript half of the Protocol_Codec. */
const CODEC_ROOT = new URL('.', import.meta.url).pathname

/** Properties 1 through 4 are the codec's, and the design gives it no others. */
const CLAIMED = [1, 2, 3, 4]

describe('the codec property tests', () => {
  const collected = collectPropertyTests(CODEC_ROOT)

  it('are found at all, so the checks below are not vacuous', () => {
    expect(collected.length).toBeGreaterThan(0)
  })

  it('each carry a well-formed tag', () => {
    const untagged = collected
      .filter((test) => !isWellFormed(test.tag))
      .map((test) => `${test.path}:${test.line}`)
    expect(untagged).toEqual([])
  })

  it('claim exactly the four properties the design assigns the codec, once each', () => {
    const numbers = collected
      .map((test) => test.tag?.number)
      .filter((number): number is number => number !== undefined)
      .sort((left, right) => left - right)
    expect(numbers).toEqual(CLAIMED)
  })
})
