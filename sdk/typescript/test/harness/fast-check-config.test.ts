// kiro-classification: public
//
// The iteration counts the design's Testing Strategy fixes are asserted, not documented.

import fc from 'fast-check'
import { describe, expect, it } from 'vitest'

import { CODEC_RUNS, MINIMUM_RUNS } from './config.js'

describe('fast-check global configuration', () => {
  it('meets the iteration floor', () => {
    expect(fc.readConfigureGlobal().numRuns ?? 0).toBeGreaterThanOrEqual(MINIMUM_RUNS)
  })

  it('carries the design values', () => {
    expect(MINIMUM_RUNS).toBe(100)
    expect(CODEC_RUNS).toBe(1_000)
  })
})
