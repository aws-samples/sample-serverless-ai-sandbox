// kiro-classification: public
//
// Iteration counts and paths shared by the TypeScript half of the offline harness.
// The numbers come from the design's Testing Strategy: every property test runs a minimum
// of 100 iterations, and the codec properties (Properties 1 through 4) run 1,000.

import { fileURLToPath } from 'node:url'

export const MINIMUM_RUNS = 100

export const CODEC_RUNS = 1_000

/** The root of this package, which is the root of the TypeScript half of the suite. */
export const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url))
