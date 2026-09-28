// kiro-classification: public
//
// Loaded by Vitest before every test file. fast-check is pinned in package.json and is not
// reimplemented; the global configuration below fixes the iteration floor the design's
// Testing Strategy sets, and a property needing more states so on the test itself with
// { numRuns: CODEC_RUNS }.

import fc from 'fast-check'

import { MINIMUM_RUNS } from './harness/config.js'
import { denyOutboundNetwork } from './harness/network.js'

fc.configureGlobal({ numRuns: MINIMUM_RUNS })

denyOutboundNetwork()
