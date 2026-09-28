// kiro-classification: public

import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // The shared generators live with the protocol rather than inside this package, because a
    // schema change has to update them rather than silently narrow them. This package holds the
    // only `node_modules` in the repository, so it is also the only place their tests can run,
    // and they are reached by path rather than by being moved. They stay outside `tsconfig.json`'s
    // `include`: `rootDir` is this directory, and a build input above it fails with TS6059.
    // `protocol/generators/tsconfig.json` typechecks them instead.
    include: [
      'test/**/*.test.ts',
      'src/**/*.test.ts',
      '../../protocol/generators/**/*.test.ts',
      // The TypeScript half of the Protocol_Codec, beside the Python half it is specified by, for
      // the same reason the generators sit where they do. `protocol/codec/tsconfig.json`
      // typechecks it.
      '../../protocol/codec/**/*.test.ts',
      // The cross-implementation vector corpus. Its Python half generates the vectors and its
      // TypeScript half decodes them, so the comparison only means anything if both halves run in
      // the offline suite. `protocol/vectors/tsconfig.json` typechecks it.
      '../../protocol/vectors/**/*.test.ts',
    ],
    // The harness is loaded before every test file, so no test can opt out of the
    // outbound network denial (R15.9, R18.17).
    setupFiles: ['./test/setup.ts'],
    environment: 'node',
    // No test in the offline suite is a long-running one; a hang is a failure.
    testTimeout: 30_000,
  },
})
