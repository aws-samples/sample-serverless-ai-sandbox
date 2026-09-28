// kiro-classification: public
//
// The per-property tagging comment form is enforced, so a tag cannot quietly go missing.

import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

import { PACKAGE_ROOT } from './config.js'
import {
  collectPropertyTests,
  FEATURE_NAME,
  isWellFormed,
  parsePropertyTag,
  PROPERTY_COUNT,
} from './property-tags.js'

const WELL_FORMED_TAG = [
  `// Feature: ${FEATURE_NAME}, Property 3: For any byte sequence, including sequences`,
  '// that are not valid UTF-8, carrying that sequence as process output through one',
  '// serialise and deserialise cycle yields a byte sequence identical to the input.',
]

describe('parsing', () => {
  it('parses the design example', () => {
    const tag = parsePropertyTag(WELL_FORMED_TAG)
    expect(tag).not.toBeNull()
    expect(tag?.feature).toBe(FEATURE_NAME)
    expect(tag?.number).toBe(3)
    expect(tag?.summary).toMatch(/^For any byte sequence/)
    expect(tag?.summary).toMatch(/identical to the input\.$/)
    expect(isWellFormed(tag)).toBe(true)
  })

  it('parses a single-line tag', () => {
    const tag = parsePropertyTag([`// Feature: ${FEATURE_NAME}, Property 44: A one-line summary.`])
    expect(tag?.number).toBe(44)
    expect(tag?.summary).toBe('A one-line summary.')
  })

  it.each([
    '// Property 3: the feature name is missing',
    `// Feature: ${FEATURE_NAME} Property 3: the comma is missing`,
    `// Feature: ${FEATURE_NAME}, Property: the number is missing`,
    `// Feature: ${FEATURE_NAME}, Property 3 the colon is missing`,
    `// feature: ${FEATURE_NAME}, Property 3: the label is lowercased`,
    `// Feature: ${FEATURE_NAME}, Property 3:`,
    '// an ordinary comment',
  ])('rejects %s', (line) => {
    expect(parsePropertyTag([line])).toBeNull()
  })

  it('rejects a foreign feature and an out-of-range number', () => {
    expect(isWellFormed(parsePropertyTag(['// Feature: other-feature, Property 3: summary.']))).toBe(
      false,
    )
    expect(
      isWellFormed(
        parsePropertyTag([`// Feature: ${FEATURE_NAME}, Property ${PROPERTY_COUNT + 1}: summary.`]),
      ),
    ).toBe(false)
  })
})

// Assembled rather than written literally: this file is itself scanned by the suite-wide
// checks below, and a literal call marker inside a fixture would be collected as a property
// test of this file.
const ASSERT_CALL = `${['fc', 'assert'].join('.')}(`

describe('collection', () => {
  it('finds the tag above a fast-check driven test', () => {
    const root = mkdtempSync(join(tmpdir(), 'offline-harness-'))
    writeFileSync(
      join(root, 'sample.test.ts'),
      [
        "import fc from 'fast-check'",
        "import { test } from 'vitest'",
        '',
        `// Feature: ${FEATURE_NAME}, Property 3: For any byte sequence, carrying it as`,
        '// process output through one round trip yields the input bytes.',
        "test('process output is byte exact', () => {",
        `  ${ASSERT_CALL}fc.property(fc.uint8Array(), (data) => data.length >= 0))`,
        '})',
        '',
        "test('not a property', () => {})",
        '',
      ].join('\n'),
      'utf8',
    )

    const collected = collectPropertyTests(root)

    expect(collected).toHaveLength(1)
    expect(collected[0]?.path).toBe('sample.test.ts')
    expect(collected[0]?.tag?.number).toBe(3)
    expect(isWellFormed(collected[0]?.tag ?? null)).toBe(true)
  })

  it('reports an untagged property test', () => {
    const root = mkdtempSync(join(tmpdir(), 'offline-harness-'))
    writeFileSync(
      join(root, 'untagged.test.ts'),
      [
        "import fc from 'fast-check'",
        "import { test } from 'vitest'",
        '',
        "test('untagged', () => {",
        `  ${ASSERT_CALL}fc.property(fc.integer(), (value) => Number.isInteger(value)))`,
        '})',
        '',
      ].join('\n'),
      'utf8',
    )

    const collected = collectPropertyTests(root)

    expect(collected).toHaveLength(1)
    expect(collected[0]?.tag).toBeNull()
  })
})

describe('the TypeScript suite', () => {
  const collected = collectPropertyTests(PACKAGE_ROOT)

  it('tags every property test it contains', () => {
    const untagged = collected
      .filter((test) => !isWellFormed(test.tag))
      .map((test) => `${test.path}:${test.line}`)
    expect(untagged).toEqual([])
  })

  it('claims no property number twice', () => {
    const owners = new Map<number, string[]>()
    for (const test of collected) {
      if (test.tag !== null) {
        const seen = owners.get(test.tag.number) ?? []
        seen.push(`${test.path}:${test.line}`)
        owners.set(test.tag.number, seen)
      }
    }
    const duplicated = [...owners.entries()].filter(([, tests]) => tests.length > 1)
    expect(duplicated).toEqual([])
  })
})
