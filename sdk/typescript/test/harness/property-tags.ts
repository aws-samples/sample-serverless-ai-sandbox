// kiro-classification: public
//
// The per-property tagging comment form the design's Testing Strategy fixes, in its
// TypeScript spelling. The Python form is identical apart from the comment marker:
//
//   // Feature: aws-serverless-agent-sandbox, Property 3: For any byte sequence, including
//   // sequences that are not valid UTF-8, carrying that sequence as process output through
//   // one serialise and deserialise cycle yields a byte sequence identical to the input.
//   test('process output is byte exact', () => {
//     fc.assert(fc.property(outputBytes(), (data) => { /* ... */ }), { numRuns: CODEC_RUNS })
//   })
//
// Properties 1 through 4 are stated in both languages, so the property numbers here overlap
// with the Python suite's by design; uniqueness is asserted per language.

import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'

export const FEATURE_NAME = 'aws-serverless-agent-sandbox'

/** The design fixes 44 correctness properties, each implemented by exactly one test. */
export const PROPERTY_COUNT = 44

export const PROPERTY_TAG_PATTERN =
  /^\s*\/\/\s*Feature:\s([a-z0-9][a-z0-9-]*),\sProperty\s([1-9][0-9]*):\s(\S.*)$/

const CONTINUATION_PATTERN = /^\s*\/\/ ?(.*)$/

const TEST_DECLARATION_PATTERN = /^\s*(?:it|test)(?:\.\w+)*\s*\(/

const EXCLUDED_DIRECTORIES = new Set(['node_modules', 'dist', '.git'])

export interface PropertyTag {
  readonly feature: string
  readonly number: number
  readonly summary: string
}

export interface TaggedTest {
  /** Path relative to the package root. */
  readonly path: string
  /** 1-based line of the test declaration the tag sits above. */
  readonly line: number
  readonly tag: PropertyTag | null
}

export function isWellFormed(tag: PropertyTag | null): boolean {
  return (
    tag !== null &&
    tag.feature === FEATURE_NAME &&
    tag.number >= 1 &&
    tag.number <= PROPERTY_COUNT &&
    tag.summary.trim().length > 0
  )
}

/** Parse a contiguous run of comment lines into a tag, or null if it is not one. */
export function parsePropertyTag(commentBlock: readonly string[]): PropertyTag | null {
  const first = commentBlock[0]
  if (first === undefined) {
    return null
  }
  const match = PROPERTY_TAG_PATTERN.exec(first)
  if (match === null) {
    return null
  }
  const [, feature, number, summary] = match
  const parts = [summary?.trim() ?? '']
  for (const line of commentBlock.slice(1)) {
    const continuation = CONTINUATION_PATTERN.exec(line)
    if (continuation === null) {
      break
    }
    parts.push(continuation[1]?.trim() ?? '')
  }
  return {
    feature: feature ?? '',
    number: Number(number),
    summary: parts.filter((part) => part.length > 0).join(' '),
  }
}

function* walkTestFiles(root: string): Generator<string> {
  for (const entry of readdirSync(root, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name),
  )) {
    if (entry.isDirectory()) {
      if (!EXCLUDED_DIRECTORIES.has(entry.name)) {
        yield* walkTestFiles(join(root, entry.name))
      }
    } else if (entry.name.endsWith('.test.ts')) {
      yield join(root, entry.name)
    }
  }
}

function commentBlockAbove(lines: readonly string[], index: number): string[] {
  const block: string[] = []
  for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
    const line = lines[cursor]
    if (line === undefined || !line.trimStart().startsWith('//')) {
      break
    }
    block.unshift(line)
  }
  return block
}

/**
 * Collect every property-based test under `root`: a test whose body drives fast-check,
 * paired with the tag comment sitting above its declaration.
 */
export function collectPropertyTests(root: string): TaggedTest[] {
  const collected: TaggedTest[] = []
  for (const file of walkTestFiles(root)) {
    const lines = readFileSync(file, 'utf8').split('\n')
    const declarations = new Set<number>()
    lines.forEach((line, index) => {
      if (!line.includes('fc.assert(')) {
        return
      }
      for (let cursor = index; cursor >= 0; cursor -= 1) {
        if (TEST_DECLARATION_PATTERN.test(lines[cursor] ?? '')) {
          declarations.add(cursor)
          return
        }
      }
    })
    for (const index of [...declarations].sort((a, b) => a - b)) {
      collected.push({
        path: relative(root, file),
        line: index + 1,
        tag: parsePropertyTag(commentBlockAbove(lines, index)),
      })
    }
  }
  return collected
}
