// kiro-classification: public
//
// The codec's view of the schema catalogue: one seam, so the coupling is stated once.
//
// `messages.yaml` is the single schema source (R8.1) and `protocol/schema.py` is its only reader.
// `export_catalogue.py` writes `catalogue.json` from that reader, and
// `protocol/generators/catalogue.ts` is the TypeScript parse of that mirror. This module re-exports
// what the codec needs from it, and it exists rather than a second reader for the reason the mirror
// exists at all: a second parse of the same document is a second place for the schema to be
// understood slightly differently, and the vector corpus would be left to discover the difference
// as a wire disagreement.
//
// The reader sits under `generators/` because that is where it was first needed, not because it is
// a generator: it imports `node:fs` and nothing else, so the codec's module graph gains no
// test-only dependency by reaching it. Naming that in one file rather than in seven import
// statements is the whole purpose here — this is the TypeScript counterpart of the codec importing
// `protocol.schema`.

export {
  ENVELOPE_KEY_BODY,
  ENVELOPE_KEY_ID,
  ENVELOPE_KEY_TYPE,
  ENVELOPE_KEY_VERSION,
  loadCatalogue,
  messageTypes,
  supports,
} from '../generators/catalogue.js'

export type {
  Catalogue,
  Field,
  IntRange,
  MessageType,
  TypeKind,
  TypeSpec,
} from '../generators/catalogue.js'
