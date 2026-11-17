// kiro-classification: public
/**
 * TypeScript Client SDK for the AWS Serverless Agent Sandbox.
 *
 * @packageDocumentation
 */

export { SandboxClient } from './client.js';
export type { SandboxClientOptions, CreateSessionOptions, ResolveSessionOptions } from './client.js';

export { SandboxSession } from './session.js';
export type { SessionData, SandboxSessionOptions } from './session.js';

export { SandboxConnection, ProcessHandle, PtySession } from './sandbox.js';
export type {
  CommandResult,
  FileEntry,
  FileInfo,
  Metrics,
  FileEvent,
  ConnectionDescriptor,
  SandboxConnectionOptions,
} from './sandbox.js';

export { GitOperations } from './git.js';
export type { GitStatus } from './git.js';

export { BearerAuth, SigV4Auth } from './auth.js';
export type { Auth } from './auth.js';
