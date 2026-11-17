// kiro-classification: public
/**
 * Git operations wrapper for executing git commands inside a Sandbox.
 *
 * @example
 * ```ts
 * const session = await client.createSession();
 * await session.waitReady();
 * await session.git.clone('https://github.com/user/repo', '/tmp/repo', { depth: 1 });
 * const status = await session.git.status({ cwd: '/tmp/repo' });
 * ```
 */

import type { CommandResult, SandboxConnection } from './sandbox.js';

/** Parsed output of `git status --porcelain`. */
export interface GitStatus {
  /** Current branch name (or `"HEAD"` if detached). */
  readonly branch: string;
  /** `true` if the working tree has no uncommitted changes. */
  readonly clean: boolean;
  readonly modified: string[];
  readonly added: string[];
  readonly deleted: string[];
  readonly untracked: string[];
}

/** Convenience wrapper for git commands inside the Sandbox. */
export class GitOperations {
  readonly #sandbox: SandboxConnection;

  constructor(sandbox: SandboxConnection) {
    this.#sandbox = sandbox;
  }

  /** Clone a repository. */
  async clone(
    url: string,
    path: string,
    options?: { branch?: string; depth?: number },
  ): Promise<CommandResult> {
    const cmd = ['git', 'clone'];
    if (options?.branch) cmd.push('-b', options.branch);
    if (options?.depth !== undefined) cmd.push('--depth', String(options.depth));
    cmd.push(url, path);
    const result = await this.#sandbox.execute(cmd, { timeoutSeconds: 120 });
    if (result.exitCode !== 0) throw new Error(`git clone failed: ${result.stderr}`);
    return result;
  }

  /** Initialise a new repository. */
  async init(path: string, options?: { bare?: boolean }): Promise<CommandResult> {
    const cmd = ['git', 'init'];
    if (options?.bare) cmd.push('--bare');
    cmd.push(path);
    const result = await this.#sandbox.execute(cmd, { timeoutSeconds: 10 });
    if (result.exitCode !== 0) throw new Error(`git init failed: ${result.stderr}`);
    return result;
  }

  /** Stage files. With `all: true`, stages everything (`git add -A`). */
  async add(
    paths: string[] = [],
    options?: { cwd?: string; all?: boolean },
  ): Promise<CommandResult> {
    const cmd = ['git', 'add'];
    if (options?.all) cmd.push('-A');
    else cmd.push(...(paths.length > 0 ? paths : ['.']));
    const result = await this.#sandbox.execute(cmd, { cwd: options?.cwd ?? '/tmp', timeoutSeconds: 10 });
    if (result.exitCode !== 0) throw new Error(`git add failed: ${result.stderr}`);
    return result;
  }

  /** Create a commit. */
  async commit(
    message: string,
    options?: { cwd?: string; authorName?: string; authorEmail?: string },
  ): Promise<CommandResult> {
    const env: Record<string, string> = {};
    if (options?.authorName) {
      env.GIT_AUTHOR_NAME = options.authorName;
      env.GIT_COMMITTER_NAME = options.authorName;
    }
    if (options?.authorEmail) {
      env.GIT_AUTHOR_EMAIL = options.authorEmail;
      env.GIT_COMMITTER_EMAIL = options.authorEmail;
    }
    const result = await this.#sandbox.execute(['git', 'commit', '-m', message], {
      cwd: options?.cwd ?? '/tmp',
      env: Object.keys(env).length > 0 ? env : undefined,
      timeoutSeconds: 10,
    });
    if (result.exitCode !== 0) throw new Error(`git commit failed: ${result.stderr}`);
    return result;
  }

  /** Push to a remote. */
  async push(options?: { remote?: string; branch?: string; cwd?: string }): Promise<CommandResult> {
    const cmd = ['git', 'push', options?.remote ?? 'origin'];
    if (options?.branch) cmd.push(options.branch);
    const result = await this.#sandbox.execute(cmd, { cwd: options?.cwd ?? '/tmp', timeoutSeconds: 60 });
    if (result.exitCode !== 0) throw new Error(`git push failed: ${result.stderr}`);
    return result;
  }

  /** Pull from a remote. */
  async pull(options?: { remote?: string; branch?: string; cwd?: string }): Promise<CommandResult> {
    const cmd = ['git', 'pull', options?.remote ?? 'origin'];
    if (options?.branch) cmd.push(options.branch);
    const result = await this.#sandbox.execute(cmd, { cwd: options?.cwd ?? '/tmp', timeoutSeconds: 60 });
    if (result.exitCode !== 0) throw new Error(`git pull failed: ${result.stderr}`);
    return result;
  }

  /** Get the repository status, parsed from `git status --porcelain`. */
  async status(options?: { cwd?: string }): Promise<GitStatus> {
    const cwd = options?.cwd ?? '/tmp';
    const branchResult = await this.#sandbox.execute(
      ['git', 'rev-parse', '--abbrev-ref', 'HEAD'], { cwd, timeoutSeconds: 5 },
    );
    const branch = branchResult.exitCode === 0 ? branchResult.stdout.trim() : 'unknown';

    const result = await this.#sandbox.execute(
      ['git', 'status', '--porcelain'], { cwd, timeoutSeconds: 10 },
    );
    const modified: string[] = [];
    const added: string[] = [];
    const deleted: string[] = [];
    const untracked: string[] = [];
    // Do NOT trim the whole block: the status column of an unstaged-modified line is a leading
    // space (` M path`), and a global trim would shift the filename slice on the first line.
    for (const line of result.stdout.split('\n')) {
      if (!line || line.length < 3) continue;
      const code = line.slice(0, 2);
      const filepath = line.slice(3).trim();
      if (code.trim() === '??') untracked.push(filepath);
      else if (code.includes('M')) modified.push(filepath);
      else if (code.includes('A')) added.push(filepath);
      else if (code.includes('D')) deleted.push(filepath);
    }
    return {
      branch,
      clean: modified.length === 0 && added.length === 0 && deleted.length === 0 && untracked.length === 0,
      modified, added, deleted, untracked,
    };
  }

  /** List branches. */
  async branches(options?: { cwd?: string }): Promise<string[]> {
    const result = await this.#sandbox.execute(
      ['git', 'branch', '--list', '--format=%(refname:short)'],
      { cwd: options?.cwd ?? '/tmp', timeoutSeconds: 10 },
    );
    if (result.exitCode !== 0) throw new Error(`git branch failed: ${result.stderr}`);
    return result.stdout.trim().split('\n').map((b) => b.trim()).filter((b) => b.length > 0);
  }
}
