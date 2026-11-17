// kiro-classification: public
//
// Unit coverage for the execute-based operations ported to reach parity with the Python SDK.
// Each test stubs SandboxConnection.execute (and readFile where needed) so nothing touches the
// network — the suite's global outbound denial stays satisfied.

import { describe, expect, it, vi } from 'vitest';

import { SandboxConnection, ProcessHandle, GitOperations, type CommandResult } from '../src/index.js';

function makeConn(): SandboxConnection {
  return new SandboxConnection({
    baseUrl: 'https://sandbox.invalid',
    authHeaderName: 'X-Test',
    authHeaderValue: 'token',
  });
}

const ok = (stdout = '', stderr = '', exitCode = 0): CommandResult => ({ exitCode, stdout, stderr });

describe('filesystem helpers', () => {
  it('fileExists maps exit code to boolean and builds the right argv', async () => {
    const conn = makeConn();
    const exec = vi.fn().mockResolvedValue(ok('', '', 0));
    conn.execute = exec;
    expect(await conn.fileExists('/tmp/x')).toBe(true);
    expect(exec).toHaveBeenCalledWith(['test', '-e', '/tmp/x'], { timeoutSeconds: 5 });

    conn.execute = vi.fn().mockResolvedValue(ok('', '', 1));
    expect(await conn.fileExists('/tmp/missing')).toBe(false);
  });

  it('fileInfo parses stat output (split-on-whitespace, max 4 — matches Python)', async () => {
    const conn = makeConn();
    conn.execute = vi.fn().mockResolvedValue(ok('1024 1700000000 644 regular file /tmp/a.txt\n'));
    const info = await conn.fileInfo('/tmp/a.txt');
    expect(info.size).toBe(1024);
    expect(info.modified).toBe(1700000000);
    expect(info.permissions).toBe('644');
    // %F ("regular file") and name share the 5th field by Python's split(None, 4) contract.
    expect(info.fileType).toBe('regular');
    expect(info.path).toBe('file /tmp/a.txt');
  });

  it('fileInfo throws when stat fails', async () => {
    const conn = makeConn();
    conn.execute = vi.fn().mockResolvedValue(ok('', 'No such file', 1));
    await expect(conn.fileInfo('/nope')).rejects.toThrow(/stat failed/);
  });

  it('makeDir toggles -p via parents', async () => {
    const conn = makeConn();
    const exec = vi.fn().mockResolvedValue(ok());
    conn.execute = exec;
    await conn.makeDir('/tmp/d');
    expect(exec).toHaveBeenCalledWith(['mkdir', '-p', '/tmp/d'], { timeoutSeconds: 5 });
    await conn.makeDir('/tmp/d', { parents: false });
    expect(exec).toHaveBeenCalledWith(['mkdir', '/tmp/d'], { timeoutSeconds: 5 });
  });

  it('renameFile shells out to mv', async () => {
    const conn = makeConn();
    const exec = vi.fn().mockResolvedValue(ok());
    conn.execute = exec;
    await conn.renameFile('/tmp/a', '/tmp/b');
    expect(exec).toHaveBeenCalledWith(['mv', '/tmp/a', '/tmp/b'], { timeoutSeconds: 5 });
  });

  it('listFilesRecursive recurses over fs.list with full-path names (no find)', async () => {
    const conn = makeConn();
    // Mock the fs.list wire op: /tmp/dir has a file and a subdir; the subdir has one file.
    conn.listFiles = vi.fn(async (dir: string) => {
      if (dir === '/tmp/dir') {
        return [
          { name: 'a.txt', kind: 'file', size: 12 },
          { name: 'sub', kind: 'directory', size: 4096 },
        ];
      }
      if (dir === '/tmp/dir/sub') {
        return [{ name: 'b.txt', kind: 'file', size: 7 }];
      }
      return [];
    });
    const entries = await conn.listFilesRecursive('/tmp/dir', { depth: 3 });
    expect(entries).toEqual([
      { name: '/tmp/dir/a.txt', kind: 'file', size: 12 },
      { name: '/tmp/dir/sub', kind: 'directory', size: 4096 },
      { name: '/tmp/dir/sub/b.txt', kind: 'file', size: 7 },
    ]);
  });

  it('listFilesRecursive honours depth (depth: 1 = immediate children only)', async () => {
    const conn = makeConn();
    const listFiles = vi.fn(async (dir: string) =>
      dir === '/tmp/dir'
        ? [{ name: 'sub', kind: 'directory', size: 4096 }]
        : [{ name: 'deep.txt', kind: 'file', size: 1 }],
    );
    conn.listFiles = listFiles;
    const entries = await conn.listFilesRecursive('/tmp/dir', { depth: 1 });
    expect(entries).toEqual([{ name: '/tmp/dir/sub', kind: 'directory', size: 4096 }]);
    expect(listFiles).toHaveBeenCalledTimes(1); // did not descend
  });

  it('writeFiles writes each file once', async () => {
    const conn = makeConn();
    const write = vi.fn().mockResolvedValue(undefined);
    conn.writeFile = write;
    await conn.writeFiles([['/tmp/a', 'A'], ['/tmp/b', new Uint8Array([66])]]);
    expect(write).toHaveBeenCalledTimes(2);
    expect(write.mock.calls[0]![0]).toBe('/tmp/a');
    expect(write.mock.calls[1]![0]).toBe('/tmp/b');
  });
});

describe('background execution', () => {
  it('executeBackground parses the pid and returns a ProcessHandle', async () => {
    const conn = makeConn();
    const exec = vi.fn().mockResolvedValue(ok('4242\n'));
    conn.execute = exec;
    const handle = await conn.executeBackground('sleep 1 | cat');
    expect(handle).toBeInstanceOf(ProcessHandle);
    expect(handle.pid).toBe(4242);
    const argv = exec.mock.calls[0]![0] as string[];
    expect(argv[0]).toBe('sh');
    expect(argv[1]).toBe('-c');
    expect(argv[2]).toContain('nohup');
    expect(argv[2]).toContain('echo $!');
  });

  it('executeBackground rejects when no pid comes back', async () => {
    const conn = makeConn();
    conn.execute = vi.fn().mockResolvedValue(ok('not-a-pid\n'));
    await expect(conn.executeBackground('true')).rejects.toThrow(/Failed to start/);
  });

  it('ProcessHandle.isRunning reflects kill -0 exit code', async () => {
    const conn = makeConn();
    const exec = vi.fn().mockResolvedValue(ok('', '', 0));
    conn.execute = exec;
    const handle = new ProcessHandle({ pid: 99, sandbox: conn, stdoutPath: '/tmp/o', stderrPath: '/tmp/e' });
    expect(await handle.isRunning()).toBe(true);
    expect(exec).toHaveBeenCalledWith(['kill', '-0', '99'], { timeoutSeconds: 5 });
  });

  it('wait reads the real exit code from the rc file (not the wait builtin)', async () => {
    const conn = makeConn();
    // First execute: the kill -0 poll loop. Second: cat of the rc file returns the code.
    const exec = vi
      .fn()
      .mockResolvedValueOnce(ok(''))        // poll loop finishes
      .mockResolvedValueOnce(ok('42\n', '', 0)); // cat rcPath
    conn.execute = exec;
    conn.readFile = vi.fn().mockResolvedValue(new TextEncoder().encode('out'));
    const handle = new ProcessHandle({
      pid: 7, sandbox: conn, stdoutPath: '/tmp/o', stderrPath: '/tmp/e', rcPath: '/tmp/.bg_rc_x',
    });
    const r = await handle.wait({ timeout: 2 });
    expect(r.exitCode).toBe(42);
    expect(exec.mock.calls[1]![0]).toEqual(['cat', '/tmp/.bg_rc_x']);
  });
});

describe('metrics', () => {
  it('getMetrics parses meminfo, df, and loadavg sections', async () => {
    const conn = makeConn();
    const stdout = [
      'MemTotal:        2048000 kB',
      'MemFree:          512000 kB',
      'MemAvailable:    1024000 kB',
      '---',
      '/dev/vda 512000 128000 384000 25% /tmp',
      '---',
      '0.15 0.10 0.05 1/200 1234',
    ].join('\n');
    conn.execute = vi.fn().mockResolvedValue(ok(stdout));
    const m = await conn.getMetrics();
    expect(m.memoryTotalKb).toBe(2048000);
    expect(m.memoryAvailableKb).toBe(1024000);
    expect(m.diskTotal).toBe('512000');
    expect(m.diskUsed).toBe('128000');
    expect(m.diskAvailable).toBe('384000');
    expect(m.loadAvg1).toBeCloseTo(0.15);
    expect(m.loadAvg15).toBeCloseTo(0.05);
  });
});

describe('git operations', () => {
  it('clone builds argv with branch and depth', async () => {
    const conn = makeConn();
    const exec = vi.fn().mockResolvedValue(ok());
    conn.execute = exec;
    await new GitOperations(conn).clone('https://host/r.git', '/tmp/r', { branch: 'main', depth: 1 });
    expect(exec).toHaveBeenCalledWith(
      ['git', 'clone', '-b', 'main', '--depth', '1', 'https://host/r.git', '/tmp/r'],
      { timeoutSeconds: 120 },
    );
  });

  it('status parses porcelain output into categories', async () => {
    const conn = makeConn();
    conn.execute = vi
      .fn()
      .mockResolvedValueOnce(ok('feature/x\n')) // rev-parse
      .mockResolvedValueOnce(ok(' M src/a.ts\nA  src/b.ts\n D src/c.ts\n?? note.txt\n'));
    const st = await new GitOperations(conn).status({ cwd: '/tmp/r' });
    expect(st.branch).toBe('feature/x');
    expect(st.clean).toBe(false);
    expect(st.modified).toEqual(['src/a.ts']);
    expect(st.added).toEqual(['src/b.ts']);
    expect(st.deleted).toEqual(['src/c.ts']);
    expect(st.untracked).toEqual(['note.txt']);
  });

  it('status reports clean tree', async () => {
    const conn = makeConn();
    conn.execute = vi.fn().mockResolvedValueOnce(ok('main\n')).mockResolvedValueOnce(ok(''));
    const st = await new GitOperations(conn).status();
    expect(st.clean).toBe(true);
    expect(st.branch).toBe('main');
  });
});
