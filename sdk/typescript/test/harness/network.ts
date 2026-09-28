// kiro-classification: public
//
// Denial of outbound network access for the TypeScript half of the offline suite
// (R15.9, R18.17). CI denies egress at the operating-system level; this guard denies it
// in-process, so a workstation run reaches the same verdict.
//
// Loopback stays reachable on purpose: the offline suite talks to local stubs.

import net from 'node:net'

const GUIDANCE =
  'The offline suite runs with no deployed AWS resources and no network access ' +
  '(R15.9, R18.17). Use a recording transport or a local stub instead.'

const GUARD_MARKER = Symbol.for('agent-sandbox.offline-network-guard')

const LOOPBACK_NAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback'])

// An unspecified address in a connect() call resolves to the local host.
const UNSPECIFIED_ADDRESSES = new Set(['', '0.0.0.0', '::'])

export class OutboundNetworkDeniedError extends Error {
  readonly target: string

  constructor(target: string) {
    super(`Outbound network access denied: ${target}. ${GUIDANCE}`)
    this.name = 'OutboundNetworkDeniedError'
    this.target = target
  }
}

/** Report whether `host` names the local machine. */
export function isLoopbackHost(host?: string | null): boolean {
  if (host === undefined || host === null) {
    return true
  }
  const bare = host.split('%')[0] ?? ''
  if (LOOPBACK_NAMES.has(bare.toLowerCase()) || UNSPECIFIED_ADDRESSES.has(bare)) {
    return true
  }
  const version = net.isIP(bare)
  if (version === 4) {
    return bare.startsWith('127.')
  }
  if (version === 6) {
    return bare === '::1' || bare === '0:0:0:0:0:0:0:1'
  }
  return false
}

/**
 * The destination a `Socket.connect` call names, or `undefined` when it names no remote
 * host: an IPC path, or a port with the host defaulted to the local machine.
 */
function connectTarget(args: readonly unknown[]): string | undefined {
  const [first, second] = args
  // net.connect() normalises its arguments and calls Socket.prototype.connect with the
  // normalised [options, callback] array, so that form is unwrapped rather than missed.
  if (Array.isArray(first)) {
    return connectTarget(first)
  }
  if (typeof first === 'number') {
    return typeof second === 'string' ? second : undefined
  }
  if (typeof first === 'string') {
    return undefined
  }
  if (typeof first === 'object' && first !== null) {
    const options = first as { host?: unknown; path?: unknown }
    if (typeof options.path === 'string') {
      return undefined
    }
    return typeof options.host === 'string' ? options.host : undefined
  }
  return undefined
}

function fetchTarget(input: unknown): string | undefined {
  const candidate =
    typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.href
        : typeof input === 'object' && input !== null && 'url' in input
          ? String((input as { url: unknown }).url)
          : undefined
  if (candidate === undefined) {
    return undefined
  }
  try {
    return new URL(candidate).hostname
  } catch {
    return undefined
  }
}

interface Marked {
  [GUARD_MARKER]?: true
}

function isMarked(value: unknown): boolean {
  return typeof value === 'function' && (value as Marked)[GUARD_MARKER] === true
}

/** Report whether outbound network access is already denied in this process. */
export function isOutboundNetworkDenied(): boolean {
  return isMarked(net.Socket.prototype.connect) && isMarked(globalThis.fetch)
}

export interface NetworkGuard {
  /** True when this guard is the one holding the patches in place. */
  readonly installed: boolean
  uninstall(): void
}

class OfflineNetworkGuard implements NetworkGuard {
  #originalConnect: typeof net.Socket.prototype.connect | undefined
  #originalFetch: typeof globalThis.fetch | undefined

  get installed(): boolean {
    return this.#originalConnect !== undefined
  }

  install(): void {
    if (this.installed || isOutboundNetworkDenied()) {
      return
    }

    const originalConnect = net.Socket.prototype.connect
    const originalFetch = globalThis.fetch

    const guardedConnect = function (this: net.Socket, ...args: unknown[]): net.Socket {
      const target = connectTarget(args)
      if (target !== undefined && !isLoopbackHost(target)) {
        throw new OutboundNetworkDeniedError(target)
      }
      return (originalConnect as (this: net.Socket, ...rest: unknown[]) => net.Socket).apply(
        this,
        args,
      )
    } as typeof net.Socket.prototype.connect
    ;(guardedConnect as Marked)[GUARD_MARKER] = true

    const guardedFetch = ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      const target = fetchTarget(input)
      if (target !== undefined && !isLoopbackHost(target)) {
        return Promise.reject(new OutboundNetworkDeniedError(target))
      }
      return originalFetch(input, init)
    }) as typeof globalThis.fetch
    ;(guardedFetch as Marked)[GUARD_MARKER] = true

    net.Socket.prototype.connect = guardedConnect
    globalThis.fetch = guardedFetch

    this.#originalConnect = originalConnect
    this.#originalFetch = originalFetch
  }

  uninstall(): void {
    if (this.#originalConnect === undefined || this.#originalFetch === undefined) {
      return
    }
    net.Socket.prototype.connect = this.#originalConnect
    globalThis.fetch = this.#originalFetch
    this.#originalConnect = undefined
    this.#originalFetch = undefined
  }
}

/** Deny every outbound connection except loopback for the rest of this process. */
export function denyOutboundNetwork(): NetworkGuard {
  const guard = new OfflineNetworkGuard()
  guard.install()
  return guard
}
