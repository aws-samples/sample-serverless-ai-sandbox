// kiro-classification: public
//
// The guard that keeps the TypeScript suite offline is itself asserted, not assumed
// (R15.9, R18.17).

import net from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import {
  denyOutboundNetwork,
  isLoopbackHost,
  isOutboundNetworkDenied,
  OutboundNetworkDeniedError,
} from './network.js'

describe('outbound network denial', () => {
  it('is installed by the setup file', () => {
    expect(isOutboundNetworkDenied()).toBe(true)
  })

  it('denies a fetch to a remote host', async () => {
    await expect(fetch('https://example.com/')).rejects.toThrow(OutboundNetworkDeniedError)
  })

  it('denies a socket connection to a remote host', () => {
    expect(() => net.connect({ host: '93.184.216.34', port: 443 })).toThrow(
      OutboundNetworkDeniedError,
    )
  })

  it('denies a socket connection given a remote host name', () => {
    expect(() => net.connect(443, 'dynamodb.eu-west-1.amazonaws.com')).toThrow(
      /Outbound network access denied/,
    )
  })

  it('reports a second guard as not holding the patches', () => {
    const second = denyOutboundNetwork()
    expect(second.installed).toBe(false)
    second.uninstall()
    expect(isOutboundNetworkDenied()).toBe(true)
  })
})

describe('loopback', () => {
  let server: net.Server
  let port: number

  beforeAll(async () => {
    server = net.createServer((socket) => socket.end())
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (address === null || typeof address === 'string') {
      throw new Error('the loopback server reported no port')
    }
    port = address.port
  })

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    )
  })

  it('stays reachable, because the offline suite talks to local stubs', async () => {
    const connected = await new Promise<boolean>((resolve, reject) => {
      const socket = net.connect(port, '127.0.0.1')
      socket.on('connect', () => {
        socket.end()
        resolve(true)
      })
      socket.on('error', reject)
    })
    expect(connected).toBe(true)
  })
})

describe('host classification', () => {
  it.each(['localhost', '127.0.0.1', '127.0.0.53', '::1', '', '0.0.0.0'])(
    'treats %s as local',
    (host) => {
      expect(isLoopbackHost(host)).toBe(true)
    },
  )

  it.each(['example.com', '93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946', '169.254.169.254'])(
    'treats %s as remote',
    (host) => {
      expect(isLoopbackHost(host)).toBe(false)
    },
  )

  it('treats an absent host as local, because connect() defaults to the local machine', () => {
    expect(isLoopbackHost(undefined)).toBe(true)
    expect(isLoopbackHost(null)).toBe(true)
  })
})
