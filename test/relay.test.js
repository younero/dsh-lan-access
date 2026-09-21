import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import crypto from 'node:crypto'
import { startRelay, PAIR_PATH, PRIVILEGED_METHODS } from '../lib/relay.js'

const TOKEN = 'test-key-123'

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve(server.address().port))
  })
}

function startUpstream(handler, { upgrade } = {}) {
  const server = http.createServer(handler)
  if (upgrade) server.on('upgrade', upgrade)
  return listen(server).then((port) => ({ server, port }))
}

async function startStack(handler, extra = {}) {
  const { upgrade, ...relayOptions } = extra
  const upstream = await startUpstream(handler, { upgrade })
  const relay = await startRelay({
    upstreamHost: '127.0.0.1',
    upstreamPort: upstream.port,
    host: '127.0.0.1',
    port: 0,
    token: TOKEN,
    log: () => {},
    ...relayOptions
  })
  return {
    upstream,
    relay,
    origin: `http://127.0.0.1:${relay.port}`,
    async close() {
      await relay.close()
      await new Promise((done) => upstream.server.close(() => done()))
    }
  }
}

function cookieFrom(response) {
  const raw = response.headers.getSetCookie?.() ?? []
  const line = raw.find((item) => item.startsWith('dsh_mobile=')) ?? response.headers.get('set-cookie')
  assert.ok(line, 'expected a dsh_mobile cookie')
  return line.split(';', 1)[0]
}

test('PRIVILEGED_METHODS covers the settings/credentials plane', () => {
  for (const method of ['settings.update', 'credentials.set', 'llm.discoverModels', 'host.pickDirectory']) {
    assert.ok(PRIVILEGED_METHODS.has(method), method)
  }
})

test('unauthenticated GET / serves the pairing page', async () => {
  const stack = await startStack((_req, res) => {
    res.writeHead(500)
    res.end('should-not-proxy')
  })
  try {
    const response = await fetch(stack.origin + '/')
    const body = await response.text()
    assert.equal(response.status, 200)
    assert.match(body, /访问密钥/)
    assert.doesNotMatch(body, /should-not-proxy/)
  } finally {
    await stack.close()
  }
})

test('unauthenticated GET on the pair path also serves the pairing page', async () => {
  const stack = await startStack((_req, res) => {
    res.writeHead(500)
    res.end('nope')
  })
  try {
    const response = await fetch(stack.origin + PAIR_PATH)
    assert.equal(response.status, 200)
    assert.match(await response.text(), /访问密钥/)
  } finally {
    await stack.close()
  }
})

test('unauthenticated /api is 401 json, not the pairing page', async () => {
  const stack = await startStack((_req, res) => {
    res.writeHead(200)
    res.end('leaked')
  })
  try {
    const response = await fetch(stack.origin + '/api/host.list', { method: 'POST' })
    assert.equal(response.status, 401)
    assert.equal(await response.text(), '{"error":"unauthorized"}')
  } finally {
    await stack.close()
  }
})

test('?k= with the right key sets a cookie and redirects to a clean URL', async () => {
  const stack = await startStack((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok')
  })
  try {
    const response = await fetch(`${stack.origin}/?k=${TOKEN}`, { redirect: 'manual' })
    assert.equal(response.status, 302)
    assert.equal(response.headers.get('location'), '/')
    const cookie = cookieFrom(response)
    const authed = await fetch(stack.origin + '/', { headers: { cookie } })
    assert.equal(await authed.text(), 'ok')
  } finally {
    await stack.close()
  }
})

test('?k= with a wrong key is 401', async () => {
  const stack = await startStack((_req, res) => {
    res.writeHead(200)
    res.end('ok')
  })
  try {
    const response = await fetch(`${stack.origin}/?k=nope`)
    assert.equal(response.status, 401)
  } finally {
    await stack.close()
  }
})

test('POST pair with the right key mints a cookie', async () => {
  const stack = await startStack((_req, res) => {
    res.writeHead(200)
    res.end('ok')
  })
  try {
    const response = await fetch(stack.origin + PAIR_PATH, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ key: TOKEN })
    })
    assert.equal(response.status, 204)
    const cookie = cookieFrom(response)
    const authed = await fetch(stack.origin + '/hello', { headers: { cookie } })
    assert.equal(await authed.text(), 'ok')
  } finally {
    await stack.close()
  }
})

test('rewrites Host to loopback and strips Origin so the fence would pass', async () => {
  let seen
  const stack = await startStack((req, res) => {
    seen = { host: req.headers.host, origin: req.headers.origin, referer: req.headers.referer }
    res.writeHead(200)
    res.end('ok')
  })
  try {
    const enroll = await fetch(`${stack.origin}/?k=${TOKEN}`, { redirect: 'manual' })
    const cookie = cookieFrom(enroll)
    await fetch(stack.origin + '/api/host.list', {
      method: 'POST',
      headers: {
        cookie,
        origin: 'http://192.168.1.8:8790',
        referer: 'http://192.168.1.8:8790/',
        'sec-fetch-site': 'cross-site'
      }
    })
    assert.equal(seen.host, `127.0.0.1:${stack.upstream.port}`)
    assert.equal(seen.origin, undefined)
    assert.equal(seen.referer, undefined)
  } finally {
    await stack.close()
  }
})

test('authenticated privileged methods proxy by default (same harness)', async () => {
  const stack = await startStack((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(req.url)
  })
  try {
    const enroll = await fetch(`${stack.origin}/?k=${TOKEN}`, { redirect: 'manual' })
    const cookie = cookieFrom(enroll)
    const response = await fetch(stack.origin + '/api/settings.describe', {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: '{}'
    })
    assert.equal(response.status, 200)
    assert.equal(await response.text(), '/api/settings.describe')
  } finally {
    await stack.close()
  }
})

test('blockPrivileged still refuses settings/credentials RPCs', async () => {
  const stack = await startStack(
    (_req, res) => {
      res.writeHead(200)
      res.end('leaked')
    },
    { blockPrivileged: true }
  )
  try {
    const enroll = await fetch(`${stack.origin}/?k=${TOKEN}`, { redirect: 'manual' })
    const cookie = cookieFrom(enroll)
    const response = await fetch(stack.origin + '/api/settings.update', {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: '{}'
    })
    assert.equal(response.status, 403)
    assert.equal(await response.text(), '{"error":"forbidden-on-mobile-relay"}')
  } finally {
    await stack.close()
  }
})

test('chunked upstream bodies survive hop-by-hop header stripping', async () => {
  const stack = await startStack((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'transfer-encoding': 'chunked' })
    res.write('hel')
    res.end('lo')
  })
  try {
    const enroll = await fetch(`${stack.origin}/?k=${TOKEN}`, { redirect: 'manual' })
    const cookie = cookieFrom(enroll)
    const response = await fetch(stack.origin + '/chunked', { headers: { cookie } })
    assert.equal(response.status, 200)
    assert.equal(await response.text(), 'hello')
  } finally {
    await stack.close()
  }
})

test('websocket handshake forwards Sec-WebSocket-Key and rewrites Host', async () => {
  let seen
  const key = 'dGhlIHNhbXBsZSBub25jZQ=='
  const stack = await startStack(
    (_req, res) => {
      res.writeHead(404)
      res.end()
    },
    {
      upgrade(req, socket) {
        seen = {
          host: req.headers.host,
          origin: req.headers.origin,
          upgrade: req.headers.upgrade,
          key: req.headers['sec-websocket-key']
        }
        const accept = crypto.createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')
        socket.write(
          `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`
        )
        socket.end()
      }
    }
  )
  try {
    const enroll = await fetch(`${stack.origin}/?k=${TOKEN}`, { redirect: 'manual' })
    const cookie = cookieFrom(enroll)
    const response = await new Promise((resolve, reject) => {
      const socket = net.connect(stack.relay.port, '127.0.0.1', () => {
        socket.write(
          `GET /api/events.mux HTTP/1.1\r\nHost: 192.168.110.56:${stack.relay.port}\r\nOrigin: http://192.168.110.56:${stack.relay.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${key}\r\nCookie: ${cookie}\r\n\r\n`
        )
      })
      const chunks = []
      socket.on('data', (chunk) => chunks.push(chunk))
      socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
      socket.on('error', reject)
      setTimeout(() => reject(new Error('timeout')), 3000)
    })
    assert.match(response, /101/)
    assert.match(response, /Sec-WebSocket-Accept/)
    assert.equal(seen.upgrade, 'websocket')
    assert.equal(seen.key, key)
    assert.equal(seen.host, `127.0.0.1:${stack.upstream.port}`)
    assert.equal(seen.origin, undefined)
  } finally {
    await stack.close()
  }
})

test('websocket upgrade requires a session cookie', async () => {
  const stack = await startStack((_req, res) => {
    res.writeHead(404)
    res.end()
  }, {
    upgrade(req, socket) {
      socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
      socket.write('pong')
      socket.end()
    }
  })
  try {
    const denied = await new Promise((resolve, reject) => {
      const socket = net.connect(stack.relay.port, '127.0.0.1', () => {
        socket.write('GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
      })
      const chunks = []
      socket.on('data', (chunk) => chunks.push(chunk))
      socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
      socket.on('error', reject)
      setTimeout(() => reject(new Error('timeout')), 3000)
    })
    assert.match(denied, /401/)

    const enroll = await fetch(`${stack.origin}/?k=${TOKEN}`, { redirect: 'manual' })
    const cookie = cookieFrom(enroll)
    const allowed = await new Promise((resolve, reject) => {
      const socket = net.connect(stack.relay.port, '127.0.0.1', () => {
        socket.write(
          `GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nCookie: ${cookie}\r\n\r\n`
        )
      })
      const chunks = []
      socket.on('data', (chunk) => chunks.push(chunk))
      socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
      socket.on('error', reject)
      setTimeout(() => reject(new Error('timeout')), 3000)
    })
    assert.match(allowed, /101/)
    assert.match(allowed, /pong/)
  } finally {
    await stack.close()
  }
})
