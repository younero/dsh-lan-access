import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import { once } from 'node:events'
import { readFile } from 'node:fs/promises'
import { startRelay, accessUrls } from '../lib/relay.js'
import { apply, normalizeConfig } from '../lib/index.js'

const TOKEN = 'lifecycle-test-key'

async function within(promise) {
  let timer
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('operation timed out')), 1500) })
    ])
  } finally {
    clearTimeout(timer)
  }
}

async function fixture(t, handler, upgrade) {
  const upstreamSockets = new Set()
  const clients = new Set()
  const upstream = http.createServer(handler)
  upstream.on('connection', (socket) => {
    upstreamSockets.add(socket)
    socket.once('close', () => upstreamSockets.delete(socket))
  })
  if (upgrade) upstream.on('upgrade', upgrade)
  upstream.listen(0, '127.0.0.1')
  await once(upstream, 'listening')
  const logs = []
  const relay = await startRelay({
    upstreamPort: upstream.address().port,
    host: '127.0.0.1', port: 0, token: TOKEN, log: (message) => logs.push(message)
  })
  t.after(async () => {
    for (const client of clients) client.destroy()
    for (const socket of upstreamSockets) socket.destroy()
    await relay.close()
    await new Promise((resolve) => upstream.close(resolve))
  })
  const origin = `http://127.0.0.1:${relay.port}`
  const enrollment = await fetch(`${origin}/?k=${TOKEN}`, { redirect: 'manual' })
  const cookie = enrollment.headers.get('set-cookie').split(';')[0]
  return {
    relay, origin, cookie, logs,
    request(path, options = {}) {
      const request = http.request(origin + path, { ...options, headers: { cookie, ...options.headers } })
      clients.add(request)
      request.on('error', () => {})
      return request
    },
    async websocket() {
      const socket = net.connect(relay.port, '127.0.0.1')
      clients.add(socket)
      socket.on('error', () => {})
      const handshake = once(socket, 'data')
      socket.write(`GET /ws HTTP/1.1\r\nHost: 127.0.0.1:${relay.port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nCookie: ${cookie}\r\n\r\n`)
      assert.match((await within(handshake))[0].toString(), /101 Switching Protocols/)
      return socket
    }
  }
}

function acceptUpgrade(_request, socket) {
  socket.on('error', () => {})
  socket.once('end', () => socket.end())
  socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n')
  socket.resume()
}

test('packaged installation leaves the relay disabled until explicitly enabled', async () => {
  const patch = await readFile(new URL('../cordis.patch.yml', import.meta.url), 'utf8')
  const enabled = patch.match(/^\s+enabled:\s*(true|false)\s*$/m)?.[1]
  assert.equal(enabled, 'false')
  assert.equal(normalizeConfig({}).enabled, false)
  apply({ effect() { assert.fail('disabled plugin must not register effects') } }, { enabled: enabled === 'true' })
})

test('a specific listener advertises its bound address and logs a local-only entry', async (t) => {
  const stack = await fixture(t, (_req, res) => res.end('ok'))
  assert.equal(stack.relay.url, `${stack.origin}/?k=${TOKEN}`)
  assert.deepEqual(stack.relay.urls, [stack.relay.url])
  assert.ok(stack.logs.includes(`本机访问入口: ${stack.relay.url}`))
  const response = await fetch(stack.relay.url, { redirect: 'manual' })
  assert.equal(response.status, 302)
})

const interfaces = {
  lo: [{ family: 'IPv4', internal: true, address: '127.0.0.1' }],
  wifi: [
    { family: 'IPv4', internal: false, address: '192.168.1.8' },
    { family: 'IPv6', internal: false, address: 'fd00::8', scopeid: 0 },
    { family: 'IPv6', internal: false, address: 'fe80::8', scopeid: 2 }
  ],
  vpn: [{ family: 'IPv4', internal: false, address: '10.8.0.7' }],
  docker: [{ family: 'IPv4', internal: false, address: '172.17.0.1' }],
  duplicate: [{ family: 'IPv4', internal: false, address: '192.168.1.8' }]
}

test('wildcard IPv4 advertises every distinct IPv4 candidate across multiple networks', () => {
  assert.deepEqual(accessUrls({ address: '0.0.0.0', port: 8790 }, 'a+b', interfaces), [
    'http://192.168.1.8:8790/?k=a%2Bb',
    'http://10.8.0.7:8790/?k=a%2Bb',
    'http://172.17.0.1:8790/?k=a%2Bb'
  ])
})

test('explicit IPv4 and IPv6 listeners ignore unrelated interfaces', () => {
  assert.deepEqual(accessUrls({ address: '10.8.0.7', port: 8790 }, TOKEN, interfaces), [
    `http://10.8.0.7:8790/?k=${TOKEN}`
  ])
  assert.deepEqual(accessUrls({ address: '::1', port: 8790 }, TOKEN, interfaces), [
    `http://[::1]:8790/?k=${TOKEN}`
  ])
})

test('dual-stack candidates format IPv6 URLs and exclude scoped link-local addresses', () => {
  const urls = accessUrls({ address: '::', port: 8790 }, TOKEN, interfaces)
  assert.ok(urls.includes(`http://[fd00::8]:8790/?k=${TOKEN}`))
  assert.ok(urls.includes(`http://192.168.1.8:8790/?k=${TOKEN}`))
  assert.ok(urls.every((url) => !url.includes('fe80')))
  for (const url of urls) assert.equal(new URL(url).port, '8790')
})

test('wildcard listeners without external interfaces fall back to the matching loopback', () => {
  assert.deepEqual(accessUrls({ address: '0.0.0.0', port: 8790 }, TOKEN, {}), [`http://127.0.0.1:8790/?k=${TOKEN}`])
  assert.deepEqual(accessUrls({ address: '::', port: 8790 }, TOKEN, {}), [`http://[::1]:8790/?k=${TOKEN}`])
})

test('truncated upstream responses abort the downstream body instead of hanging', async (t) => {
  let upstreamResponse
  const stack = await fixture(t, (_req, res) => {
    upstreamResponse = res
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': 100 })
    res.write('partial')
  })
  const request = stack.request('/broken')
  const received = once(request, 'response')
  request.end()
  const [response] = await within(received)
  response.on('error', () => {})
  const closed = new Promise((resolve) => response.once('close', resolve))
  const [chunk] = await within(once(response, 'data'))
  assert.equal(chunk.toString(), 'partial')
  upstreamResponse.destroy()
  await within(closed)
  assert.equal(response.complete, false)
  assert.equal(response.aborted, true)
})

test('upstream failure before response headers returns a complete 502', async (t) => {
  const stack = await fixture(t, (req) => req.socket.destroy())
  const response = await fetch(stack.origin + '/failed', { headers: { cookie: stack.cookie }, signal: AbortSignal.timeout(1500) })
  assert.equal(response.status, 502)
  assert.equal(await response.text(), 'relay upstream error')
})

test('disconnecting a streaming client closes the upstream response', async (t) => {
  let upstreamClosed
  const stack = await fixture(t, (_req, res) => {
    upstreamClosed = new Promise((resolve) => res.once('close', resolve))
    res.writeHead(200, { 'content-type': 'text/event-stream' })
    res.write('data: hello\n\n')
  })
  const request = stack.request('/stream')
  const received = once(request, 'response')
  request.end()
  const [response] = await within(received)
  await within(once(response, 'data'))
  response.destroy()
  await within(upstreamClosed)
})

test('aborting an upload cancels the incomplete upstream request', async (t) => {
  let reportStarted
  const started = new Promise((resolve) => { reportStarted = resolve })
  let upstreamClosed
  let upstreamRequest
  const stack = await fixture(t, (req) => {
    upstreamRequest = req
    req.on('error', () => {})
    upstreamClosed = new Promise((resolve) => req.once('close', resolve))
    req.once('data', reportStarted)
  })
  const request = stack.request('/upload', { method: 'POST', headers: { 'content-length': 100 } })
  request.write('partial')
  await within(started)
  request.destroy()
  await within(upstreamClosed)
  assert.equal(upstreamRequest.complete, false)
})

test('disconnecting a WebSocket client closes its upstream socket', async (t) => {
  let upstreamClosed
  const stack = await fixture(t, (_req, res) => res.end(), (req, socket) => {
    upstreamClosed = new Promise((resolve) => socket.once('close', resolve))
    acceptUpgrade(req, socket)
  })
  const client = await stack.websocket()
  client.destroy()
  await within(upstreamClosed)
})

test('a normal upstream WebSocket EOF flushes its final payload to a slow client', async (t) => {
  let peer
  const stack = await fixture(t, (_req, res) => res.end(), (req, socket) => {
    peer = socket
    acceptUpgrade(req, socket)
  })
  const client = await stack.websocket()
  const payload = Buffer.alloc(2 * 1024 * 1024, 'x')
  const chunks = []
  client.on('data', (chunk) => {
    chunks.push(chunk)
    client.pause()
    setImmediate(() => client.resume())
  })
  const ended = once(client, 'end')
  peer.end(payload)
  await within(ended)
  assert.deepEqual(Buffer.concat(chunks), payload)
})

test('closing with live WebSocket and HTTP streams releases both hops and the listening port', async (t) => {
  let streamClosed, websocketClosed
  const stack = await fixture(t, (_req, res) => {
    streamClosed = new Promise((resolve) => res.once('close', resolve))
    res.write('streaming')
  }, (req, socket) => {
    websocketClosed = new Promise((resolve) => socket.once('close', resolve))
    acceptUpgrade(req, socket)
  })
  const websocket = await stack.websocket()
  const websocketClientClosed = once(websocket, 'close')
  const request = stack.request('/stream')
  const received = once(request, 'response')
  request.end()
  const [response] = await within(received)
  response.on('error', () => {})
  const streamClientClosed = new Promise((resolve) => response.once('close', resolve))
  await within(once(response, 'data'))
  const closing = stack.relay.close()
  assert.equal(stack.relay.close(), closing, 'concurrent close calls share completion')
  await within(Promise.all([closing, streamClosed, websocketClosed, websocketClientClosed, streamClientClosed]))
  await stack.relay.close()
  const replacement = http.createServer()
  replacement.listen(stack.relay.port, '127.0.0.1')
  await within(once(replacement, 'listening'))
  await new Promise((resolve) => replacement.close(resolve))
})
