/**
 * Authenticated LAN relay for dsh-lan-access.
 *
 * dsh binds its Web server to loopback and refuses `--host 0.0.0.0` on purpose:
 * the `/api` bridge reaches the agent loop (bash / file tools), so exposing it
 * is remote code execution. This module keeps that bind and adds one narrow
 * door for phones:
 *
 *   phone ──HTTP/WS──> relay (0.0.0.0:port, auth) ──HTTP/WS──> 127.0.0.1:webServerPort
 *
 * Because the upstream copy rewrites `Host` to loopback (and strips the
 * browser markers the fence would reject), the relay is the whole trust
 * boundary. It therefore:
 *
 *   - requires a signed session cookie, minted by visiting `/?k=<key>` or by
 *     submitting the key on the pairing page;
 *   - rate-limits and constant-time-compares the key;
 *   - refuses the privileged RPC methods the upstream fence only pins to
 *     loopback (settings / credentials / native dialogs / model discovery),
 *     which would otherwise be reachable once every request looks loopback.
 *
 * @module dsh-lan-access/relay
 */
import http from 'node:http'
import net from 'node:net'
import crypto from 'node:crypto'
import { networkInterfaces } from 'node:os'

const COOKIE_NAME = 'dsh_mobile'
const PAIR_PATH = '/__dsh_mobile__/pair'
const MAX_BODY_BYTES = 4096
const RATE_WINDOW_MS = 60_000
const RATE_MAX_ATTEMPTS = 10

/** Hop-by-hop headers must not be forwarded either way (RFC 9110 §7.6.1). */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'trailers',
  'transfer-encoding',
  'upgrade'
])

/**
 * Methods gated to loopback upstream. Mirrors `PRIVILEGED_METHODS` in
 * `@deepseek-ai/dsh-client-connection`; keep in sync when that set changes.
 * The relay must enforce this itself because it rewrites every request to
 * look loopback-origin.
 */
const PRIVILEGED_METHODS = new Set([
  'agentPreset.read',
  'agentPreset.copy',
  'agentPreset.openDocument',
  'agentPreset.remove',
  'host.pickDirectory',
  'host.openPath',
  'settings.describe',
  'settings.openDocument',
  'settings.update',
  'settings.replace',
  'settings.mutate',
  'credentials.describe',
  'credentials.set',
  'credentials.unset',
  'llm.discoverModels'
])

const PAIR_PAGE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>DeepSeek Harness · 移动端配对</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100dvh; display: grid; place-items: center;
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
         background: Canvas; color: CanvasText; padding: 24px env(safe-area-inset-right) 24px env(safe-area-inset-left); }
  main { width: min(420px, 100%); }
  h1 { font-size: 20px; margin: 0 0 8px; }
  p { margin: 0 0 20px; opacity: .72; }
  form { display: grid; gap: 12px; }
  input { font: inherit; padding: 14px 16px; border-radius: 12px;
          border: 1px solid color-mix(in srgb, CanvasText 22%, transparent); background: Field; color: FieldText; }
  button { font: inherit; padding: 14px 16px; border-radius: 12px; border: 0;
           background: #4d6bfe; color: #fff; font-weight: 600; }
  #msg { min-height: 1.5em; margin: 16px 0 0; font-size: 14px; opacity: .8; }
</style>
</head>
<body>
<main>
  <h1>DeepSeek Harness</h1>
  <p>输入电脑终端里 <code>dsh-lan-access</code> 打印的访问密钥，或直接扫描/打开带 <code>?k=</code> 的链接。</p>
  <form id="pair">
    <input id="key" type="password" inputmode="text" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="访问密钥" required>
    <button type="submit">连接</button>
  </form>
  <p id="msg" role="status"></p>
</main>
<script>
  const form = document.getElementById('pair')
  const key = document.getElementById('key')
  const msg = document.getElementById('msg')
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    msg.textContent = '连接中…'
    try {
      const response = await fetch('${PAIR_PATH}', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ key: key.value })
      })
      if (!response.ok) { msg.textContent = '密钥不正确或尝试过于频繁'; return }
      location.replace('/')
    } catch {
      msg.textContent = '网络错误，请重试'
    }
  })
</script>
</body>
</html>
`

/** First non-internal IPv4 address, or undefined on a host without a LAN. */
function pickLanAddress() {
  for (const list of Object.values(networkInterfaces())) {
    for (const iface of list ?? []) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address
    }
  }
  return undefined
}

/** Parse a Cookie header into a plain object; values are URI-decoded. */
function parseCookies(header) {
  const out = {}
  if (typeof header !== 'string') return out
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index < 0) continue
    const key = part.slice(0, index).trim()
    if (key === '') continue
    try {
      out[key] = decodeURIComponent(part.slice(index + 1).trim())
    } catch {
      out[key] = ''
    }
  }
  return out
}

/** Constant-time string comparison that never throws on length mismatch. */
function safeEqual(a, b) {
  const left = Buffer.from(String(a))
  const right = Buffer.from(String(b))
  return left.length === right.length && crypto.timingSafeEqual(left, right)
}

function sign(key, expiry) {
  return crypto.createHmac('sha256', key).update(String(expiry)).digest('base64url')
}

/** `expiry.signature` — stateless session value, no server-side store. */
function mintSession(key, ttlMs) {
  const expiry = Date.now() + ttlMs
  return `${expiry}.${sign(key, expiry)}`
}

function verifySession(key, value) {
  if (typeof value !== 'string') return false
  const dot = value.indexOf('.')
  if (dot <= 0) return false
  const expiry = Number(value.slice(0, dot))
  if (!Number.isFinite(expiry) || expiry < Date.now()) return false
  return safeEqual(value.slice(dot + 1), sign(key, expiry))
}

/**
 * Copy request headers for the upstream hop: drop browser-fence markers and
 * hop-by-hop fields, then force Host to the loopback authority the `/api`
 * fence accepts. Upgrade requests keep Connection/Upgrade so the handshake
 * can complete.
 */
function upstreamHeaders(headers, upstreamPort, { upgrade = false } = {}) {
  const out = {}
  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase()
    if (lower === 'origin' || lower === 'referer' || lower.startsWith('sec-fetch-')) continue
    if (!upgrade && HOP_BY_HOP.has(lower)) continue
    out[name] = value
  }
  out.host = `127.0.0.1:${upstreamPort}`
  return out
}

/** Strip hop-by-hop fields from an upstream response before writing it out. */
function downstreamHeaders(headers) {
  const out = {}
  for (const [name, value] of Object.entries(headers)) {
    if (HOP_BY_HOP.has(name.toLowerCase())) continue
    out[name] = value
  }
  return out
}

/** `/api/<method>` names a privileged RPC method the relay may refuse. */
function blockedApiMethod(pathname, enabled) {
  if (!enabled) return false
  if (!pathname.startsWith('/api/')) return false
  return PRIVILEGED_METHODS.has(pathname.slice('/api/'.length))
}

async function readJsonBody(request, limit) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.length
    if (size > limit) throw new Error('request body too large')
    chunks.push(chunk)
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'))
}

/**
 * Start the relay.
 *
 * @param {object} options
 * @param {string} options.upstreamHost - upstream bind host (loopback literal).
 * @param {number} options.upstreamPort - upstream Web server port.
 * @param {string} [options.host] - relay bind host.
 * @param {number} [options.port] - relay port; 0 picks a free one.
 * @param {string} [options.token] - static access key; generated when absent.
 * @param {number} [options.sessionTtlMs] - cookie lifetime.
 * @param {boolean} [options.blockPrivileged] - when true, refuse settings /
 *   credentials / native-dialog RPCs. Default false: the phone is a remote
 *   window onto the same harness, so it needs the same RPC plane.
 * @param {(message: string) => void} [options.log] - boot logger.
 * @returns {Promise<{ port: number, url: string, accessKey: string, close: () => Promise<void> }>}
 */
export function startRelay(options) {
  const {
    upstreamHost = '127.0.0.1',
    upstreamPort,
    host = '0.0.0.0',
    port = 8790,
    token,
    sessionTtlMs = 30 * 24 * 60 * 60 * 1000,
    blockPrivileged = false,
    log = () => {}
  } = options

  if (!Number.isInteger(upstreamPort) || upstreamPort <= 0) {
    return Promise.reject(new Error('relay: upstreamPort must be a listening port number'))
  }

  const accessKey = token ?? crypto.randomBytes(24).toString('base64url')
  const attempts = new Map()

  const cookieHeader = () =>
    `${COOKIE_NAME}=${encodeURIComponent(mintSession(accessKey, sessionTtlMs))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(sessionTtlMs / 1000)}`

  const isAuthed = (request) => verifySession(accessKey, parseCookies(request.headers.cookie)[COOKIE_NAME])

  const allowAttempt = (address) => {
    const now = Date.now()
    const list = (attempts.get(address) ?? []).filter((at) => now - at < RATE_WINDOW_MS)
    list.push(now)
    attempts.set(address, list)
    return list.length <= RATE_MAX_ATTEMPTS
  }

  const proxy = (request, response) => {
    const upstream = http.request(
      {
        host: upstreamHost,
        port: upstreamPort,
        method: request.method,
        path: request.url,
        headers: upstreamHeaders(request.headers, upstreamPort)
      },
      (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, downstreamHeaders(upstreamResponse.headers))
        upstreamResponse.pipe(response)
      }
    )
    upstream.on('error', () => {
      if (!response.headersSent) response.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('relay upstream error')
    })
    request.pipe(upstream)
  }

  const handleUpgrade = (request, socket, head) => {
    let pathname = '/'
    try {
      pathname = new URL(request.url ?? '/', 'http://relay').pathname
    } catch {
      /* keep the default */
    }
    if (!isAuthed(request) || blockedApiMethod(pathname, blockPrivileged)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    // Replay the handshake with the original header names/order (Node's parsed
    // `headers` map drops duplicates and lowercases keys). The `/api` fence
    // only needs Host rewritten to loopback and Origin/Sec-Fetch-* stripped.
    socket.pause()
    const upstream = net.connect(upstreamPort, upstreamHost, () => {
      const skip = new Set(['host', 'origin', 'referer'])
      let raw = `${request.method} ${request.url} HTTP/1.1\r\n`
      const pairs = request.rawHeaders
      for (let i = 0; i < pairs.length; i += 2) {
        const name = pairs[i]
        const lower = name.toLowerCase()
        if (skip.has(lower) || lower.startsWith('sec-fetch-')) continue
        raw += `${name}: ${pairs[i + 1]}\r\n`
      }
      raw += `Host: 127.0.0.1:${upstreamPort}\r\n\r\n`
      upstream.write(raw)
      if (head?.length) upstream.write(head)
      upstream.pipe(socket)
      socket.pipe(upstream)
      socket.resume()
    })
    upstream.on('error', () => socket.destroy())
    socket.on('error', () => upstream.destroy())
  }

  const handleRequest = async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://relay')
    const pathname = url.pathname
    const address = request.socket.remoteAddress ?? 'unknown'

    // Enrollment link: /?k=<key> mints the cookie and strips the key.
    const key = url.searchParams.get('k')
    if (key !== null) {
      if (!allowAttempt(address)) {
        response.writeHead(429, { 'content-type': 'text/plain; charset=utf-8' })
        response.end('too many attempts')
        return
      }
      if (!safeEqual(key, accessKey)) {
        response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
        response.end('invalid key')
        return
      }
      response.writeHead(302, { location: pathname === PAIR_PATH ? '/' : pathname, 'set-cookie': cookieHeader() })
      response.end()
      return
    }

    if (pathname === PAIR_PATH && request.method === 'POST') {
      if (!allowAttempt(address)) {
        response.writeHead(429, { 'content-type': 'text/plain; charset=utf-8' })
        response.end('too many attempts')
        return
      }
      try {
        const body = await readJsonBody(request, MAX_BODY_BYTES)
        if (typeof body?.key === 'string' && safeEqual(body.key, accessKey)) {
          response.writeHead(204, { 'set-cookie': cookieHeader() })
          response.end()
          return
        }
      } catch {
        /* falls through to 401 */
      }
      response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('invalid key')
      return
    }

    if (!isAuthed(request)) {
      if (pathname.startsWith('/api/')) {
        response.writeHead(401, { 'content-type': 'application/json; charset=utf-8' })
        response.end('{"error":"unauthorized"}')
        return
      }
      if (request.method === 'GET' && (pathname === '/' || !pathname.includes('.'))) {
        response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
        response.end(PAIR_PAGE)
        return
      }
      response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('unauthorized')
      return
    }

    if (blockedApiMethod(pathname, blockPrivileged)) {
      response.writeHead(403, { 'content-type': 'application/json; charset=utf-8' })
      response.end('{"error":"forbidden-on-mobile-relay"}')
      return
    }

    proxy(request, response)
  }

  const server = http.createServer((request, response) => {
    handleRequest(request, response).catch(() => {
      if (!response.headersSent) response.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' })
      response.end('relay error')
    })
  })
  server.on('upgrade', handleUpgrade)

  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => {
      const boundPort = server.address().port
      const displayHost = pickLanAddress() ?? '127.0.0.1'
      const url = `http://${displayHost}:${boundPort}/?k=${encodeURIComponent(accessKey)}`
      log(`手机访问入口: ${url}`)
      log(`这是当前 dsh web 的远程窗口（cwd=${process.cwd()}），不是独立实例；会话/工作区与本机浏览器相同`)
      log(`仅限可信局域网；公网请使用 Tailscale / Cloudflare Tunnel，并保留 dsh 的 127.0.0.1 绑定`)
      resolve({
        port: boundPort,
        url,
        accessKey,
        close: () => new Promise((done) => server.close(() => done()))
      })
    })
  })
}

export { PAIR_PATH, PRIVILEGED_METHODS }
