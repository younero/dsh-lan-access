/** dsh LAN port-forwarding plugin. */
import { startRelay } from './relay.js'

export const name = 'dsh-lan-access'
export const inject = ['webServer']

// The relay is a window onto the same local dsh process. Without this small
// bootstrap, dsh sees the LAN hostname and switches its client connection to
// remote-browser mode, which hides the local workspace/settings plane.
const LOOPBACK_BOOT = `<script>
(function () {
  if (window.__dshLanForwardingBoot) return
  window.__dshLanForwardingBoot = true
  // crypto.randomUUID() is unavailable on ordinary HTTP LAN origins. dsh
  // uses it when creating the folder picker request, so provide the same
  // UUID v4 shape through the still-available getRandomValues primitive.
  try {
    if (window.crypto && typeof window.crypto.randomUUID !== 'function' && typeof window.crypto.getRandomValues === 'function') {
      var randomUUID = function () {
          var bytes = new Uint8Array(16)
          window.crypto.getRandomValues(bytes)
          bytes[6] = (bytes[6] & 15) | 64
          bytes[8] = (bytes[8] & 63) | 128
          var hex = Array.from(bytes, function (byte) { return byte.toString(16).padStart(2, '0') }).join('')
          return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20)
      }
      try { Object.defineProperty(window.crypto, 'randomUUID', { configurable: true, value: randomUUID }) }
      catch (_) { window.crypto.randomUUID = randomUUID }
    }
  } catch (_) {}
  var loader
  function patchRegistration(registration) {
    if (!registration || registration.id !== '@deepseek-ai/dsh-client-connection') return registration
    var factory = registration.factory
    if (typeof factory !== 'function') return registration
    return {
      id: registration.id,
      factory: function (require) {
        var exports = factory(require)
        var apply = exports && exports.apply
        if (typeof apply !== 'function') return exports
        exports.apply = function (ctx, config) {
          var provide = ctx.provide
          if (typeof provide === 'function') {
            ctx.provide = function (name, handle) {
              if (name === 'connection' && handle && typeof handle === 'object') {
                try { handle.isLoopback = true } catch (_) {}
              }
              return provide.apply(this, arguments)
            }
          }
          try { return apply.call(this, ctx, config) }
          finally { if (provide) ctx.provide = provide }
        }
        return exports
      }
    }
  }
  function patch(value) {
    if (!value || typeof value.load !== 'function' || value.__dshLanForwardingPatched) return value
    var load = value.load.bind(value)
    value.load = function (registration) { return load(patchRegistration(registration)) }
    value.__dshLanForwardingPatched = true
    return value
  }
  try {
    Object.defineProperty(window, '__ModuleLoader__', {
      configurable: true,
      get: function () { return loader },
      set: function (value) { loader = patch(value) }
    })
  } catch (_) { patch(window.__ModuleLoader__) }
})()
</script>`

// Keep mobile styling in a scoped, additive layer. It only targets semantic
// data-slot/role attributes that DSH already uses, so generated class names or
// component internals can change without making this patch brittle.
const MOBILE_STYLE = `<style id="dsh-lan-access-mobile">
@media (max-width: 820px) {
  :root {
    --dsh-lan-edge: max(12px, env(safe-area-inset-left));
    --dsh-lan-edge-right: max(12px, env(safe-area-inset-right));
  }
  html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
  body { overscroll-behavior-x: none; }
  [data-slot="conversation"] input,
  [data-slot="conversation"] textarea { font-size: 16px; }
  [data-slot="conversation"] button,
  [data-slot="sidebar"] button { min-height: 36px; touch-action: manipulation; }
  [data-slot="conversation"],
  [data-slot="sidebar"] { -webkit-tap-highlight-color: transparent; }
  [data-slot="conversation"] [data-phase] { gap: 6px; }
  [data-slot="conversation"] pre,
  [data-slot="conversation"] code { max-width: 100%; overflow-x: auto; }
  [data-slot="conversation"] pre { font-size: 12px; }
  [data-composer-card] { max-width: calc(100vw - var(--dsh-lan-edge) - var(--dsh-lan-edge-right)); }
  [role="dialog"][aria-modal="true"] {
    max-width: 100vw;
    max-height: 100dvh;
    margin: 0;
  }
  [role="dialog"][aria-modal="true"] input,
  [role="dialog"][aria-modal="true"] textarea { font-size: 16px; }
}
</style>`

function injectLoopbackBoot(html) {
  return html.replace(/<head[^>]*>/i, (open) => `${open}\n${LOOPBACK_BOOT}\n${MOBILE_STYLE}`)
}

function normalizeConfig(config) {
  const raw = config && typeof config === 'object' ? config : {}
  return {
    enabled: raw.enabled === true,
    host: typeof raw.host === 'string' && raw.host ? raw.host : '0.0.0.0',
    port: Number.isInteger(raw.port) ? raw.port : 8790,
    token: typeof raw.token === 'string' && raw.token ? raw.token : undefined,
    blockPrivileged: raw.blockPrivileged === true,
    sessionTtlMs: Number.isFinite(raw.sessionTtlMs) && raw.sessionTtlMs > 0
      ? raw.sessionTtlMs
      : 30 * 24 * 60 * 60 * 1000
  }
}

export function apply(ctx, config) {
  const options = normalizeConfig(config)
  if (!options.enabled) return

  ctx.effect(
    () => ctx.webServer.tapIndex(injectLoopbackBoot),
    'dsh-lan-access: local connection compatibility'
  )

  let disposed = false
  let relay
  ctx.effect(() => {
    startRelay({
      upstreamHost: '127.0.0.1',
      upstreamPort: ctx.webServer.port,
      host: options.host,
      port: options.port,
      token: options.token,
      blockPrivileged: options.blockPrivileged,
      sessionTtlMs: options.sessionTtlMs,
      log: (message) => console.log(`dsh-lan-access: ${message}`)
    }).then((started) => {
      if (disposed) started.close()
      else relay = started
    }).catch((error) => {
      console.error(`dsh-lan-access: relay failed to start: ${error instanceof Error ? error.message : String(error)}`)
    })
    return () => {
      disposed = true
      return relay?.close()
    }
  }, 'dsh-lan-access: LAN port forwarding')
}

export { normalizeConfig }
