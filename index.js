/**
 * dsh-auth-cookie-guard — Host half.
 *
 * Why this plugin exists
 * ----------------------
 * The desktop shell starts the Host with `--port 0`, so the Web listener gets a
 * fresh OS-assigned port on every launch. `dsh-client-connection` binds the
 * browser session cookie to `host:port`:
 *
 *   cookieName(authority) = 'dsh-auth-' + base64url(sha256(authority))
 *   authority             = '127.0.0.1:<port>'
 *   Max-Age               = cookieMaxAgeDays (default 30 days)
 *
 * Cookies are scoped by host, not by port, so every launch mints one more
 * `dsh-auth-…` cookie for 127.0.0.1 and never removes the ones from previous
 * ports. Chromium sends them all in one `Cookie` header, and Node's HTTP server
 * caps the request header block at `maxHeaderSize` = 16384 bytes. One cookie is
 * roughly 225 bytes of header, so after ~71 launches the navigation request is
 * rejected by the HTTP parser with HPE_HEADER_OVERFLOW and the window fails to
 * load the application ("打不开").
 *
 * What the guard does
 * -------------------
 * 1. Reap — every response produced by `browserAuth.authorizeIndex/authorizeConnect`
 *    (which dsh-host-frontend-static calls for the index and every static asset)
 *    carries `Set-Cookie: …=; Max-Age=0` for each `dsh-auth-` cookie that is not
 *    bound to the current authority. The jar collapses back to one cookie per
 *    launch instead of growing without bound.
 * 2. Recover — if a jar is already past the limit, the request never reaches the
 *    Host as a parsed request. Node still emits `clientError` with
 *    `HPE_HEADER_OVERFLOW` and `err.rawPacket` (the truncated request bytes),
 *    which contain the cookie names and the original request target. The guard
 *    answers with `303 See Other` to the same target plus one expiry per parsed
 *    cookie name; the browser drops those cookies and retries, so a jammed
 *    profile heals itself on the next launch without any manual cache clearing.
 *
 * The guard is defensive: it never throws into the request path, restores the
 * methods it wrapped when it is disposed, and degrades to a no-op when the
 * internal shape of the connection service changes.
 */

import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const name = 'auth-cookie-guard'

export const inject = ['connection', 'webServer']

/** Same literal as COOKIE_PREFIX in dsh-client-connection. */
const COOKIE_PREFIX = 'dsh-auth-'
/** `dsh-auth-` followed by the 43 characters of base64url(sha256(authority)). */
const COOKIE_NAME_LENGTH = COOKIE_PREFIX.length + 43
const COOKIE_NAME_PATTERN = /dsh-auth-[A-Za-z0-9_-]{43}/g
const EXPIRED_DATE = 'Thu, 01 Jan 1970 00:00:00 GMT'
/**
 * Hysteresis: only reap once the jar holds more than this many guard cookies.
 * A single desktop launch settles at one, so the surplus only ever comes from
 * repeated launches; the margin keeps a second Harness instance that shares the
 * same DSH_HOME (its own authority-bound cookie) alive instead of logging it out.
 */
const REAP_ABOVE = 4
const ARMED = Symbol.for('dsh.auth-cookie-guard.armed')
const WRAPPED = Symbol.for('dsh.auth-cookie-guard.wrapped')

const state = {
  startedAt: new Date().toISOString(),
  reaped: 0,
  reapEvents: 0,
  overflowRepairs: 0,
  maxJarSeen: 0,
  lastEvent: undefined,
  errors: 0,
}

let flushTimer

function dshHome() {
  const configured = process.env.DSH_HOME
  if (typeof configured === 'string' && configured.length > 0) return configured
  return join(homedir(), '.dsh')
}

function readAudience(hostHeader, secure) {
  if (typeof hostHeader !== 'string' || hostHeader.length === 0) return undefined
  try {
    const url = new URL(`${secure ? 'https:' : 'http:'}//${hostHeader}`)
    return { authority: secure ? url.origin : url.host, hostname: url.hostname }
  } catch {
    return undefined
  }
}

function cookieNameFor(authority) {
  return COOKIE_PREFIX + createHash('sha256').update(authority).digest('base64url')
}

function isGuardCookie(name) {
  return typeof name === 'string' && name.length === COOKIE_NAME_LENGTH && name.startsWith(COOKIE_PREFIX)
}

function cookieNamesOf(headerValue) {
  if (typeof headerValue !== 'string' || headerValue.length === 0) return []
  const names = []
  for (const segment of headerValue.split(';')) {
    const at = segment.indexOf('=')
    const name = (at === -1 ? segment : segment.slice(0, at)).trim()
    if (isGuardCookie(name)) names.push(name)
  }
  return names
}

function expiryCookie(name, secure) {
  // A Secure cookie can only be replaced by a Secure expiry cookie, so mirror
  // the listener's scheme; the rest of the attributes match the original one.
  const attributes = `${name}=; Max-Age=0; Path=/; Expires=${EXPIRED_DATE}; SameSite=Strict`
  return secure ? `${attributes}; Secure` : attributes
}

function mergeSetCookie(headers, cookies) {
  if (Array.isArray(headers)) {
    const raw = headers.slice()
    for (const cookie of cookies) raw.push('set-cookie', cookie)
    return raw
  }
  if (headers === undefined || headers === null) return { 'set-cookie': cookies.slice() }
  const copy = {}
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === 'set-cookie') continue
    copy[key] = value
  }
  const existing = headers['set-cookie'] ?? headers['Set-Cookie']
  copy['set-cookie'] = existing === undefined
    ? cookies.slice()
    : [...(Array.isArray(existing) ? existing : [existing]), ...cookies]
  return copy
}

/** Attach expiry cookies to whatever `res.writeHead` call the auth path makes. */
function armResponse(response, cookies) {
  const armed = response[ARMED]
  if (armed !== undefined) {
    armed.push(...cookies)
    return
  }
  const list = [...cookies]
  response[ARMED] = list
  const original = response.writeHead
  response.writeHead = function patchedWriteHead(statusCode, reasonOrHeaders, maybeHeaders) {
    try {
      const [reason, headers] = typeof reasonOrHeaders === 'string'
        ? [reasonOrHeaders, maybeHeaders]
        : [undefined, reasonOrHeaders]
      const merged = mergeSetCookie(headers, list)
      return reason === undefined
        ? original.call(this, statusCode, merged)
        : original.call(this, statusCode, reason, merged)
    } catch {
      return original.apply(this, arguments)
    }
  }
}

function record(event) {
  state.lastEvent = event
  if (event.kind === 'reap') {
    state.reapEvents += 1
    state.reaped += event.count
  } else if (event.kind === 'overflow-repair') {
    state.overflowRepairs += 1
  } else if (event.kind === 'error') {
    state.errors += 1
  }
  if (typeof event.jar === 'number' && event.jar > state.maxJarSeen) state.maxJarSeen = event.jar
  if (flushTimer !== undefined) return
  flushTimer = setTimeout(() => {
    flushTimer = undefined
    try {
      const directory = join(dshHome(), 'auth-cookie-guard')
      mkdirSync(directory, { recursive: true })
      writeFileSync(
        join(directory, 'state.json'),
        `${JSON.stringify({ ...state, pid: process.pid, storedAt: new Date().toISOString() }, null, 2)}\n`,
        'utf8',
      )
    } catch {
      /* diagnostics are best-effort */
    }
  }, 1500)
  flushTimer.unref?.()
}

function requestTargetOf(raw) {
  const match = /^[A-Za-z]+ (\S+) HTTP\//.exec(raw)
  const target = match?.[1]
  return target !== undefined && target.startsWith('/') ? target : '/'
}

function hostHeaderOf(raw) {
  const match = /\r\nHost: *([^\r\n]+)/i.exec(raw)
  return match?.[1]?.trim()
}

export function apply(ctx) {
  const connection = ctx.get('connection') ?? ctx.connection
  const webServer = ctx.get('webServer') ?? ctx.webServer
  const logger = ctx.logger

  if (webServer?.server === undefined || typeof webServer.server.on !== 'function') {
    logger?.warn?.('[auth-cookie-guard] web server unavailable; guard inactive')
    return
  }

  const auth = connection?.browserAuth
  if (auth === undefined || typeof auth.authorizeIndex !== 'function') {
    logger?.warn?.('[auth-cookie-guard] connection.browserAuth unavailable; guard inactive')
    return
  }
  if (auth[WRAPPED] === true) {
    logger?.info?.('[auth-cookie-guard] already installed on this connection; skipping')
    return
  }

  const secureNow = () => (ctx.get('webServer')?.protocol ?? 'http:') === 'https:'

  let origin
  try {
    origin = webServer.getOrigin?.()
  } catch {
    origin = undefined
  }
  /** Bind host of this listener; only same-host requests are allowed to reap. */
  const listenerHost = (() => {
    try {
      return origin === undefined ? undefined : new URL(origin).hostname
    } catch {
      return undefined
    }
  })()

  const reap = (req, res, where) => {
    try {
      const header = req?.headers?.cookie
      const names = cookieNamesOf(header)
      if (names.length <= REAP_ABOVE) return
      const secure = secureNow()
      const audience = readAudience(req?.headers?.host, secure)
      if (audience === undefined) return
      if (listenerHost !== undefined && audience.hostname !== listenerHost) return
      const current = cookieNameFor(audience.authority)
      const stale = [...new Set(names.filter((cookie) => cookie !== current))]
      if (stale.length === 0) return
      armResponse(res, stale.map((cookie) => expiryCookie(cookie, secure)))
      record({ kind: 'reap', where, count: stale.length, jar: names.length, authority: audience.authority })
    } catch (error) {
      record({ kind: 'error', where, message: String(error?.message ?? error) })
      logger?.warn?.(`[auth-cookie-guard] reap failed: ${String(error?.message ?? error)}`)
    }
  }

  const originalAuthorizeIndex = auth.authorizeIndex
  const originalAuthorizeConnect = auth.authorizeConnect

  auth.authorizeIndex = function guardAuthorizeIndex(req, res, secure) {
    reap(req, res, 'index')
    return originalAuthorizeIndex.call(this, req, res, secure)
  }
  if (typeof originalAuthorizeConnect === 'function') {
    auth.authorizeConnect = function guardAuthorizeConnect(req, res, secure, publish) {
      reap(req, res, 'connect')
      return originalAuthorizeConnect.call(this, req, res, secure, publish)
    }
  }
  auth[WRAPPED] = true

  let overflowStreak = 0
  const limit = 32

  const onClientError = (error, socket) => {
    try {
      if (socket === undefined || socket === null || socket.destroyed === true) return
      const code = String(error?.code ?? '')
      const raw = typeof error?.rawPacket?.toString === 'function' ? error.rawPacket.toString('latin1') : ''
      const names = [...new Set(raw.match(COOKIE_NAME_PATTERN) ?? [])]
      const secure = secureNow()
      const audience = readAudience(hostHeaderOf(raw), secure)
      const current = audience === undefined ? undefined : cookieNameFor(audience.authority)
      const stale = names.filter((cookie) => cookie !== current)
      const overflowing = code === 'HPE_HEADER_OVERFLOW'

      if (overflowing && stale.length > 0 && overflowStreak < limit) {
        overflowStreak += 1
        const target = requestTargetOf(raw)
        record({
          kind: 'overflow-repair',
          count: stale.length,
          jar: names.length,
          target,
          streak: overflowStreak,
          authority: audience?.authority,
        })
        logger?.warn?.(`[auth-cookie-guard] recovered oversized request header (${stale.length} cookies, hop ${overflowStreak})`)
        const head = [
          'HTTP/1.1 303 See Other',
          `Location: ${target}`,
          'Cache-Control: no-store',
          'Referrer-Policy: no-referrer',
          'Connection: close',
          'Content-Length: 0',
          ...stale.map((cookie) => `Set-Cookie: ${expiryCookie(cookie, secure)}`),
          '',
          '',
        ].join('\r\n')
        socket.end(head)
        return
      }

      const status = overflowing ? '431 Request Header Fields Too Large' : '400 Bad Request'
      socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`)
    } catch (failure) {
      record({ kind: 'error', where: 'clientError', message: String(failure?.message ?? failure) })
      try {
        socket.destroy()
      } catch {
        /* socket already gone */
      }
    }
  }

  const onRequestSettled = () => {
    overflowStreak = 0
  }

  webServer.server.on('clientError', onClientError)
  webServer.server.on('request', onRequestSettled)

  ctx.effect(() => () => {
    webServer.server.off('clientError', onClientError)
    webServer.server.off('request', onRequestSettled)
    if (auth[WRAPPED] === true) {
      auth.authorizeIndex = originalAuthorizeIndex
      if (typeof originalAuthorizeConnect === 'function') auth.authorizeConnect = originalAuthorizeConnect
      delete auth[WRAPPED]
    }
  }, 'auth-cookie-guard: cookie reaper')

  logger?.info?.('[auth-cookie-guard] active: reaping stale dsh-auth- cookies per request')
  record({ kind: 'start', port: webServer.listenedPort, authority: origin })
}
