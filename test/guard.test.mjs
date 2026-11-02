/**
 * Regression test for dsh-auth-cookie-guard.
 *
 * Boots a real `node:http` server, installs the plugin through a minimal stand-in
 * for the Cordis context, and drives real requests through it. No test runner and
 * no dependencies: `node test/guard.test.mjs` (or `npm test`).
 *
 * Optional first argument: path to the plugin entry, defaults to `../index.js`.
 */

import http from 'node:http'
import { createHash } from 'node:crypto'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const entry = pathToFileURL(resolve(here, process.argv[2] ?? '../index.js')).href

const results = []
function check(label, ok, detail) {
  results.push({ label, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail === undefined ? '' : `  — ${detail}`}`)
}

const PREFIX = 'dsh-auth-'
/** A syntactically valid guard cookie name that belongs to no real authority. */
const fakeName = (i) => PREFIX + String(i).padStart(43, 'x')
/** The name the plugin computes for a live authority: PREFIX + base64url(sha256(authority)). */
const currentName = (authority) => PREFIX + createHash('sha256').update(authority).digest('base64url')

const disposers = []

/** Minimal projection of the Cordis context this plugin touches. */
function makeCtx(server, origin) {
  const auth = {
    authorizeIndex(req, res) {
      res.writeHead(401, { 'content-type': 'text/plain' })
      res.end('unauthorized')
    },
    authorizeConnect(req, res) {
      res.writeHead(401)
      res.end()
    },
  }
  const services = {
    connection: { browserAuth: auth },
    webServer: {
      server,
      protocol: 'http:',
      listenedPort: Number(new URL(origin).port),
      getOrigin: () => origin,
    },
  }
  const ctx = {
    get: (key) => services[key],
    connection: services.connection,
    webServer: services.webServer,
    logger: { info() {}, warn() {}, error() {} },
    effect: (factory) => {
      disposers.push(factory())
    },
  }
  return { ctx, auth }
}

function request(port, { cookies = [], host } = {}) {
  return new Promise((done) => {
    const headers = {}
    if (cookies.length > 0) headers.cookie = cookies.join('; ')
    if (host !== undefined) headers.host = host
    const req = http.request({ port, host: '127.0.0.1', headers }, (res) => {
      let body = ''
      res.on('data', (chunk) => (body += chunk))
      res.on('end', () => done({
        status: res.statusCode,
        setCookie: res.headers['set-cookie'] ?? [],
        location: res.headers.location,
        body,
      }))
    })
    req.on('error', (error) => done({ error: String(error?.message ?? error), setCookie: [] }))
    req.end()
  })
}

const guard = await import(entry)

// --- reaper: threshold, live-cookie preservation, host guard ---------------
{
  const server = http.createServer()
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
  const port = server.address().port
  const authority = `127.0.0.1:${port}` // http authority carries no scheme
  const { ctx, auth } = makeCtx(server, `http://${authority}`)
  guard.apply(ctx)
  server.on('request', (req, res) => auth.authorizeIndex(req, res, false))

  const quiet = await request(port, { cookies: [fakeName(1), fakeName(2)] })
  check('jar=2 stays untouched (hysteresis)', quiet.status === 401 && quiet.setCookie.length === 0, `set-cookie=${quiet.setCookie.length}`)

  const live = currentName(authority)
  const noisy = await request(port, {
    cookies: [fakeName(1), fakeName(2), fakeName(3), fakeName(4), fakeName(5), live],
  })
  check('jar=6 reaps the 5 stale entries', noisy.setCookie.length === 5, `set-cookie=${noisy.setCookie.length}`)
  check('jar=6 keeps the live entry', !noisy.setCookie.some((cookie) => cookie.startsWith(`${live}=`)), `live=${live.slice(0, 20)}…`)
  check('expiry carries Max-Age=0 and the epoch date', noisy.setCookie.every((cookie) => cookie.includes('Max-Age=0') && cookie.includes('Expires=Thu, 01 Jan 1970')), noisy.setCookie[0])

  const foreign = await request(port, {
    cookies: [fakeName(1), fakeName(2), fakeName(3), fakeName(4), fakeName(5), fakeName(6)],
    host: `192.168.1.5:${port}`,
  })
  check('foreign Host header never reaps', foreign.setCookie.length === 0, `set-cookie=${foreign.setCookie.length}`)

  await new Promise((ok) => server.close(ok))
  for (const dispose of disposers.splice(0)) dispose()
  check('dispose restores the wrapped method', auth.authorizeIndex.name === 'authorizeIndex', auth.authorizeIndex.name)
}

// --- recovery: a jar that already overflowed the header limit --------------
{
  const server = http.createServer({ maxHeaderSize: 2048 })
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
  const port = server.address().port
  const { ctx, auth } = makeCtx(server, `http://127.0.0.1:${port}`)
  guard.apply(ctx)
  server.on('request', (req, res) => auth.authorizeIndex(req, res, false))

  const many = Array.from({ length: 40 }, (_, i) => fakeName(100 + i))
  const overflow = await request(port, { cookies: many })
  check('oversized header answers 303 instead of 431', overflow.status === 303, `status=${overflow.status} ${overflow.error ?? ''}`)
  check('recovery expires every parsed cookie name', overflow.setCookie.length === 40, `set-cookie=${overflow.setCookie.length}`)
  check('recovery redirects to the original target', overflow.location === '/', `location=${overflow.location}`)

  const healthy = await request(port, { cookies: [fakeName(7)] })
  check('listener still serves afterwards', healthy.status === 401, `status=${healthy.status}`)

  await new Promise((ok) => server.close(ok))
  for (const dispose of disposers.splice(0)) dispose()
}

const failed = results.filter((result) => !result.ok)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length === 0 ? 0 : 1)
