# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-11-02

### Added

- **Reaper** — wraps `connection.browserAuth.authorizeIndex` / `authorizeConnect`
  (reached by the index page and every static asset) and answers with
  `Set-Cookie: <name>=; Max-Age=0` for every `dsh-auth-*` cookie that is not bound
  to the current `host:port`, so the jar stops growing on every desktop launch.
- **Recovery** — listens for `clientError` + `HPE_HEADER_OVERFLOW`, parses the
  cookie names and the original request target out of `err.rawPacket`, and answers
  `303 See Other` with one expiry per cookie so a jammed profile heals on its own.
- **Safety bounds** — hysteresis (`REAP_ABOVE = 4`), only names actually present in
  the request are expired, only same-hostname authorities trigger a reap, and the
  expiry mirrors `Secure` for TLS listeners.
- **Diagnostics** — `$DSH_HOME/auth-cookie-guard/state.json` with `reaped`,
  `reapEvents`, `overflowRepairs`, `maxJarSeen`, `lastEvent`, `errors`.
- **Tests** — `npm test` boots real `node:http` servers and covers the threshold,
  live-cookie preservation, the foreign-host guard, the epoch expiry attributes,
  overflow recovery, and disposal.
