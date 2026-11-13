# Rust port: architecture

Status: proposal, 2026-11-13. Priorities (operator): stable, correct and secure first; then every QoL feature that is genuinely useful. Target: feature parity with Java 2.1.0, then the fork brief's fixes (S1-S13 as design rules) and features F1-F5.

## Shape

One binary, `clamv-webui`, in a Cargo workspace:

| Crate | Role |
|---|---|
| `crates/clamd` | Async clamd protocol client (TCP and Unix socket). PING, VERSION, STATS, RELOAD, SCAN/CONTSCAN, INSTREAM. Replaces the Java `clamav-client` 2.1.2 dependency. Hard limits on stream size, chunk size, connect/read timeouts. |
| `crates/server` | Web UI, REST API v1, auth, jobs, scheduler, watcher, webhooks, metrics. |

The Go `clamctl` CLI and MCP bridge in `cli/` stay as they are. The REST API v1 contract (`openapi/clamav-v1.yaml`) is kept so `clamctl` keeps working.

## Crates we depend on

| Need | Choice | Why |
|---|---|---|
| Runtime / HTTP | `tokio`, `axum`, `tower-http` | De-facto standard, small attack surface, no reflection magic. |
| Templates | `askama` | Compile-time checked templates; a typo fails the build, not a page. Thymeleaf pages are ported one by one. |
| Static assets | `rust-embed` | Existing Bootstrap, jQuery, xterm.js and CSS are reused and embedded in the binary. |
| i18n | `fluent` or a small `.properties` loader | The six existing `messages_*.properties` files are reused as-is. |
| Database | `sqlx` (compile-time checked queries, migrations) | See "Databases". |
| Passwords | `argon2` for new hashes, `bcrypt` to verify imported Java hashes and rehash on login | Upgrade path without forcing password resets. |
| Sessions / CSRF | `tower-sessions` (DB-backed store), own double-submit CSRF | SameSite=Strict, Secure configurable (S8). |
| OIDC | `openidconnect` | Issuer discovery, PKCE, nonce, exact redirect URI. |
| LDAP | `ldap3` | Filter values escaped with `ldap3::ldap_escape` (closes the injection question). |
| Secrets at rest | `aes-gcm` | Same model as Java's `auth-settings.key`. |
| Cron | `croner` | Parses cron, gives "next 3 runs" for the preview (F1). Own tokio scheduler loop on top. |
| Watcher | `notify` plus periodic rescan | Limits configurable, processed files not counted (functional fix 1). |
| Webhooks | `reqwest` (rustls) with a custom resolver | Resolve once, check against policy + CIDR allowlist, connect to that IP: no DNS rebinding. |
| Metrics | `prometheus-client` | Token compared in constant time (`subtle`). |
| Logging | `tracing`, `tracing-subscriber` | INFO default, no ANSI, `LOG_FORMAT=json` option (S11). Every alert-worthy event is a log line for LogTide. |
| clamdtop | `portable-pty` + axum WebSocket | Optional, OPERATOR+, off by default (S6). |
| TLS | `rustls` only | No OpenSSL in the image. |

## Databases

Rust has no H2 driver. Supported: **SQLite (default, replaces H2), PostgreSQL, MySQL and MariaDB** (operator decision, 2026-11-13). `sqlx` covers all four (MariaDB via the MySQL driver). Each database gets its own migration folder (`migrations/{sqlite,postgres,mysql}`, MariaDB shares MySQL's unless a difference forces a split) and a repository layer behind a trait, so queries stay compile-time checked per backend. CI runs the DB test suite against SQLite plus Postgres, MySQL and MariaDB service containers. Existing H2 data is not imported automatically; a one-off `clamv-webui import-h2 <export.sql>` can be added if the NAS install has history worth keeping.

## Security design rules (from brief section 2)

- S1: `X-Forwarded-*` ignored unless `TRUST_PROXY_CIDRS` is set; client IP is the socket peer.
- S2: no HTTP Basic on the UI. API uses bearer tokens only. Lockout covers every credential check.
- S3: uploads streamed to clamd via INSTREAM; nothing written to disk when quarantine is off. Default upload cap 256 MB.
- S4: `/setup` exists only until first admin is created; `SETUP_CONSOLE=false` removes it entirely.
- S5/S9: one `ScanRoots` type: canonicalises (`realpath`) on save and on use, returns one generic "not allowed" error.
- S7: CSP, Referrer-Policy, Permissions-Policy, X-Content-Type-Options, frame-ancestors on every response.
- S10: optional `CLAMD_HOST_ALLOWLIST`.
- S12: no unused deps; `cargo deny` checks advisories and licences in CI.
- S13: `/healthz` unauthenticated; image runs with `read_only: true`, writes only to `/app/data` and tmpfs `/tmp`; `HEALTHCHECK` uses the binary itself (no curl in the image).
- No H2 console, no actuator: `/metrics` is the only management endpoint.

## Image

`rust:1-bookworm` builder, `gcr.io/distroless/cc-debian12:nonroot` runtime, UID 10001 (same as the Java image). No shell, no package manager, no clamav-daemon. clamdtop needs the ncurses `clamdtop` binary, so it ships as a separate `:latest-clamdtop` variant later, if wanted.

## Agents (after parity)

Like Arcane's Docker agents: one central UI manages lightweight agents on other hosts, each next to its own clamd and storage.

- **Same binary.** `clamv-webui agent` runs headless: no UI, no database, no users. It owns its clamd and its scan roots.
- **Agent dials out.** The agent opens a WebSocket to the central server and keeps it open. Agent hosts need no inbound port, and NAT is fine. Central marks an agent offline when the connection drops.
- **Mutual auth.**
  1. An admin creates an agent in the UI and gets a one-time enrollment token (short expiry, stored hashed) plus the central TLS fingerprint.
  2. `clamv-webui agent enroll --server https://central:8443 --token … --fingerprint sha256:…` generates an Ed25519 key on the agent, sends the public key, and pins central's certificate.
  3. After that, every connection is mTLS on a dedicated agent port: central pins the agent key, the agent pins central's cert. The token cannot be reused. Revoking an agent deletes its key.
  The agent port always uses TLS, even on a private mesh, so a compromised mesh peer cannot impersonate either side.
- **Agent enforces its own limits.** Central only sends typed requests (ping, version, stats, scan these paths, cancel job). The agent checks every path against its own local `SCAN_ROOTS` with `realpath`, so a compromised central cannot make it scan, read or move anything outside them. File contents never leave the agent; only verdicts, detections and progress do. Quarantine, if ever enabled, is an agent-local setting.
- **Schedules live centrally.** Central stores schedules, picks the agent, and records results. If the agent is offline at run time, the run is logged as missed (a log line, so LogTide alerts) and retried at the next window.
- **Logging.** Agents log locally as JSON lines too, so fluent-bit on each host can ship them.
- **Protocol.** Versioned JSON messages over WebSocket (`v1`), with request ids, heartbeats and backpressure. Central refuses agents with an incompatible protocol version and shows "update agent" in the UI.

The scheduler and job code are written from the start against an `Executor` trait (local clamd or remote agent), so agents slot in without reworking F1.

## Licensing

This is a translation of LGPL-2.1-or-later code, so the port is a derivative work and stays **LGPL-2.1-or-later**. Root `LICENSE` holds the LGPL-2.1 text; `NOTICE` credits Kosztyk (clamv-webui) and rguziy (clamav-web-client). Since the whole program's source is published under the LGPL, static linking in Rust raises no relinking issue. All Rust deps must be LGPL-compatible (MIT, Apache-2.0, BSD, ISC, MPL-2.0, Zlib, Unicode); `deny.toml` enforces it. Vendored front-end assets keep their own MIT licences.

Consequence: security fixes can no longer go upstream as small Java PRs from this branch. Upstream reports, if wanted, have to be written separately against the Java code.

## Repository layout during the port

The Rust workspace lives at the repo root next to the Java code until parity. Java sources, `pom.xml` and the Java Dockerfile are removed in the PR that reaches parity. Until then `Dockerfile` builds the Rust binary, and CI pushes images only from `main`, so nothing replaces `:latest` before the port is merged.

## Order of work

1. Scaffold, CI, image, compose (this PR).
2. clamd client + endpoints + dashboard (PING/VERSION/STATS).
3. Auth: local users, sessions, CSRF, lockout, API tokens, roles.
4. Scan jobs: upload (INSTREAM) and path scans, job list, detections, audit log.
5. Scheduled scans + EICAR control (F1, F2).
6. Watcher, webhooks, metrics.
7. Configuration Center, LDAP, OIDC, i18n, clamdtop.
8. Parity check against the feature inventory, delete Java.
9. Agents.
