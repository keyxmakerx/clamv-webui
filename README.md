# ClamAV Web UI

A small, self-hosted web interface and API for [ClamAV](https://www.clamav.net/) `clamd`, written in Rust.
It scans uploads and server paths, runs scheduled and watched-folder scans, and keeps an audit trail. It never moves or deletes files.

Forked from an earlier Java application, which has been replaced entirely. Licensed under LGPL-2.1-or-later (see `LICENSE` and `NOTICE`).

## Features

- **Scans**: upload scans (in-memory stream to clamd), path scans limited to `SCAN_ROOTS`, job history with per-file results.
- **Schedules**: cron schedules per path. Each run first scans an EICAR control, so a run against a broken clamd reports a failure, not a clean result.
- **Watched folders**: new or changed files under a watched path are scanned automatically.
- **Agents**: run the same image with `agent` on other hosts. Each agent scans its own folders with its own clamd and reports back, so one UI covers every machine. Agents connect out to the server, so they need no open port.
- **Multiple clamd endpoints**, with a status page (signature age, threads, queue) and alerts when clamd goes down or signatures go stale.
- **Users and roles**: Viewer, Operator, Admin. Local accounts, OIDC single sign-on, and LDAP with roles taken from groups on every sign-in.
- **API** at `/api/v1` with personal tokens, used by the `clamctl` CLI and MCP server (`cli/`, `docs/CLI.md`, `docs/MCP.md`).
- **Webhooks** for alerts (any JSON receiver, or Discord), with SSRF protection.
- **Prometheus metrics** and Grafana dashboards (`dashboards/`).
- **Settings page** for the tunables that are not locked by environment variables, with a diff before applying.
- **Databases**: SQLite (default), PostgreSQL, MySQL, MariaDB.
- **Structured logs**: every audit event and alert is also a log line (`LOG_FORMAT=json` for log shippers).

## Quick start

`docker-compose.yml` runs the UI with its own `clamav/clamav` container. Put files to scan in `./scan`.

```sh
docker compose up -d
```

Open http://localhost:8080. On first start an `admin` account is created with a generated password, written to `data/bootstrap-admin-password`. Open that file on the host, sign in, then delete the file.

To use a clamd you already run, use `docker-compose.external-clamd.yml`. It joins an existing Docker network, mounts scan roots read-only, and lists optional webhook, metrics, OIDC and LDAP settings as comments. For agents on other hosts, see [Agents](#agents).

Lost the admin password? Run `docker compose exec clamv-webui /app/clamv-webui reset-admin`. It writes a new password to a file and prints only the file's path.

## Agents

1. In **Admin > Agents**, add an agent. The page shows its token once, plus a compose file for the agent host.
2. On that host, save the token as `./agent_token` and start `docker-compose.agent.yml` next to a clamd.
3. Pick the agent under **Run on** when you scan a path or add a schedule. Schedules with the EICAR control run that check on the agent too.

The agent enforces its own `SCAN_ROOTS`. Jobs queued for an offline agent wait (and expire after a day). A job the agent loses is marked failed. Online and offline changes are logged as `agent.online` and `agent.offline`.

| Variable | Purpose |
|---|---|
| `AGENT_SERVER_URL` | The server, as the agent host reaches it |
| `AGENT_TOKEN(_FILE)` | The agent's token |
| `AGENT_SERVER_FINGERPRINT` | SHA-256 of the server certificate (logged at server start); trust exactly that certificate |
| `AGENT_CA_FILE` | Or: a PEM CA bundle for the server certificate |

`CLAMD_ENDPOINT`, `SCAN_ROOTS`, `SCAN_CONCURRENCY`, `CLAMD_MAX_STREAM_MB` and `LOG_*` apply to the agent as they do to the server. Plain `http://` works but sends the token unencrypted, so use it only over a VPN or mesh.

## Configuration

Every option is an environment variable (or a `--flag`; run `clamv-webui --help`). Secrets also take a `*_FILE` variant for Docker secrets, which wins over the plain variable.

### Core

| Variable | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` | Web and API listener |
| `HEALTH_PORT` | `8081` | Plain-HTTP `/health` for container checks |
| `DATA_DIR` | `./data` (`/app/data` in the image) | SQLite database, TLS files, bootstrap password |
| `DATABASE_URL(_FILE)` | SQLite in `DATA_DIR` | `sqlite://`, `postgres://`, `mysql://` or `mariadb://` |
| `LOG_FORMAT` / `LOG_LEVEL` | `plain` / `info` | `json` for one object per line |
| `BOOTSTRAP_ADMIN_PASSWORD` | generated | First admin password; a supplied one is not forced to change |

### clamd and scanning

| Variable | Default | Purpose |
|---|---|---|
| `CLAMD_ENDPOINT` | `tcp://clamav:3310` | Default endpoint (`tcp://host:port` or `unix:///path`) |
| `CLAMD_HOST_ALLOWLIST` | empty | Hosts admins may add endpoints for; empty allows only the default |
| `CLAMD_MAX_STREAM_MB` | `256` | Must not exceed clamd's `StreamMaxLength` |
| `SCAN_ROOTS` | empty | Comma-separated paths that path scans, schedules and watches may use; clamd must see them at the same paths |
| `SCAN_CONCURRENCY` | `2` | Path scans running at once |
| `UPLOAD_MAX_FILES` | `10` | Files per upload |
| `WATCH_POLL_SECS` | `60` | Seconds between looks at watched folders |
| `JOB_RETENTION_DAYS` | `90` | `0` keeps jobs forever |
| `AUDIT_RETENTION_DAYS` | `365` | `0` keeps audit events forever |

### Web, sessions and TLS

| Variable | Default | Purpose |
|---|---|---|
| `COOKIE_SECURE` | `false` | Always on with TLS; leave off only on plain HTTP over a private network |
| `SESSION_IDLE_MINUTES` / `SESSION_MAX_HOURS` | `30` / `12` | Session lifetime |
| `REQUEST_TIMEOUT_SECS` | `60` | Per-request timeout for UI and API calls |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | unset | Serve HTTPS with your certificate |
| `TLS_SELF_SIGNED` / `TLS_SELF_SIGNED_NAMES` | `false` / unset | Generate a certificate in `DATA_DIR/tls` for the listed names or IPs |

### Webhooks

| Variable | Default | Purpose |
|---|---|---|
| `WEBHOOK_URL(_FILE)` | unset | `http(s)` receiver; Discord webhook URLs get a chat message |
| `WEBHOOK_EVENTS` | `alerts` | `alerts` (detections, failures, clamd down, stale signatures) or `all` |
| `WEBHOOK_ALLOWED_CIDRS` | empty | Private ranges the receiver may resolve to, e.g. `100.82.0.0/16` |
| `WEBHOOK_ALLOW_PRIVATE` | `false` | Allow any private address (cloud metadata stays blocked) |

### Metrics

`METRICS_TOKEN(_FILE)` (16+ characters) enables `/metrics` and `/actuator/prometheus`, read with `Authorization: Bearer <token>`. Without a token both return 404. See `dashboards/prometheus.yml.example`.

### OIDC single sign-on

| Variable | Purpose |
|---|---|
| `OIDC_ISSUER` | Issuer URL (discovery is used) |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET(_FILE)` | Client credentials |
| `OIDC_REDIRECT_URI` | Must end in `/login/oauth2/code/clamav` |
| `OIDC_ADMIN_GROUPS`, `OIDC_OPERATOR_GROUPS`, `OIDC_VIEWER_GROUPS` | Comma-separated; a user in none of them cannot sign in |
| `OIDC_GROUPS_CLAIM` | Default `groups`; dotted paths like `realm_access.roles` work |
| `OIDC_SCOPES`, `OIDC_BUTTON_LABEL`, `OIDC_CA_FILE`, `OIDC_PROVIDER_LOGOUT` | Optional |

### LDAP

| Variable | Purpose |
|---|---|
| `LDAP_URL` | `ldaps://` URL, or `ldap://` with `LDAP_STARTTLS=true`; plain LDAP is refused |
| `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD(_FILE)` | Service account used to find the user |
| `LDAP_USER_BASE`, `LDAP_USER_FILTER` | Search base and filter (`{username}` is escaped) |
| `LDAP_ADMIN_GROUPS`, `LDAP_OPERATOR_GROUPS`, `LDAP_VIEWER_GROUPS` | Group DNs or names; no group means no access |
| `LDAP_GROUP_ATTRIBUTE`, `LDAP_CA_FILE` | Optional |

### Settings page

The Settings page (Admin) can change the scan, retention, watch, webhook-policy and session tunables at runtime. A value set by an environment variable or flag is locked there. Changes are audited.

## Security model

- Runs as UID 10001 in a read-only container with all capabilities dropped. Scan roots should be mounted read-only; the app never writes to them.
- Path scans resolve symlinks and must stay inside `SCAN_ROOTS`. clamd endpoints are limited to `CLAMD_HOST_ALLOWLIST`.
- Passwords use Argon2id. Sessions are server-side with `SameSite=Strict` cookies, CSRF tokens on every form, and login rate limiting.
- A strict Content-Security-Policy (no inline script or style) and the usual security headers on every response.
- API tokens are stored hashed and shown once. Metrics need a bearer token.
- Webhook delivery pins the resolved address, refuses private and metadata ranges unless allowed, follows no redirects, and never logs the URL.
- OIDC uses PKCE, state and nonce, and only asymmetric signatures. LDAP requires TLS.
- Agent tokens are stored hashed, can be rotated or disabled, and only reach the agent endpoints. Results from an agent are size-limited and cleaned before they are stored.

Report vulnerabilities privately through GitHub security advisories.

## Building

```sh
cargo build --release      # binary at target/release/clamv-webui
cargo test                 # SQLite; set TEST_DATABASE_URLS to also test other databases
docker build -t clamv-webui .
```

CI builds and tests on every push, checks dependencies with `cargo deny`, runs CodeQL and Trivy, and publishes `ghcr.io/keyxmakerx/clamv-webui:latest`.
