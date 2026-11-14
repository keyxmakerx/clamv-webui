# ClamAV Web UI

A small, self-hosted web interface and API for [ClamAV](https://www.clamav.net/) `clamd`, written in Rust.
It scans uploads and server paths, runs scheduled and watched-folder scans, and keeps an audit trail. It never moves or deletes files.

Forked from an earlier Java application, which has been replaced entirely. Licensed under LGPL-2.1-or-later (see `LICENSE` and `NOTICE`).

## Features

- **Scans**: upload scans (in-memory stream to clamd), path scans limited to `SCAN_ROOTS`, job history with per-file results.
- **Dashboard**: scans, detections and failures over 24 h, 7 or 30 days, compared with the period before, with a clickable activity chart and the top signatures, folders and hosts.
- **Coverage page**: one view of which threats each host is covered for (malware at rest and on arrival, canaries, EICAR checks, signature age), this server and every agent alike, with what is missing.
- **Detections page**: every infected file across all hosts, filtered by signature, host, type and folder, with CSV export (up to 50,000 rows).
- **Search**: the Jobs and Detections pages take free text plus `field:value` terms, for example `sig:Eicar host:nas -path:/games after:7d`. Quotes match exactly, `-` excludes, dates take `YYYY-MM-DD` or `7d`, `12h`, `30m`. Filters are remembered per browser.
- **Display**: light and dark themes, times shown in your own time zone (or a fixed one) with a 12 or 24 hour clock, set under Account.
- **Schedules**: cron schedules per path. Each run first scans an EICAR control, so a run against a broken clamd reports a failure, not a clean result.
- **Watched folders**: files are scanned the moment they are written (Linux inotify), with periodic polling as a safety net.
- **Canary files**: decoys that raise an alert (log, audit, webhook) the moment anything opens, changes or deletes them, managed per host from the UI, with auditd naming the program and user where the host logs it.
- **Agents**: run the same image with `agent` on other hosts. Each agent scans its own folders with its own clamd and reports back, so one UI covers every machine. Agents connect out to the server, so they need no open port.
- **Multiple clamd endpoints**, with a status page (signature age, threads, queue) and alerts when clamd goes down or signatures go stale.
- **Two-factor sign-in**: an authenticator app (TOTP) with recovery codes, and passkeys (fingerprint, face or security key), which also sign in without a password.
- **Users and roles**: Viewer, Operator, Admin. Local accounts, OIDC single sign-on, and LDAP with roles taken from groups on every sign-in.
- **API** at `/api/v1` with personal tokens, used by the `clamctl` CLI and MCP server (`cli/`, `docs/CLI.md`, `docs/MCP.md`).
- **Alerts** to up to five destinations: any JSON webhook, Discord, Slack or Mattermost, ntfy and Gotify, with priorities, signatures you can mute, and SSRF protection.
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

| `REALTIME_PATHS` | Folders inside `SCAN_ROOTS` scanned as soon as files are written; results show up as watch jobs on the server |

`CLAMD_ENDPOINT`, `SCAN_ROOTS`, `SCAN_CONCURRENCY`, `CLAMD_MAX_STREAM_MB`, `CLAMD_CONF_FILE` (its `ExcludePath` rules), `CANARY_FILES`, `WATCH_REALTIME` and `LOG_*` apply to the agent as they do to the server. Plain `http://` works but sends the token unencrypted, so use it only over a VPN or mesh.

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
| `UPDATE_CHECK` | `true` | Look up the latest GitHub release once a day and tell admins on the dashboard; sends only the version |

### clamd and scanning

| Variable | Default | Purpose |
|---|---|---|
| `CLAMD_ENDPOINT` | `tcp://clamav:3310` | Default endpoint (`tcp://host:port` or `unix:///path`) |
| `CLAMD_HOST_ALLOWLIST` | empty | Hosts admins may add endpoints for; empty allows only the default |
| `CLAMD_MAX_STREAM_MB` | `1024` | Upload size limit; raise clamd's `StreamMaxLength` to match (see below) |
| `SCAN_ROOTS` | empty | Comma-separated paths that path scans, schedules and watches may use; clamd must see them at the same paths |
| `SCAN_CONCURRENCY` | `2` | Path scans running at once |
| `UPLOAD_MAX_FILES` | `10` | Files per upload |
| `WATCH_POLL_SECS` | `60` | Seconds between looks at watched folders |
| `WATCH_REALTIME` | `true` | Scan files in watched folders as soon as they are written |
| `CANARY_FILES` | empty | Comma-separated decoy files; any access logs `canary.tripped` at ERROR, adds a `CANARY_TRIPPED` audit entry and calls the webhook |
| `JOB_RETENTION_DAYS` | `90` | `0` keeps jobs forever |
| `AUDIT_RETENTION_DAYS` | `365` | `0` keeps audit events forever |
| `DETECTION_RETENTION_DAYS` | `365` | Jobs that found malware are kept at least this long; `0` keeps them forever |

clamd refuses streams over its `StreamMaxLength` (25 MB by default in many builds), so set it to at least `CLAMD_MAX_STREAM_MB` in clamd.conf, e.g. `StreamMaxLength 1024M`, and keep `MaxFileSize` and `MaxScanSize` at or above it. Files with names that are not UTF-8 in watched folders are streamed to clamd, so they are scanned too.

| Variable | Purpose |
|---|---|
| `CLAMD_CONF_FILE` | Mounted clamd.conf. Shown read-only under **Admin > clamd Config** with checks against the upload limit; its `ExcludePath` rules also apply to watched folders and single-file scans |
| `FRESHCLAM_CONF_FILE` | Mounted freshclam.conf, shown read-only |

Real-time watching sees writes made on the same machine (bind mounts included, NFS or SMB mounts written from elsewhere are not); polling covers the rest. It needs one inotify watch per folder; for very large trees raise `fs.inotify.max_user_watches` on the host. Folders past the limit still get polled.

Canary files: add them per host on the **Canaries** page (this server and each agent, up to 50 each), or list them in `CANARY_FILES`. Put a tempting decoy (say `/srv/share/finance/passwords.csv`) somewhere nothing legitimate reads; the page can write the decoy for you if the folder is writable from the container, and it never overwrites or deletes a file. Keep canaries outside scanned folders (the page refuses those), since a scan opening one would trip it. Each row shows whether the host could arm it and when it was last touched. Alerts repeat at most once a minute per file, and a deleted canary is watched again once it is back.

To have alerts name who touched a canary, add the auditd rule the page shows (`-w <file> -p rwxa -k clamv_canary`) on the host and mount `/var/log/audit` read-only into the container; the alert then reads, for example, "opened by /usr/bin/cat (uid 1000, login uid 1000, pid 4242)".

### Web, sessions and TLS

| Variable | Default | Purpose |
|---|---|---|
| `COOKIE_SECURE` | `false` | Always on with TLS; leave off only on plain HTTP over a private network |
| `SESSION_IDLE_MINUTES` / `SESSION_MAX_HOURS` | `30` / `12` | Session lifetime |
| `REQUEST_TIMEOUT_SECS` | `60` | Per-request timeout for UI and API calls |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | unset | Serve HTTPS with your certificate |
| `TLS_SELF_SIGNED` / `TLS_SELF_SIGNED_NAMES` | `false` / unset | Generate a certificate in `DATA_DIR/tls` for the listed names or IPs |
| `TRUSTED_PROXIES` | empty | Reverse proxies (CIDRs) whose `X-Forwarded-For`/`-Proto` are believed; see [docs/REVERSE_PROXY.md](docs/REVERSE_PROXY.md) |
| `PUBLIC_URL` | unset | The address users open, e.g. `https://clamav.example.com`; passkeys are tied to its host name |
| `SECRET_KEY_FILE` | `DATA_DIR/secret.key` | Key that encrypts stored 2FA secrets; created on first use. Back it up with the database |

### Alerts (webhook, ntfy, Gotify, Slack, Discord)

| Variable | Default | Purpose |
|---|---|---|
| `WEBHOOK_URL(_FILE)` | unset | Up to 5 comma-separated destinations, see below |
| `WEBHOOK_IGNORE_SIGNATURES` | empty | Signature prefixes that never notify on their own, e.g. `PUA.` (still logged and listed) |
| `WEBHOOK_EVENTS` | `alerts` | `alerts` (detections, failures, clamd down, stale signatures) or `all` |
| `WEBHOOK_ALLOWED_CIDRS` | empty | Private ranges the receiver may resolve to, e.g. `100.82.0.0/16` |
| `WEBHOOK_ALLOW_PRIVATE` | `false` | Allow any private address (cloud metadata stays blocked) |

Destinations: a plain `https://…` URL gets the JSON event, and Discord webhook URLs get a chat message. Put a prefix in front for the others:
`ntfy+https://ntfy.sh/<topic>` (add `?auth=…` for a protected topic), `gotify+https://gotify.example/?token=<app token>`, `slack+https://…` (Slack or Mattermost incoming webhook). Canary hits are sent at the highest priority, malware and failed EICAR checks at high.

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
- Passwords use Argon2id. Second factors: TOTP seeds are encrypted with `SECRET_KEY_FILE`, codes cannot be replayed, recovery codes are hashed and single-use, five wrong codes end the attempt and ten in 15 minutes lock the account's second step, however many times the password is entered. HTTP Basic on the API is refused for accounts with a second factor (use a token). Passkeys require user verification and are checked for origin, relying party, signature and counter. Admins can reset a user's second factors; `reset-admin` clears the admin's. Sessions are server-side with `SameSite=Strict` cookies, CSRF tokens on every form, login rate limiting, and a per-user limit of 30 scans a minute in the UI and API.
- A strict Content-Security-Policy (no inline script or style) and the usual security headers on every response.
- API tokens are stored hashed and shown once. Metrics need a bearer token.
- File names in notifications have bidirectional-override characters replaced, so `cv\u202Efdp.exe` cannot pose as a PDF; Slack text is escaped so names cannot carry mentions or links.
- Webhook delivery pins the resolved address, refuses private and metadata ranges unless allowed, follows no redirects, and never logs the URL.
- OIDC uses PKCE, state and nonce, and only asymmetric signatures. LDAP requires TLS.
- Agent tokens are stored hashed, can be rotated or disabled, and only reach the agent endpoints. Results from an agent are size-limited and cleaned before they are stored, and each agent may send at most 1200 events a minute.

Report vulnerabilities privately through GitHub security advisories.

## Building

```sh
cargo build --release      # binary at target/release/clamv-webui
cargo test                 # SQLite; set TEST_DATABASE_URLS to also test other databases
docker build -t clamv-webui .
```

CI builds and tests on every push, checks dependencies with `cargo deny`, runs CodeQL and Trivy, and publishes `ghcr.io/keyxmakerx/clamv-webui:latest`.
