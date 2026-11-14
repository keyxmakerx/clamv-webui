# clamv-webui 2.1.0 (Java): behaviour inventory for the Rust port

Date: 2026-11-13. Source: `2e57d05`, about 9.6k lines of Java in `src/main/java/info/trizub/clamav/webclient/` plus templates, a Go CLI and helper scripts.
Companion: [SECURITY-REAUDIT-2026-11.md](SECURITY-REAUDIT-2026-11.md) (findings referenced below as S#/N#).

Each section ends with a **Port** line: keep, change or drop. These are recommendations for the port thread, not decisions.

## 1. Runtime shape

- One process, two modes (`configuration/ConfigurationBootstrap.java`):
  1. **Setup/recovery listener**: a JDK `HttpServer` on the app port that serves only `/setup/` (and 503 elsewhere) when there is no configuration, when `CLAMAV_CONFIGURATION_RECOVERY=true`, or when Spring startup fails. No database is opened.
  2. **Application**: Spring Boot (Tomcat, Thymeleaf, JPA, Flyway). `/setup/` stays available through `ConfigurationRecoveryFilter` (S4).
- Working directory `/app`: `./data` (H2 db, uploads, quarantine, bootstrap password) and `./conf` (settings, encrypted secrets, keys, recovery token). Both must be volumes.
- Container: `eclipse-temurin:21-jre` plus apt `clamav-daemon util-linux ncurses-term` (for native clamdtop), uid/gid 10001, port 8080.
- **Port:** keep the single binary. Run setup mode only when unconfigured, and add a switch to disable recovery afterwards (S4). Drop the apt clamd stack unless clamdtop stays (see section 9).

## 2. Authentication and authorisation

| Mechanism | Where | Notes |
|---|---|---|
| Local form login | `POST /login` | BCrypt, password 12–128 chars, lockout 5 per 15 min keyed (user, IP) (`identity/LoginAttemptService.java`). First admin is `admin`, password from `CLAMAV_BOOTSTRAP_ADMIN_PASSWORD` or random, written to `data/bootstrap-admin-password`. |
| LDAP form login | `POST /login/ldap` | Separate endpoint, never falls back to local. LDAPS or StartTLS required. Bind via a user search, optional nested groups (max depth), groups mapped to roles. |
| OIDC | `/oauth2/**`, `/login/oauth2/code/clamav` | Lazy discovery, confidential client (client_secret_basic), registration id `clamav`. Identity is `issuer+sub` hashed to `oidc:<48 hex>`. Groups claim path is configurable. Logout mode `local` or `provider` (RP-initiated). |
| HTTP Basic | everywhere | Global (S2). Refused unless the request looks HTTPS (S1). CSRF is skipped for `Authorization: Basic` on legacy `/api/**`. |
| API bearer tokens | `/api/v1/**` | Random token, SHA-256 hash stored, 12-char prefix shown. Scopes: `scan:upload scan:path jobs:read endpoints:read health:read audit:read`. Optional endpoint-id and path-root restrictions, expiry, revocation, last-used. HTTPS required (S1). |
| Prometheus scrape token | `/actuator/prometheus` | Bearer, at least 24 chars, SHA-256 hash in conf, fail-closed. |
| Recovery token | `/setup/api/*` | 43-char base64url in `conf/configuration-recovery-token`, Bearer or JSON `token`, 8 failures/min/IP. |

Roles are cumulative: `VIEWER < OPERATOR < ADMIN` (stored as all implied authorities in `app_user_roles`). External identities have no default role (deny by default).

Route policy (`config/SecurityConfig.java:87-104`):
- Public: static assets, `/error`, `/setLocale`, `/login`, `/login/ldap`, OAuth2 callbacks, `/actuator/prometheus` (token filter).
- VIEWER: `/`, `/dashboard`, `/main`, `/clamdtop`, `/ws/clamdtop` (S6), `GET /api/health|endpoints|clamdtop`, `GET /rest-monitor/summary`.
- OPERATOR: `/scan/**`, `/jobs/**`, `/api/**` (legacy), `/api-scan`, `/api-reports`, `/rest-monitor/**`.
- ADMIN: `/admin/**`, `/actuator/**`, `/api/v1/tokens/**`, `/h2/**`.
- `/api/v1/**`: authenticated; then per-scope checks in `security/ApiV1Access.java` (session users are mapped to scopes by role).

CSRF: on for browser sessions; skipped for `/h2/**`, Basic on legacy `/api/**`, and Bearer on `/api/v1/**`. `GET /api/v1/csrf` hands a token to CLI clients that use sessions.

**Port:** keep local, OIDC, scoped API tokens and the scrape token. Make LDAP optional (feature flag). Drop global Basic, or keep it only for `/api/**` behind a flag with lockout (S2). Lockout per account *and* per IP, with a bounded map (N9). Invalidate sessions on password, role or enable change (N7). Decide the transport story once: TLS in-process, or an explicit trusted-network mode, instead of trusting forwarded headers by default (S1).

## 3. HTTP surface

### UI pages (Thymeleaf, `templates/pages/*.html`, shell in `fragments/shell.html`)
| Path | Page | Role |
|---|---|---|
| `/login` | login (local, LDAP tab, SSO button) | public |
| `/dashboard`, `/` | dashboard: endpoint health, recent jobs, metrics | VIEWER |
| `/main` | legacy main page | VIEWER |
| `/clamdtop` | native clamdtop in xterm.js over `/ws/clamdtop` | VIEWER |
| `/scan` | upload form, path form, allowed roots, per-endpoint upload limits | OPERATOR |
| `/jobs`, `/jobs/table`, `/jobs/{id}` | job list (top 200, auto-refresh fragment), job detail | OPERATOR |
| `/api-scan`, `/api-reports` | external ClamAV REST API monitor (section 8) | OPERATOR |
| `/admin/endpoints` | clamd endpoints CRUD (default endpoint is owned by Configuration Center) | ADMIN |
| `/admin/users` | local users: create, delete (not the last admin), reset password | ADMIN |
| `/admin/watch` | watched directories: create, toggle, delete | ADMIN |
| `/admin/audit` | last 200 audit events | ADMIN |
| `/admin/api-tokens` | issue and revoke API tokens | ADMIN |
| `/admin/settings/authentication` | LDAP/OIDC settings with save, test and enable actions | ADMIN |
| `/admin/configuration-center` | all settings: review, apply, test (section 5) | ADMIN |
| `/admin/configuration` | read-only observer of mounted clamd.conf/freshclam.conf | ADMIN |
| `/admin/integrations` | Prometheus info, downloadable Grafana dashboard and alert rules | ADMIN |
| `/settings`, `/admin/settings`, `/ping`, `/version`, `/stats`, `/reload`, `/scanFolder`, `/scanFile` | legacy redirects | any |
| `/setLocale?lang=&returnTo=` | 6 languages (en uk ro fr es de), cookie `clamav_lang` | public |

### JSON APIs
- **`/api/v1`** (contract in `src/main/resources/openapi/clamav-v1.yaml`, served at `/api/v1/openapi.yaml`): `auth`, `csrf`, `health/live`, `health/ready`, `health/clamd` (signature age, STALE after `api.v1.clamd.max-database-age-hours`=168), `metrics/clamd`, `endpoints`, `jobs` (paged, filtered, `api.v1.max-page-size`=100), `jobs/{id}`, `jobs/{id}/progress`, `POST scans/uploads` (multipart `files`), `POST scans/paths` (JSON `path`, `endpointId`), `audit`, plus `tokens` (ADMIN: POST, GET, DELETE). Upload/path scans are rate-limited per client IP plus credential hash (`api.v1.scan-rate-limit-per-minute`=30, `security/ScanRateLimitFilter.java:30-34`); the IP part is spoofable under S1.
- **Legacy `/api`**: `GET clamdtop|endpoints|health|jobs|jobs/{id}`, `POST scan/upload`, `POST scan/path`.
- **`/rest-monitor/*`**: proxies to an external ClamAV REST API (section 8).
- **Consumers:** the Go CLI `clamctl` and its MCP server (`cli/`, `docs/CLI.md`, `docs/MCP.md`) speak `/api/v1` with a token or Basic.

**Port:** keep `/api/v1` wire-compatible (it is the CLI/MCP contract; use the OpenAPI file as the test oracle). Drop legacy `/api` and the legacy redirects unless something still calls them. Add an anonymous `/healthz` (S13).

## 4. Scanning

### Job model
Types `UPLOAD`, `PATH`, `WATCH`; status `QUEUED -> RUNNING -> FINISHED`; verdict `OK`, `VIRUS_FOUND`, `ERROR`. The id is a 32-hex UUID. Claiming is an atomic `UPDATE ... WHERE status=QUEUED` (`repo/ScanJobRepository.claimQueued`). There is an in-memory fixed thread pool (`app.concurrentScans`=2) with a reconcile sweep every 60 s for QUEUED rows. On startup everything not FINISHED is re-queued (N5). Detections are stored as JSON `{path: [signatures]}` in `found_viruses_json`.

### Upload flow
Multipart (`spring.servlet.multipart.max-*`=2048MB) -> validate the whole batch (size against the effective limit, exclusions) -> copy to `uploadDir/<id>-<sanitised name>` -> SHA-256 -> job. The worker either:
- sends clamd `nMULTISCAN <path>` over its own socket (default `app.upload.pathScan.enabled=true`, which requires clamd to see the same path), optionally falling back to INSTREAM; or
- streams INSTREAM via clamav-client.

Uploads are never deleted (S3). Quarantine moves them when enabled.

### Path flow
`PathPolicy.normalize` -> `toRealPath` -> must be under an existing real root in `app.allowedScanRoots` (default `/scandir`) -> clamd `MULTISCAN <realpath>` via clamav-client. When the default endpoint has a mounted clamd.conf, the app walks the tree itself and scans each file, applying `ExcludePath` regexes and size limits (`service/DaemonScanPolicy.java:93-120`).

### Watcher
Every `app.watch.pollSeconds` (30 s), for each enabled watched directory: walk depth 5, first 1000 regular files (processed files count toward the 1000). New or changed (mtime+size) files become WATCH jobs, tracked in `processed_files` (N6).

### Quarantine
Off by default. Moves the upload, or any path clamd reported, into `quarantineDir` with a timestamp prefix (S5).

**Port:** keep the job model and atomic claim, and add schedules (F1) on top. Delete uploads after the scan. Stream uploads straight to clamd INSTREAM by default, with no disk copy unless quarantine needs one. Enforce the size limit while streaming, not afterwards. Record per-file ERROR results (N3). Resume long path jobs or mark them interrupted instead of restarting blindly (N5). Add retention.

## 5. Configuration

Precedence, highest first: deployment (command line, env, `SPRING_APPLICATION_JSON`, external `application.*`) > Configuration Center store (`conf/configuration-center.properties`, secrets encrypted with `conf/configuration-center.key`) > legacy `conf/clamav-web-client.properties` (`SettingsService`) > packaged defaults. Fields are marked `live` or `restart`; deployment-controlled fields show as locked in the UI.

Catalog: `src/main/resources/configuration-center/catalog.json`, **107 fields**, in 7 categories (Connections, Scanning, Identity & API, Notifications, Network, Monitoring, System) and 16 sections: `clamd rest database scanning quarantine watch local ldap oidc api webhook proxy trust metrics observer system`. Each field has a type (boolean, number, text, url, path, select, jdbc), env aliases, secret/sensitive flags, min/max and a hint.

Workflow (UI and `/setup/` share `ConfigurationEngine`): `view` -> `review` (validates, returns a diff and a reviewId, expires) -> `apply` (optimistic revision check, explicit HTTP acknowledgement for secrets, database-change acknowledgement) -> audit line in `conf/configuration-audit.jsonl`. `test` probes clamd (zPING), the database (`SELECT 1`, never creates H2), the REST API, LDAP bind or OIDC discovery with draft values.

Other files: `conf/auth-settings.key` (AES-256-GCM key for LDAP/OIDC secrets in `auth_provider_settings`; override with `CLAMAV_AUTH_SETTINGS_KEY(_FILE)`), integration settings (scrape token hash), database-state and database-choice properties.

Optional read-only observer: `CLAMAV_CONFIG_PATH` / `FRESHCLAM_CONFIG_PATH`, polled every 30 s. When `clamav.config.discovery-enabled`, the clamd.conf TCP/socket address becomes the default endpoint and its limits and ExcludePath apply to scans.

**Port:** keep one typed settings schema with field metadata, and the review/apply/audit flow. Simplify precedence to env/file > UI store > defaults, and drop the legacy properties file. Allowlist database URL options for all engines (N8). Decide whether all four databases are worth it; SQLite plus PostgreSQL would cover a home NAS and still allow growth.

## 6. Database

Flyway per vendor (`db/migration/{h2,mariadb,mysql,postgresql}`), V1, V3, V4 SQL plus Java V2 (`db/V2__reconcile_legacy_columns.java`, legacy upgrade) and an optional PostgreSQL LOB migration.

| Table | Key columns |
|---|---|
| `clamd_endpoints` | id, name (unique, 64), host (255; a leading `/` means Unix socket), port, platform (UNIX/WINDOWS), enabled |
| `app_users` / `app_user_roles` | username (unique), password_hash, enabled, created_at, last_login_at / (user_id, role) |
| `api_credentials` | label, token_hash (unique), prefix, scopes (csv), endpoint_ids (csv), path_roots (csv), created/expires/revoked/last_used |
| `audit_events` | at, username, action, details (1024), outcome, job_id, transport, endpoint_id, ip, user_agent |
| `scan_jobs` | id (64), type, status, verdict, target (2048), stored_path, sha256, size_bytes, endpoint_id FK, submitted_by/transport/at, started_at, finished_at, found_viruses_json, error_message, quarantine_path |
| `watched_directories` | path, endpoint_id FK, enabled |
| `processed_files` | path (unique, 4096), last_modified, size_bytes, sha256, processed_at |
| `external_identities` | principal_name PK, source, issuer, subject, first/last_seen |
| `auth_provider_settings` | provider PK, settings_json, encrypted_secret, updated_at/by |

Audit actions seen: `SCAN_UPLOAD`, `SCAN_PATH`, `SCAN_RESULT`, `SCAN_FAILED`, `SCAN_REST_UPLOAD`, `ENDPOINT_*`, `USER_*`, `WATCH_*`, `EXTERNAL_LOGIN`, `EXTERNAL_ADMIN_GRANTED`, `API_TOKEN_CREATE`, `API_TOKEN_REVOKE`, `CONFIGURATION_CENTER_UPDATE`, `CONFIGURATION_CONNECTION_TEST`.

**Port:** the same entities plus `scan_schedules` and `scan_runs` (F1). Replace CSV columns with join tables or JSON. Index `scan_jobs(status, submitted_at)`. Add retention jobs.

## 7. clamd interaction

| Command | Used for | Transport |
|---|---|---|
| `zPING` / `PING` | health, connection test, dashboard | TCP via clamav-client, Unix via `service/UnixClamdClient.java` |
| `VERSION` | engine and signature version, signature age | same |
| `STATS` | dashboard, Prometheus clamd gauges (`metrics/ClamdMetricsCollector.java`, every 30 s, at most 12 endpoints), `/api/clamdtop` | same |
| `MULTISCAN <path>` | PATH/WATCH scans, upload path-scan | clamav-client (US-ASCII, no timeouts: N2, N4) or the app's own `nMULTISCAN` (UTF-8, 24 h timeout) |
| `INSTREAM` | upload scans | clamav-client, 2 KiB chunks, no StreamMaxLength handling |
| native `clamdtop host:port` | `/ws/clamdtop` | subprocess under `script` PTY |

Response handling: `<path>: OK`, `<path>: <sig> FOUND`, `<...> ERROR`. With `AlertExceedsMax=yes`, limit hits arrive as `Heuristics.Limits.Exceeded.* FOUND`.

**Port:** write a small native client: `z`-prefixed NUL-terminated commands, UTF-8 paths (reject NUL/newline), connect, read and total timeouts, bounded reply size, INSTREAM chunks of at least 64 KiB, and a stream length capped client-side at `StreamMaxLength` (read it from clamd.conf or settings). Parse every line into OK / FOUND / ERROR / LIMIT_EXCEEDED. Use `IDSESSION` or a small connection pool for per-file scans. Treat `Heuristics.Limits.Exceeded.*` as its own verdict class.

## 8. Integrations

- **Webhook** (`service/NotificationService.java`, `WebhookDeliveryClient`, `WebhookAddressPolicy`): fires on every finished job. JSON `{jobId,type,target,endpoint,submittedBy,verdict,foundViruses,error,quarantinePath,...}`, or Discord `content` when the URL is a Discord webhook. Async bounded queue (2 workers, 100 deep), connect/read/DNS/total timeouts, redirects off, DNS pinned through a resolver that blocks loopback, private, CGNAT (100.64/10), link-local and metadata unless `allow-private-addresses`. The URL is treated as a secret.
- **Prometheus**: Micrometer `clamav.scans`, `clamav.scan.completed|failures|detections`, `clamav.viruses.detected`, `clamav.scan.duration`, gauges for pending/running jobs, workers busy/capacity/queued, database availability, plus clamd STATS gauges. A Grafana dashboard and alert rules are in `dashboards/`, also downloadable from `/admin/integrations`.
- **External ClamAV REST API monitor** (`service/RestApiBridge.java`, `/rest-monitor/*`, pages `api-scan`/`api-reports`): a read-mostly client for a separate "clamav-rest-api" product (stats, jobs, history, webhooks, async upload) with an API key or bearer token. Unrelated to this deployment.
- **CLI/MCP**: the Go `clamctl` binary in `cli/` (Basic or token, upload, path, wait, jobs, audit, `mcp serve`).

**Port:** keep the webhook with its SSRF policy, add a CIDR allowlist and an "infections and errors only" mode. **Write a structured log line for every detection and failed scan** (N1); that is the operator's primary alert path. Keep the Prometheus names so existing dashboards still work. Drop the REST API monitor. Keep the CLI as is, since it only needs `/api/v1`.

## 9. clamdtop

Native ncurses `clamdtop` in a PTY, streamed as base64 over a WebSocket into xterm.js, at most 8 sessions, 128-byte input frames. A fallback `/api/clamdtop` returns parsed STATS JSON (`service/ClamdTopService.java`).

**Port:** recommend dropping the native PTY and rendering STATS JSON in the browser (one HTTP poll; no subprocess, no clamav packages in the image). If it stays, make it OPERATOR+ and behind a flag (S6).

## 10. Logging and operations

Logback to the console, multi-line pattern, ANSI, app at DEBUG, Spring at ERROR (S11, N10). No detection log line (N1). Scheduled tasks: watcher tick 1 s, endpoint discovery 1 s, job reconcile 60 s, job metrics 15 s, clamd metrics 30 s.

**Port:** one-line JSON logs (`tracing` with a JSON formatter); INFO by default; WARN for security events; a stable `event` field (`scan.detected`, `scan.error`, `auth.failed`, `auth.locked`, `config.changed`, `eicar.control_failed`) for LogTide rules.

## 11. Security lessons the Rust version must not repeat

1. **Never trust forwarded headers by default.** Off unless a trusted proxy CIDR is configured; only then honour `X-Forwarded-*`. Base the TLS-required rules on real transport or an explicit trusted-network flag. (S1)
2. **Every password path goes through the same throttle**: form, Basic, LDAP, recovery token. Per account and per IP, with a bounded store. (S2, N9)
3. **Re-validate every filesystem path at use time**: canonicalise, check against the roots, and refuse anything clamd reports outside them before any move or delete. Use `openat`-style handling where possible. (S5)
4. **Uploads are toxic waste.** Stream with a hard cap enforced while reading, scan, delete. No unbounded staging copies. (S3)
5. **Detections and scan failures must produce a log line**, and partial failures must never be masked as success or as a plain detection. (N1, N3)
6. **Every network call has connect, read and total timeouts and a bounded response size**, including clamd. (N4)
7. **Paths on the wire are UTF-8 bytes**, never lossy-encoded. Reject NUL and newline. Use NUL-delimited clamd commands. (N2)
8. **Authorisation is explicit per route.** No `anyRequest().authenticated()` fallthrough; deny by default, and test the route table (a table-driven test over every route and role).
9. **Errors shown to users are generic**; details go to logs with a correlation id. No existence oracles. (S9)
10. **Security headers by default**: strict CSP (no inline script), `Referrer-Policy: no-referrer`, `Permissions-Policy`, `frame-ancestors 'none'`, `SameSite=Strict` cookies. (S7, S8)
11. **Recovery and admin back doors can be switched off** once set up, and never sit in front of the auth layer without their own strong gate. (S4)
12. **Allowlist, don't blocklist**, for any user-supplied connection string or URL option (database, LDAP, webhook, clamd host). (N8, S10)
13. **Session invalidation on credential, role or enable change.** (N7)
14. **No unused capability in the image**: no mail, no H2 console, no clamav-daemon unless needed. Read-only root, non-root user, an anonymous health endpoint for `HEALTHCHECK`. (S12, S13, H2)
15. **Bound the history**: retention for jobs, audit and processed-file tables; never load whole tables at startup. (N5)
16. **Keep the good parts**: scoped, hashed, expiring API tokens; constant-time comparisons; deny-by-default external role mapping keyed on `issuer+sub`; the webhook DNS-pinning SSRF policy; the review/apply/audit configuration flow; strict H2 URL allowlisting; LDAP filter encoding.
