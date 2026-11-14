# Security re-audit: clamv-webui 2.1.0 (Java)

Date: 2026-11-13. Scope: upstream 2.1.0 as forked (`2e57d05`), read-only. No code was changed.
Purpose: independently verify the 2026-11-12 audit (S1–S13), cover its open items, and feed the Rust port.

Severity is rated for **this deployment** (single operator, UI reachable only over NetBird, plain HTTP, clamd unauthenticated on `media`, quarantine off). Where the generic rating differs it is noted.

Line numbers refer to files under `src/main/java/info/trizub/clamav/webclient/` unless a path says otherwise.

## Summary

| Result | Count |
|---|---|
| S1–S13 confirmed | 11 (S4 downgraded to Low) |
| S1–S13 partly refuted | 2 (S7, S8) |
| New findings | 12 (N1–N12) |
| Known CVEs in runtime jars | 0 (Trivy, 159 jars) |

Top three for the operator: **N1** (no log line on detection, so LogTide can never alert), **N2/N3** (library scans silently fail on non-ASCII names and drop per-file errors), **S1+S2** (spoofed `X-Forwarded-Proto` enables unthrottled Basic brute force).

## 1. Verification of S1–S13

| # | Verdict | Severity | Evidence and notes |
|---|---|---|---|
| S1 | Confirmed | Medium (High behind a public proxy) | `application.properties:52` defaults `server.forward-headers-strategy=framework`. `req.isSecure()` drives the HTTPS-only rules in `ApiTokenAuthenticationFilter.java:31` and `LegacyBasicTlsFilter.java:16` (the file is 21 lines; the brief's `:215` is wrong). `getRemoteAddr()` drives the lockout key in `identity/LoginLockoutFilter.java:21`, the API scan rate limit (`security/ScanRateLimitFilter.java:30`) and audit IPs. Any client can send `X-Forwarded-Proto: https` / `X-Forwarded-For`. The bootstrap setup listener trusts the same headers (`configuration/ConfigurationBootstrap.java:228-231`). **Caveat:** with `none`, Bearer tokens and Basic stop working over plain HTTP, which is how the mesh serves it. The fork needs TLS, or an explicit "trusted plain-HTTP network" switch, not just `none`. |
| S2 | Confirmed | Medium | `config/SecurityConfig.java:115` enables `.httpBasic()` globally. Basic failures never call `LoginAttemptService.fail` (only the form handler at `SecurityConfig.java:111` and LDAP at `identity/IdentityLdapConfiguration.java:34` do). Chained with S1: `X-Forwarded-Proto: https` plus Basic gives unlimited password guessing against local users. |
| S3 | Confirmed | Medium | `service/ScanJobService.java:101-116` copies every upload to `./data/uploads/<id>-<name>` and nothing ever deletes it (`ScanExecutionService` only moves it when quarantine is on). The default limit is 2 GiB (`application.properties:3-6`, `service/SettingsService.java:57`). Also: Spring stages the whole multipart body in `java.io.tmpdir` first, so a 2 GiB upload briefly costs 4 GiB, and the size check (`DaemonScanPolicy.requireUpload`) runs only after the full body has arrived. |
| S4 | Confirmed, downgraded | Low | `configuration/ConfigurationRecoveryFilter.java:16` runs at `HIGHEST_PRECEDENCE+20`, before Spring Security, and is always active. It is gated by a 256-bit token in `conf/configuration-recovery-token`, compared in constant time, 8 attempts/min/IP (`ConfigurationSetupProtocol.java:91-103`). So the real exposure is: anyone who can read the `conf` volume gets full configuration control (datasource, identity providers, scan roots) and an SSRF probe (`/setup/api/test`). A disable switch is still worthwhile. |
| S5 | Confirmed | N/A today (High if quarantine is enabled) | `service/ScanExecutionService.java:215-224` moves every path clamd reports as FOUND, with no `allowedScanRoots`/`toRealPath` check. `service/QuarantineService.java:29` uses `REPLACE_EXISTING`. A rogue or spoofed clamd can name any file the UI user can write. |
| S6 | Confirmed | Medium | `SecurityConfig.java:92` lets VIEWER open `/ws/clamdtop`. Each connection spawns `/usr/bin/script` + `clamdtop` (`web/NativeClamdtopWebSocket.java:57-64`). The 8-connection cap is a non-atomic check (`:38`). Arguments are properly shell-quoted; no injection found. `Dockerfile:21-22` installs the full `clamav-daemon` package (libclamav, freshclam) into the UI image just for this. |
| S7 | Partly refuted | Low | Spring Security already sends `X-Content-Type-Options: nosniff`, `Cache-Control: no-store` and `X-Frame-Options` (relaxed to `SAMEORIGIN` only for H2, `SecurityConfig.java:141`). Missing: CSP, `Referrer-Policy`, `Permissions-Policy`. Templates contain no inline `<script>` or `on*=` handlers, so `script-src 'self'` is feasible. |
| S8 | Partly refuted | Low | Already configurable: Configuration Center keys `server.servlet.session.cookie.same-site` (default `lax`) and `server.servlet.session.cookie.secure` (default `false`). The fix is only a `strict` default. |
| S9 | Confirmed | Low | `util/PathPolicy.java:23` puts the path in "missing or inaccessible", distinct from "not allowed by scan policy" (`:171`). Shown raw by `web/WebUiController.java:192,210` and `web/GlobalExceptionHandler.java:111`. Both APIs already return generic messages. |
| S10 | Confirmed | Low | `service/EndpointService.java:89-93` and `WebUiController.java:264-279` accept any host:port. Admin-only, blind (clamd protocol). |
| S11 | Confirmed, plus more | Medium | `src/main/resources/logback.xml:3-4`: Spring at ERROR, app at DEBUG, ANSI colours. **New:** the `<Pattern>` contains a literal newline and indentation, so every log event is split over two lines. fluent-bit will ship halves. |
| S12 | Confirmed | Info | `pom.xml:44` `java.version=17` vs JDK 21 build. `spring-boot-starter-mail` (`pom.xml:150-155`) is unused (no mail code). |
| S13 | Confirmed | Low | No `HEALTHCHECK`. `/actuator/health` needs ADMIN (`SecurityConfig.java:90`), `/api/v1/health/live` needs a session or token with `health:read`. There is no anonymous liveness endpoint. Read-only root: writes go to `./data`, `./conf` (volumes) and `/tmp` (multipart staging, Tomcat work dir), so `read_only: true` should work with a `/tmp` tmpfs at least as large as the upload limit. Not runtime-tested (no Docker daemon in the audit sandbox). |

## 2. Open items

### H2 console
`spring.h2.console.enabled=false` (`application.properties:21`). It is not in the Configuration Center catalog, so it can be enabled only by deployment env (`SPRING_H2_CONSOLE_ENABLED`). If enabled it is ADMIN-only but CSRF-exempt (`SecurityConfig.java:129`) and frameable. **Not reachable in the default build.** Recommendation: drop `spring-boot-h2console` (`pom.xml:116`), the CSRF exemption and `SAMEORIGIN`. The H2 *JDBC URL* path is well defended: `ConfigurationCatalog.checkJdbc` allowlists H2 options and blocks `INIT`/`RUNSCRIPT` (`configuration/ConfigurationCatalog.java:103-123`).

### Actuator and Prometheus
- Exposed: `health,info,metrics,prometheus` (`application.properties:31`). `/actuator/**` is ADMIN-only; health details `when_authorized`.
- `/actuator/prometheus` is `permitAll` in the chain but guarded by `metrics/PrometheusAccessFilter.java`: Bearer token required, at least 24 chars, fail-closed when none is configured. Stored as unsalted SHA-256 hex (`service/IntegrationSettingsService.java:86-89`) in the conf volume, compared with `MessageDigest.isEqual`. Adequate for a random token. The token crosses the mesh in clear text.
- No issues found.

### OIDC and LDAP
- OIDC: issuer must be `https://`; discovery issuer must equal the configured one (`identity/AuthenticationProviderProber.java:49`); ID token issuer re-checked (`identity/ExternalOidcUserService.java:25`). Identity is `issuer+sub`, never email (`identity/ExternalIdentityMapper.java:42`). Roles are deny-by-default from a validated claim path. **Note:** when `clamav.public-url` is unset the redirect URI is `{baseUrl}` (`identity/LazyOidcClientRegistrationRepository.java:44-52`), which follows spoofable forwarded headers (S1). The IdP's redirect allowlist mitigates it. PKCE is not explicitly enabled; verify the Spring Security 7 default before relying on it.
- LDAP: `ldaps://` or StartTLS enforced (`IdentityLdapConfiguration.java:44-47`). User lookup uses `FilterBasedLdapUserSearch` (escapes `{0}`). The group filter template is parsed and validated, with values `LdapEncoder.filterEncode`d (`identity/LdapGroupSearchFilter.java`). Blank passwords rejected. **No LDAP injection found.**
- Group mapping matches the group *name attribute* (`cn` by default), case-insensitively (`ExternalIdentityMapper.java:46-53`). Any group with a matching `cn` anywhere under the group search base grants the role. Info; matters only if others can create groups.

### clamav-client 2.1.2 (`xyz.capybara`)
Unmaintained: last release 2022-02-01 (Maven Central metadata). Source reviewed from the `-sources.jar`:
- **No TCP timeouts.** `SocketChannel.open(server)` with blocking reads (`Command.kt:18`, `InStream.kt:24`). A stalled clamd hangs a scan worker forever, and the default pool has 2 workers. (The app's own Unix-socket client *does* have timeouts.)
- **MULTISCAN path encoded as US-ASCII** (`MultiScan.kt:14`). `/data/Amélie` is sent as `/data/Am?lie`, so clamd fails it. All PATH and WATCH jobs over TCP go through this. See N2.
- Response parsing drops errors when a FOUND is present (N3), and buffers the reply unbounded.
- **INSTREAM** sends 2 KiB chunks with no knowledge of `StreamMaxLength`. When clamd hits the limit it replies `INSTREAM size limit exceeded. ERROR` and closes; the client keeps writing, gets a broken pipe, and throws `CommunicationException`. The clamd reason is lost and the job ends as an opaque ERROR.

### Upload / INSTREAM path, zip bombs
- The app never decompresses anything; bombs are clamd's problem. With `AlertExceedsMax=yes`, archives over `MaxScanSize`/`MaxRecursion`/`MaxFiles` come back as `Heuristics.Limits.Exceeded.* FOUND`, and the app records VIRUS_FOUND. That is safe for uploads. **For library scans, every file over 2000M (4K remuxes) will be a "detection".** F1 needs a way to classify these separately.
- The effective upload limit is `min(app.upload.maxBytes, StreamMaxLength, MaxScanSize, MaxFileSize)`, but only when a clamd.conf is mounted via `CLAMAV_CONFIG_PATH` (`service/DaemonScanPolicy.java:48-58`). Without it, uploads above clamd's `StreamMaxLength` fail as described above.
- Path scans check the size limit only for single files, not for directory targets (`DaemonScanPolicy.java:84`).

### Dependency CVEs
- Trivy (built from source, DB pulled 2026-11-13), run over the 159 runtime jars resolved from `pom.xml` (`mvn dependency:copy-dependencies -DincludeScope=runtime`): **0 vulnerabilities.**
- `eclipse-temurin:21-jre` (Ubuntu 26.04): 0 HIGH/CRITICAL.
- **Not scanned:** the final image layer with apt `clamav-daemon util-linux ncurses-term` (no Docker daemon available here). The CI Trivy job from fork setup will cover it.
- The committed SBOM `docs/security/runtime.cdx.json` is stale: it lists mariadb-java-client 3.5.10, which Trivy flags with 4 CVEs (CVE-2026-119210/-119276/-119281 MEDIUM, -119280 LOW). The pom already pins 3.5.11, which fixes them.
- Vendored front-end libraries (jQuery 3.6.0, Bootstrap, xterm under `static/js`) are invisible to Dependabot.
- OWASP dependency-check and OSV could not run: NVD and OSV are blocked by the audit sandbox's network policy.

### Error pages
`server.error.include-*=never`; `templates/error.html` prints only the status and app version; both API error handlers return generic bodies. Two leaks remain, both Low: raw exception text in UI flash messages (S9), and raw exception text in `scan_jobs.error_message` (for example the upload path and clamd's raw reply, `ScanExecutionService.java:151-155`), visible to OPERATOR on the job page and sent in webhooks.

## 3. New findings

| # | Severity | Finding | Evidence |
|---|---|---|---|
| N1 | **High** (for this operator) | **No log line is written when malware is found.** Detections go to the DB, metrics and the webhook only. The sole log statements are `log.debug` (`ScanExecutionService.java:228,273`); `AuditService.recordResult` does not log. LogTide therefore cannot alert on detections. | grep for info/warn/error with virus/found: none |
| N2 | **High** (functional) | PATH/WATCH scans over TCP fail for any non-ASCII path (see clamav-client). A scheduled library scan would ERROR on whole directories. | `MultiScan.kt:14` |
| N3 | Medium | When MULTISCAN returns FOUND lines plus ERROR lines, the ERROR lines are discarded and the job is VIRUS_FOUND. Several ERROR lines with no FOUND become `InvalidResponseException`. Files clamd could not read are never reported. Reproduced with the library's regexes. | `ScanCommand.kt` parse order |
| N4 | Medium | No connect/read timeout on TCP clamd (library). The app's own upload MULTISCAN uses a 24 h read timeout. One hung clamd stalls the whole queue. | `ScanExecutionService.java:51` |
| N5 | Medium | On restart every non-finished job is re-queued from scratch, after `repo.findAll()` loads the entire job history into memory. There is no retention for `scan_jobs`, `audit_events` or `processed_files`. | `ScanJobService.java:43-52` |
| N6 | Low | The watcher marks a file processed when the job is *created*, not when it scans clean. Failed scans are never retried, and per-file exceptions are swallowed silently. | `service/WatcherService.java:100-117` |
| N7 | Low | Password reset, role change or disabling a user does not end that user's existing sessions (no session registry). Inferred from code, not runtime-tested. | `service/UserService.java:119-124` |
| N8 | Low | MySQL/MariaDB/PostgreSQL JDBC URLs accept any option outside a short blocklist, for example `allowLoadLocalInfile`, `autoDeserialize`, `socketFactory`. Admin or recovery-token only. H2 is properly allowlisted. | `ConfigurationCatalog.java:109-111` |
| N9 | Low | The lockout is keyed by (mechanism, username, IP), so it is not a per-account lockout, and the map is never pruned (only on success). Many distinct usernames grow memory without bound. | `identity/LoginAttemptService.java:47-61` |
| N10 | Low | Multi-line log pattern (see S11). | `logback.xml:9-12` |
| N11 | Info | Webhook payloads include the full target path, signatures and raw error text, sent to an external receiver (Discord supported). | `service/NotificationService.java:84-92` |
| N12 | Info | The app version is shown on the unauthenticated login and error pages. | `templates/error.html` |

## 4. Method

Manual review of every security-relevant class (filters, `SecurityConfig`, identity, configuration center, scan pipeline, WebSocket, metrics, error handlers), the clamav-client source jar, `pom.xml`, `Dockerfile` and `logback.xml`. Regex behaviour for N3 was checked by running the library's patterns in Java. Not done: runtime testing of the app or image (no Docker daemon in the sandbox).
