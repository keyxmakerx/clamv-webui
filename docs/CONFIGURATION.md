# Configuration

Every option is an environment variable (or a `--flag`; run `clamv-webui --help`). Secrets also take a `*_FILE` variant for Docker secrets, which wins over the plain variable.


Back to the [README](../README.md). How the parts fit together: [ARCHITECTURE.md](ARCHITECTURE.md).

## Core

| Variable | Default | Purpose |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` | Web and API listener |
| `HEALTH_PORT` | `8081` | Plain-HTTP `/health` for container checks |
| `DATA_DIR` | `./data` (`/app/data` in the image) | SQLite database, TLS files, bootstrap password |
| `DATABASE_URL(_FILE)` | SQLite in `DATA_DIR` | `sqlite://`, `postgres://`, `mysql://` or `mariadb://` |
| `LOG_FORMAT` / `LOG_LEVEL` | `plain` / `info` | `json` for one object per line |
| `BOOTSTRAP_ADMIN_PASSWORD` | generated | First admin password; a supplied one is not forced to change |
| `AIDE_LOG` / `RKHUNTER_LOG` | `/var/log/aide/aide.log` / `/var/log/rkhunter.log` | Host reports to read (mount read-only); on agents too. Empty turns one off |
| `FALCO_EVENTS` / `FALCO_MIN_PRIORITY` | `/var/log/falco/events.json` / `warning` | Falco JSON alert file to follow (mount read-only); lowest priority kept |
| `UPDATE_CHECK` | `true` | Look up the latest GitHub release once a day and tell admins on the dashboard; sends only the version |

## clamd and scanning

| Variable | Default | Purpose |
|---|---|---|
| `CLAMD_ENDPOINT` | `tcp://clamav:3310` | Default endpoint (`tcp://host:port` or `unix:///path`), created on first start only; change it later under **Admin > clamd Endpoints** |
| `CLAMD_HOST_ALLOWLIST` | empty | Hosts admins may add endpoints for; empty allows only the host of `CLAMD_ENDPOINT` |
| `CLAMD_MAX_STREAM_MB` | `1024` | Upload size limit; raise clamd's `StreamMaxLength` to match (see below) |
| `SCAN_ROOTS` | empty | Comma-separated paths that path scans, schedules and watches may use; clamd must see them at the same paths |
| `SCAN_CONCURRENCY` | `2` | Path scans running at once |
| `SCHEDULE_TZ` | `TZ`, else `UTC` | Default time zone for schedules (IANA name, e.g. `Europe/Berlin`); each schedule can set its own |
| `UPLOAD_MAX_FILES` | `10` | Files per upload |
| `WATCH_POLL_SECS` | `60` | Seconds between looks at watched folders |
| `WATCH_REALTIME` | `true` | Scan files in watched folders as soon as they are written |
| `CANARY_FILES` | empty | Comma-separated decoy files; any access logs `canary.tripped` at ERROR, adds a `CANARY_TRIPPED` audit entry and calls the webhook |
| `JOB_RETENTION_DAYS` | `90` | `0` keeps jobs forever |
| `AUDIT_RETENTION_DAYS` | `365` | `0` keeps audit events forever |
| `DETECTION_RETENTION_DAYS` | `365` | Jobs that found malware are kept at least this long; `0` keeps them forever |

clamd refuses streams over its `StreamMaxLength` (100 MB in the official image, 25 MB in older releases), so set it to at least `CLAMD_MAX_STREAM_MB` in clamd.conf, e.g. `StreamMaxLength 1024M`, and keep `MaxFileSize` and `MaxScanSize` at or above it. The official image takes these as `CLAMD_CONF_StreamMaxLength` and so on, which the bundled compose file sets to 1024M. Files with names that are not UTF-8 in watched folders are streamed to clamd, so they are scanned too.

| Variable | Purpose |
|---|---|
| `CLAMD_CONF_FILE` | Mounted clamd.conf. Shown read-only under **Admin > clamd Config** with checks against the upload limit; its `ExcludePath` rules also apply to watched folders and single-file scans |
| `FRESHCLAM_CONF_FILE` | Mounted freshclam.conf, shown read-only |

Real-time watching sees writes made on the same machine (bind mounts included, NFS or SMB mounts written from elsewhere are not); polling covers the rest. It needs one inotify watch per folder; for very large trees raise `fs.inotify.max_user_watches` on the host. Folders past the limit still get polled.

Canary files: add them per host on the **Canaries** page (this server and each agent, up to 50 each), or list them in `CANARY_FILES`. Put a tempting decoy (say `/srv/share/finance/passwords.csv`) somewhere nothing legitimate reads; the page can write the decoy for you if the folder is writable from the container, and it never overwrites or deletes a file. Keep canaries outside scanned folders (the page refuses those), since a scan opening one would trip it. Each row shows whether the host could arm it and when it was last touched. Alerts repeat at most once a minute per file, and a deleted canary is watched again once it is back.

To have alerts name who touched a canary, add the auditd rule the page shows (`-w <file> -p rwxa -k clamv_canary`) on the host and mount `/var/log/audit` read-only into the container; the alert then reads, for example, "opened by /usr/bin/cat (uid 1000, login uid 1000, pid 4242)".

## Web, sessions and TLS

| Variable | Default | Purpose |
|---|---|---|
| `COOKIE_SECURE` | `false` | Always on with TLS; leave off only on plain HTTP over a private network |
| `SESSION_IDLE_MINUTES` / `SESSION_MAX_HOURS` | `30` / `12` | Session lifetime |
| `SSO_SESSION_MINUTES` | `60` | SSO and LDAP sessions end sooner, so role changes at the provider apply |
| `REQUIRE_ADMIN_2FA` | `false` | Admins with a local password must add an authenticator app or passkey first |
| `API_BASIC_HTTPS_ONLY` | `false` | Refuse HTTP Basic on the API over plain HTTP (tokens still work) |
| `REQUEST_TIMEOUT_SECS` | `60` | Per-request timeout for UI and API calls |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | unset | Serve HTTPS with your certificate |
| `TLS_SELF_SIGNED` / `TLS_SELF_SIGNED_NAMES` | `false` / unset | Generate a certificate in `DATA_DIR/tls` for the listed names or IPs |
| `TRUSTED_PROXIES` | empty | Reverse proxies (CIDRs) whose `X-Forwarded-For`/`-Proto` are believed; see [REVERSE_PROXY.md](REVERSE_PROXY.md) |
| `PUBLIC_URL` | unset | The address users open, e.g. `https://clamav.example.com`; passkeys are tied to its host name, and other host names are refused |
| `ALLOWED_HOSTS` | empty | Extra host names accepted when `PUBLIC_URL` is set (localhost always is) |
| `SECRET_KEY_FILE` | `DATA_DIR/secret.key` | Key that encrypts stored 2FA secrets; created on first use. Back it up with the database |

## Alerts (webhook, ntfy, Gotify, Slack, Discord)

| Variable | Default | Purpose |
|---|---|---|
| `WEBHOOK_URL(_FILE)` | unset | Up to 5 comma-separated destinations, see below |
| `WEBHOOK_IGNORE_SIGNATURES` | empty | Signature prefixes that never notify on their own, e.g. `PUA.` (still logged and listed) |
| `WEBHOOK_EVENTS` | `alerts` | `alerts` (detections, failures, clamd down, stale signatures) or `all` |
| `WEBHOOK_ALLOWED_CIDRS` | empty | Private ranges the receiver may resolve to, e.g. `100.82.0.0/16` |
| `WEBHOOK_ALLOW_PRIVATE` | `false` | Allow any private address (cloud metadata stays blocked) |

Destinations: a plain `https://…` URL gets the JSON event, and Discord webhook URLs get a chat message. Put a prefix in front for the others:
`ntfy+https://ntfy.sh/<topic>` (add `?auth=…` for a protected topic), `gotify+https://gotify.example/?token=<app token>`, `slack+https://…` (Slack or Mattermost incoming webhook). Canary hits are sent at the highest priority, malware and failed EICAR checks at high.

## CrowdSec

| Variable | Default | Purpose |
|---|---|---|
| `CROWDSEC_LAPI_URL` | unset | Local API, e.g. `http://crowdsec:8080`; turns on the CrowdSec pages |
| `CROWDSEC_MACHINE_ID` | `clamv-webui` | Watcher added with `cscli machines add clamv-webui --password "$(cat crowdsec_pw)"` |
| `CROWDSEC_PASSWORD(_FILE)` | unset | That watcher's password |
| `CROWDSEC_CA_FILE` | unset | Extra CA for an https LAPI |
| `CROWDSEC_INCLUDE_CAPI` | `false` | Also show the community blocklist (large) |
| `CROWDSEC_READ_ONLY` | `false` | Hide the ban and unban buttons |
| `CROWDSEC_LOOKBACK_HOURS` | `168` | Hours of alerts kept in memory (nothing is stored in the database) |

clamv refreshes every minute and re-reads the whole window hourly. Bans are sent the way `cscli decisions add` sends them, so every bouncer applies them. Deleting alerts needs CrowdSec's `trusted_ips`, so clamv doesn't offer it. A LAPI that stops answering is logged (`crowdsec.lapi_down`) and notified, and so is its recovery.

## Managed host checks and firewall

Docker alone covers scans, canaries, CrowdSec and reading reports. Managed AIDE and rkhunter and the Firewall page also need a one-time setup on each host, which the image does itself:

```sh
docker run --rm --user 0 -v /:/host ghcr.io/keyxmakerx/clamv-webui:latest host-setup
```

It adds a `clamv` user with the containers' uid (10001, or `--uid`), the units `clamv-aide-check`, `clamv-aide-accept`, `clamv-rkhunter-check`, `clamv-rkhunter-propupd`, `clamv-firewall-snapshot`, `clamv-firewall-apply`, `clamv-firewall-remove` and `clamv-timer-set` (each one fixed script, read-only system, no network, few capabilities), daily timers, `/var/lib/clamv/firewall` and `/var/lib/clamv/timers`, and a polkit rule that lets `clamv` start those units and switch the two timers, and nothing else. It refuses hosts with polkit older than 0.106, which then stay on report reading, and ends with a note for anything else the host lacks (AIDE, rkhunter, nftables). Hosts set up before this release need `host-setup` again. `host-setup --remove` takes it away again. Without Docker, `sudo examples/host-checks/install.sh` does the same. AIDE and rkhunter themselves are host packages.

Then mount `/run/dbus/system_bus_socket` read-only and `/var/lib/clamv/firewall` and `/var/lib/clamv/timers` read-write into the clamv or agent container. The Integrity page then sets each timer's daily time (HH:MM, or empty for a random time). Reports still reach clamv through `AIDE_LOG` and `RKHUNTER_LOG`.

The firewall plan only narrows: each rule lets the listed networks reach a port and drops everyone else. On a host running ufw, clamv adds rules commented `clamv` above the host's own; with firewalld, rich rules in the default zone, saved once confirmed; otherwise its own `inet clamv` table at priority -5, after established traffic and loopback. It removes only what it added. Ports published by Docker go through Docker's own chains first and are best limited in compose. clamv refuses a plan that closes SSH to everyone or blocks its own port for your address, and iptables-legacy rules, which nftables cannot override, are flagged.

## Quarantine

Off until `QUARANTINE_DIR` is set (on the server, or on an agent that also allows `quarantine`). An admin then moves a detection there from **Detections**: clamd must still find the file infected, and the scan root must be mounted read-write. The copy is kept read-only with its SHA-256. Restore (to the original path, never over a file) and delete each need a passkey. `QUARANTINE_AUTO=true` moves every new detection automatically. Each step is logged and audited.

## Agents

Set these on the agent host. Setup steps are in the [README](../README.md#agents).

| Variable | Purpose |
|---|---|
| `AGENT_SERVER_URL` | The server, as the agent host reaches it; must be `https://` |
| `AGENT_TOKEN(_FILE)` | The agent's token |
| `AGENT_SERVER_FINGERPRINT` | SHA-256 of the server certificate (logged at server start); trust exactly that certificate |
| `AGENT_CA_FILE` | Or: a PEM CA bundle for the server certificate |
| `AGENT_ALLOW_PLAINTEXT` | `true` accepts an `http://` server URL (token and results unencrypted); only for a private VPN or mesh |
| `AGENT_QUEUE_DIR` | Writable folder that keeps unsent results across agent restarts (default: memory; up to 5,000 items or 64 MB) |
| `CANARY_DIRS` | Folders where the server may have the agent write decoys; elsewhere a canary is only watched |
| `REALTIME_PATHS` | Folders inside `SCAN_ROOTS` scanned as soon as files are written; results show up as watch jobs on the server |
| `AGENT_ALLOW(_FILE)` | What this host lets the server ask for: `scan`, `canaries`, `checks`, `timers`, `baseline`, `firewall`, `quarantine` or `all` (default `scan,canaries,checks`); set only on the agent host |

The agent writes its own JSON line for every job it runs (`agent.action`) or refuses (`agent.action_refused`), and limits each kind per hour (scans 600, canaries and checks 60, timers 20, firewall 6, baseline 4, quarantine 120); a refused or limited job fails with `AGENT_REFUSED` or `AGENT_RATE_LIMITED`. Firewall applies and baseline accepts stay off until that host enables them.

`CLAMD_ENDPOINT`, `SCAN_ROOTS`, `SCAN_CONCURRENCY`, `CLAMD_MAX_STREAM_MB`, `CLAMD_CONF_FILE` (its `ExcludePath` rules), `CANARY_FILES`, `QUARANTINE_DIR`, `WATCH_REALTIME` and `LOG_*` apply to the agent as they do to the server. Changing `TLS_SELF_SIGNED_NAMES` makes a new certificate; the server logs `tls.cert_replaced` and Admin > Agents shows the new fingerprint every agent needs. Prometheus gets `clamav_agent_up`, `clamav_agent_last_seen_timestamp`, `clamav_agent_jobs_queued` and friends, one series per agent.

## Metrics

`METRICS_TOKEN(_FILE)` (16+ characters) enables `/metrics` and `/actuator/prometheus`, read with `Authorization: Bearer <token>`. Without a token both return 404. See `dashboards/prometheus.yml.example`.

## OIDC single sign-on

| Variable | Purpose |
|---|---|
| `OIDC_ISSUER` | Issuer URL (discovery is used) |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET(_FILE)` | Client credentials |
| `OIDC_REDIRECT_URI` | Must end in `/login/oauth2/code/clamav` |
| `OIDC_ADMIN_GROUPS`, `OIDC_OPERATOR_GROUPS`, `OIDC_VIEWER_GROUPS` | Comma-separated; a user in none of them cannot sign in |
| `OIDC_GROUPS_CLAIM` | Default `groups`; dotted paths like `realm_access.roles` work |
| `OIDC_SCOPES`, `OIDC_BUTTON_LABEL`, `OIDC_CA_FILE`, `OIDC_PROVIDER_LOGOUT` | Optional |

## LDAP

| Variable | Purpose |
|---|---|
| `LDAP_URL` | `ldaps://` URL, or `ldap://` with `LDAP_STARTTLS=true`; plain LDAP is refused |
| `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD(_FILE)` | Service account used to find the user |
| `LDAP_USER_BASE`, `LDAP_USER_FILTER` | Search base and filter (`{username}` is escaped) |
| `LDAP_ADMIN_GROUPS`, `LDAP_OPERATOR_GROUPS`, `LDAP_VIEWER_GROUPS` | Group DNs or names; no group means no access. Use full DNs: a short name matches that group in any OU |
| `LDAP_GROUP_ATTRIBUTE`, `LDAP_CA_FILE` | Optional |

## Settings page

The Settings page (Admin) can change the scan, retention, watch, webhook-policy and session tunables at runtime. A value set by an environment variable or flag is locked there. Changes are audited.

## Languages

Each user picks a language under **Account**; otherwise the browser's language is used, then English. Only English ships for now. To add one, copy `crates/server/i18n/en.json` to `<code>.json`, translate the values and add a line to `LANGS` in `src/i18n.rs`; missing strings show in English. The shell is wrapped so far; page text moves into the catalog as it is translated.

## Security model

- Runs as UID 10001 in a read-only container with all capabilities dropped. Scan roots should be mounted read-only; the app never writes to them unless quarantine is turned on.
- Path scans resolve symlinks and must stay inside `SCAN_ROOTS`. clamd endpoints are limited to `CLAMD_HOST_ALLOWLIST`.
- Passwords use Argon2id. Second factors: TOTP seeds are encrypted with `SECRET_KEY_FILE`, codes cannot be replayed, recovery codes are hashed and single-use, five wrong codes end the attempt and ten in 15 minutes lock the account's second step, however many times the password is entered. HTTP Basic on the API is refused for accounts with a second factor (use a token). Passkeys require user verification and are checked for origin, relying party, signature and counter. Admins can reset a user's second factors; `reset-admin` clears the admin's. Sessions are server-side with `SameSite=Strict` cookies, CSRF tokens on every form, login rate limiting, and a per-user limit of 30 scans a minute in the UI and API. Sign-in hardening, step-up confirmation and what to do when locked out: [SECURITY.md](SECURITY.md).
- A strict Content-Security-Policy (no inline script or style) and the usual security headers on every response.
- API tokens are stored hashed and shown once. Metrics need a bearer token.
- File names in notifications have bidirectional-override characters replaced, so `cv\u202Efdp.exe` cannot pose as a PDF; Slack text is escaped so names cannot carry mentions or links.
- Webhook delivery pins the resolved address, refuses private and metadata ranges unless allowed, follows no redirects, and never logs the URL.
- OIDC uses PKCE, state and nonce, and only asymmetric signatures. LDAP requires TLS.
- The CrowdSec watcher password is never logged. Admins add bans; their own address, loopback and anything wider than /8 (IPv4) or /32 (IPv6) is refused, and `CROWDSEC_READ_ONLY` removes writes.
- Managed host checks never run as root inside clamv: systemd starts fixed units on a polkit allow-list, the agent refuses any action outside it too, and a baseline change needs a fresh passkey assertion bound to that action and host.
- The firewall units accept only the inside of clamv's own table: the apply script reads the plan only if clamv's own user owns the file, accepts only the line shapes clamv generates (one input chain: listed networks reach a port, everyone else is dropped; no NAT, marks or other hooks), refuses table, ruleset, flush, delete and similar keywords, checks the plan in an empty network namespace where it must create exactly `inet clamv`, keeps the previous table, and restores it after 90 s unless the hash is confirmed. clamv confirms only once a new connection gets through, and every apply or removal is logged (`firewall.apply`, `firewall.removed`), audited and needs a passkey.
- Agents act only on what their own host allows (`AGENT_ALLOW`), which the server cannot change, and rate-limit each kind of job.
- Quarantine is off by default; it only moves files clamd confirms infected, restores only to the original path, and restore or delete needs a passkey.
- Agent tokens are stored hashed, can be rotated or disabled, and only reach the agent endpoints. Results from an agent are size-limited and cleaned before they are stored, and each agent may send at most 1200 events a minute.

Report vulnerabilities privately through GitHub security advisories.

## Building and releases

```sh
cargo build --release      # binary at target/release/clamv-webui
cargo test                 # SQLite; set TEST_DATABASE_URLS to also test other databases
docker build -t clamv-webui .
```

CI builds and tests on every push, checks dependencies with `cargo deny`, runs CodeQL and Trivy, starts the image once, and publishes `ghcr.io/keyxmakerx/clamv-webui:latest` (amd64) plus a short commit tag for rollback.

Releases: set `version` in `Cargo.toml`, merge, then push a tag `vX.Y.Z` on that commit. CI checks the tag matches, publishes `:X.Y.Z` and `:X.Y`, and creates the GitHub release that the dashboard's update notice looks for. Compose files stay on `:latest`.

Schema changes go in a new numbered file under `crates/server/migrations/<backend>/` with a line in `crates/server/migrations.sha256`; files already on `main` never change (CI refuses it).
