# Sign-in and session security

How sign-in is protected, what asks for a fresh confirmation, and what to do when you are locked out.

## Baseline (audit of 18 Nov 2026)

A read-only audit of `main` at `5715cd5` covered every file under `auth/` and the session, CSRF, API, passkey, 2FA, OIDC, LDAP and agent code. It found no way in without credentials and no high-severity issue. Confirmed sound:

- Forwarded headers are believed only from `TRUSTED_PROXIES`; the internal HTTPS marker is stripped from every request.
- Form sign-in, HTTP Basic and password change go through one throttled check. Basic is refused for accounts with a second factor.
- CSP without inline script or style, `frame-ancestors 'none'`, cookies `HttpOnly; SameSite=Strict`.
- Every signed-in state-changing UI handler checks the session CSRF token, on top of a same-origin check on every unsafe request.
- Session ids, API tokens, agent tokens and recovery codes are stored as SHA-256 only. TOTP seeds are AES-256-GCM sealed and bound to their user. No log line carries a secret.
- Passkey and OIDC checks: single-use challenges, origin, RP hash, user verification, counter, PKCE, state bound to the browser, nonce, issuer, audience, algorithm list.
- API tokens act only within the scopes they were given when created, and are stored as SHA-256 only.

Not covered by that audit: a real browser with a hardware key, a running container, and `cargo deny` (CI runs it). Every review so far was done by Claude threads.

The fixes below came out of that audit.

## Sign-in throttling

- At most 4 password checks run at once (each holds 19 MiB for Argon2). Others wait up to 10 s, then get "busy".
- A failure is counted before the password is checked and handed back if it was right, so a burst of parallel guesses gets the same 5 tries as a slow one.
- Limits per 15 minutes: 5 failures per account and address, 20 per account, 30 per address. IPv6 addresses count per /64.
- Passkey sign-in failures count against the address only, so they cannot lock anyone else out.
- SSO sign-in starts are limited to 10 a minute per address.
- The compose files set `mem_limit` on the app container.

### Clearing a lock

Locks live in memory. Restart the container (`docker restart clamv-webui`) to clear all of them at once; otherwise they expire after 15 minutes. `reset-admin` resets the admin password and second factors but does not clear a running server's locks.

## "Confirm it's you"

A stolen session cookie alone cannot add its own sign-in method or make a new admin. These actions need a confirmation from the last 5 minutes in the same session:

- turning on an authenticator app,
- adding or removing a passkey,
- creating an admin, raising someone's role or re-enabling them,
- resetting someone's password or second factors.

What counts as confirmation: a current authenticator code (if you have one), else your password, else your directory password (LDAP). SSO users sign in again at the provider, which is asked for a fresh login (`prompt=login`, `max_age=0`) and must return a recent `auth_time`. Confirmations are kept in memory, so a restart forgets them.

## SSO and LDAP

- An authenticator app or passkey added here is asked for after SSO sign-in too, as it already was after LDAP.
- SSO and LDAP sessions last `SSO_SESSION_MINUTES` (default 60), after which the user signs in again and roles from the provider apply. A role removed at the provider therefore takes effect within that time.
- For LDAP groups, use full DNs. A short name matches a group of that name in any OU.

## Admins and tokens

- `REQUIRE_ADMIN_2FA=true` (also on the Settings page) sends an admin with a local password and no second factor to Account until they add one. SSO and LDAP admins are exempt: their provider's policy applies.
- API tokens stop working when the admin who made them is deleted, disabled, demoted or changes their password.

## HTTP and host names

- With `PUBLIC_URL` set, requests for any other host name get 421, which shuts out DNS rebinding. `localhost`, `127.0.0.1` and `[::1]` are always accepted; add other names (say the mesh IP your CLI uses) to `ALLOWED_HOSTS`. Health, metrics and agent routes are exempt.
- HTTP Basic is accepted over plain HTTP by default, so it works on a private mesh. `API_BASIC_HTTPS_ONLY=true` refuses it unless the request came over HTTPS (directly or from a trusted proxy). Bearer tokens are unaffected.
- The sign-in page no longer says whether `admin` still has its one-time password. It is in `DATA_DIR/bootstrap-admin-password` on first start.
