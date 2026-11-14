# Behind a reverse proxy

Run clamv-webui on its own host name (for example `clamav.example.com`). Serving it under a path such as `/clamav/` is not supported.

## What the app needs

| Setting | Value |
|---|---|
| `TRUSTED_PROXIES` | The proxy's address or network, e.g. `172.18.0.0/16` for a Docker network. Only these peers may set `X-Forwarded-For` and `X-Forwarded-Proto`. Leave it empty when nothing sits in front. |
| `PUBLIC_URL` | The address users open, e.g. `https://clamav.example.com`. Passkeys are tied to this host name. |
| `COOKIE_SECURE` | `true` once users only reach the app over HTTPS. Cookies are also marked Secure on any request a trusted proxy reports as HTTPS. |

The proxy must:

- pass the original `Host` header (the app checks that form posts come from the same host);
- set `X-Forwarded-For` and `X-Forwarded-Proto`;
- allow request bodies of at least `CLAMD_MAX_STREAM_MB` (1 GB by default) for uploads;
- allow responses to take at least 60 seconds on `/agent/` (agents long-poll for 25 s) and on scans.

With `TRUSTED_PROXIES` set, the client address in the audit log, the sign-in lockout and the logs is the one the proxy reports. Requests from any other peer are judged by their own address, so a client cannot spoof it by sending the headers itself. Keep port 8080 reachable only from the proxy.

Set HSTS at the proxy, not in the app: `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Start with a short `max-age` until HTTPS works everywhere.

## Caddy

```caddyfile
clamav.example.com {
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    request_body {
        max_size 1100MB
    }
    reverse_proxy clamv-webui:8080 {
        transport http {
            read_timeout 120s
        }
    }
}
```

Caddy passes `Host` and sets `X-Forwarded-For` and `X-Forwarded-Proto` by itself.

## Traefik (Docker labels)

```yaml
    labels:
      - traefik.enable=true
      - traefik.http.routers.clamav.rule=Host(`clamav.example.com`)
      - traefik.http.routers.clamav.entrypoints=websecure
      - traefik.http.routers.clamav.tls.certresolver=le
      - traefik.http.routers.clamav.middlewares=clamav-hsts
      - traefik.http.middlewares.clamav-hsts.headers.stsSeconds=31536000
      - traefik.http.middlewares.clamav-hsts.headers.stsIncludeSubdomains=true
      - traefik.http.services.clamav.loadbalancer.server.port=8080
```

Traefik has no body size limit by default. Raise `respondingTimeouts.readTimeout` on the entry point if long uploads are cut off.

## nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name clamav.example.com;
    ssl_certificate     /etc/ssl/clamav.crt;
    ssl_certificate_key /etc/ssl/clamav.key;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    client_max_body_size 1100m;

    location / {
        proxy_pass http://clamv-webui:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_request_buffering off;
    }
}
```

## clamctl and MCP

Point `clamctl` and the MCP server at the public HTTPS URL. API tokens work through the proxy unchanged.

## Agents

Agents can reach the server through the proxy (`AGENT_SERVER_URL=https://clamav.example.com`) or directly over the mesh. Through the proxy, the certificate is checked against the system roots, or pin it with `AGENT_SERVER_FINGERPRINT`.
