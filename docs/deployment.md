# Deployment Guide

## Reverse Proxy Requirement

smallhold **must** run behind a reverse proxy. It does not perform TLS termination, rate limiting, or connection management itself — these are delegated to the infrastructure layer.

### Why

| Concern | Why not in-app |
|---------|----------------|
| TLS termination | Let's Encrypt integration, certificate rotation, OCSP stapling are proxy concerns |
| Rate limiting | In-memory counters don't survive restarts, are trivially bypassed by rotating IPs |
| Connection limits | Proxy tracks connections across all endpoints; app sees only individual requests |
| Request size limits | Reject oversized bodies before they reach the application |
| IP extraction | Proxy sets `X-Real-IP` / `X-Forwarded-For` from the actual client |

### Recommended: Caddy

Caddy handles TLS automatically via Let's Encrypt and has simple rate limiting.

```caddy
your.domain {
    # TLS is automatic with Caddy

    # Rate limiting on auth endpoints (requires caddy-ratelimit plugin)
    @auth {
        path /oauth/* /admin/webauthn/*
    }
    rate_limit @auth {
        zone auth_zone {
            key {remote.ip}
            events 5
            window 1m
        }
    }

    # Proxy to smallhold
    reverse_proxy localhost:3000 {
        # Pass real client IP
        header_up X-Real-IP {remote.ip}
        header_up X-Forwarded-For {remote.ip}
        header_up X-Forwarded-Proto {scheme}

        # WebSocket support (for streaming)
        transport http {
            versions h2c 1.1
        }
    }

    # Request size limit (40MB for media uploads)
    request_body {
        max_size 40MB
    }
}
```

### Alternative: nginx

```nginx
# In http {} context (e.g., /etc/nginx/conf.d/limits.conf):
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_conn_zone $binary_remote_addr zone=streaming:10m;

server {
    listen 443 ssl http2;
    server_name your.domain;

    ssl_certificate     /etc/letsencrypt/live/your.domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain/privkey.pem;

    # Request size limit
    client_max_body_size 40m;

    # Login/OAuth/WebAuthn endpoints — strict rate limit
    location ~ ^/(oauth/|admin/webauthn/) {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://127.0.0.1:3000;
        include proxy_params;
    }

    # Streaming — connection limit
    location /api/v1/streaming {
        limit_conn streaming 4;
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
        include proxy_params;
    }

    # Everything else
    location / {
        proxy_pass http://127.0.0.1:3000;
        include proxy_params;
    }
}

# proxy_params file:
# proxy_set_header X-Real-IP $remote_addr;
# proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
# proxy_set_header X-Forwarded-Proto $scheme;
# proxy_set_header Host $host;
```

### Required proxy behaviors

1. **TLS termination** — smallhold listens on plain HTTP (default port 3000)
2. **X-Real-IP header** — required if app-level IP logging is added in future; proxy should always set it
3. **WebSocket upgrade** — required for `/api/v1/streaming`
4. **Rate limiting on auth endpoints** — `POST /oauth/authorize`, `POST /oauth/token`, `POST /oauth/authorize/webauthn/*`, `POST /admin/webauthn/register/begin` — recommend 5 requests/minute per IP
5. **Connection limits on streaming** — recommend 4 concurrent connections per IP to `/api/v1/streaming`
6. **Request body size** — 40MB (matches `limits.max_media_mb` default)
7. **Security headers** — the application does not set these; the proxy must:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: same-origin`
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains`
   - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; frame-ancestors 'none'` (on HTML pages)
8. **Cache-Control** — the proxy should set per-path caching:
   - `/api/*`, `/oauth/*`, `/inbox`: `no-store`
   - `/.well-known/*`, `/nodeinfo`: `public, max-age=300`
   - `/users/*`: `public, max-age=60`
   - `/media/*`: `public, max-age=31536000, immutable`

### What happens without a proxy

- No TLS — federation peers will refuse to connect (ActivityPub requires HTTPS)
- No rate limiting — brute-force attacks on admin password are uncapped
- No connection limits — a single client can exhaust server resources via streaming
- No security headers — XSS, clickjacking, MIME sniffing attacks possible
- `X-Real-IP` will be missing — all requests appear from 127.0.0.1

## Configuration

smallhold reads `config.toml` from the working directory (or path specified via `--config`).

```toml
[server]
listen = "127.0.0.1:3000"  # Only bind to loopback — proxy handles external traffic
domain = "your.domain"
secret_key = "at-least-32-chars-random-string"

[storage]
database_path = "./data/smallhold.db"
media_dir = "./data/media"

[federation]
user_agent = "smallhold/0.3.0 (+https://your.domain)"
delivery_timeout_secs = 30
fetch_timeout_secs = 15
delivery_concurrency = 10
```

## Docker

```bash
docker run -d \
  --name smallhold \
  -p 127.0.0.1:3000:3000 \
  -v ./data:/data \
  -v ./config.toml:/config.toml:ro \
  markatwood/smallhold:latest
```

Note: bind to `127.0.0.1` only — never expose port 3000 directly to the internet.
