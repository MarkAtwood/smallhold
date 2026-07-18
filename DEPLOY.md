# Deploying smallhold

## Requirements

- A Linux x86_64 server (any VPS — $5-6/month is fine)
- A domain name with DNS pointing at the server
- Nothing else. No Redis, no PostgreSQL, no Docker.

## Docker (fastest path)

```bash
# 1. Clone and set your domain
git clone https://github.com/yourname/smallhold && cd smallhold
export SMALLHOLD_DOMAIN=yourdomain.example

# 2. Initialize data directory
mkdir -p data
docker compose run --rm smallhold init --config /data/config.toml
# Edit data/config.toml — set domain, check paths

# 3. Create persona and set password
docker compose run --rm smallhold persona create writer --display-name="Your Name" --config /data/config.toml
echo "yourpassword" | docker compose run --rm -T smallhold admin set-password --config /data/config.toml

# 4. Start
docker compose up -d
```

Caddy handles TLS automatically. Your instance is live at `https://yourdomain.example`.

Data lives in `./data/` (SQLite database, media files, config). Back up this directory.

## Bare metal (no Docker)

### Build

```bash
cargo build --release
# Binary: target/release/smallhold (~19MB, dynamically linked)
```

For a static binary (no glibc dependency):

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Deploy

### 1. Copy the binary

```bash
scp target/release/smallhold root@yourserver:/opt/smallhold/smallhold
```

### 2. Initialize

```bash
ssh root@yourserver
cd /opt/smallhold
./smallhold init
```

This creates `config.toml` with a generated secret key, an empty SQLite database, and a `media/` directory.

### 3. Edit config

```bash
vi config.toml
```

Set your domain:

```toml
[server]
listen = "127.0.0.1:8080"
domain = "yourdomain.example"
```

The server listens on localhost. The reverse proxy handles TLS and public-facing traffic.

### 4. Set admin password and create a persona

```bash
./smallhold admin set-password
./smallhold persona create writer --display-name="Your Name"
```

### 5. Install Caddy (recommended reverse proxy)

```bash
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install caddy
```

### 6. Configure Caddy

```
# /etc/caddy/Caddyfile
yourdomain.example {
    reverse_proxy 127.0.0.1:8080

    handle_path /media/* {
        root * /opt/smallhold/media
        file_server
        header Cache-Control "public, max-age=31536000, immutable"
    }
}
```

Caddy automatically provisions a Let's Encrypt TLS certificate. No configuration needed.

**nginx alternative:**

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.example;

    ssl_certificate /etc/letsencrypt/live/yourdomain.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.example/privkey.pem;

    location /media/ {
        alias /opt/smallhold/media/;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (streaming)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### 7. Create systemd service

```ini
# /etc/systemd/system/smallhold.service
[Unit]
Description=smallhold fediverse server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/smallhold
ExecStart=/opt/smallhold/smallhold serve
Environment=RUST_LOG=smallhold=info
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable smallhold
systemctl start smallhold
```

### 8. Verify

```bash
# Check the service
systemctl status smallhold

# Health check
curl http://127.0.0.1:8080/health

# WebFinger (from outside)
curl https://yourdomain.example/.well-known/webfinger?resource=acct:writer@yourdomain.example

# Connect a client
# Open https://phanpy.social, enter yourdomain.example
```

## Backup

The entire instance state is two things:

```
/opt/smallhold/smallhold.db    # SQLite database (all data)
/opt/smallhold/media/          # Uploaded images
```

Backup both. For a live backup without stopping the server:

```bash
sqlite3 /opt/smallhold/smallhold.db ".backup /backups/smallhold-$(date +%Y%m%d).db"
rsync -a /opt/smallhold/media/ /backups/media/
```

## Restore

```bash
systemctl stop smallhold
cp /backups/smallhold-20260718.db /opt/smallhold/smallhold.db
rsync -a /backups/media/ /opt/smallhold/media/
systemctl start smallhold
```

## Migrate from Mastodon

```bash
# On Mastodon: Settings > Import and export > Request your archive
# Download the .tar.gz when the email arrives

./smallhold import mastodon writer ~/Downloads/archive-*.tar.gz
```

This imports your posts (with original timestamps), profile, media, and following list.

## CDN

smallhold is CDN-friendly. The server sets appropriate `Cache-Control` headers on every response:

| Path | Cache | TTL |
|------|-------|-----|
| `/media/*` | Immutable | 1 year (set by reverse proxy) |
| `/.well-known/*`, `/nodeinfo/*` | Public | 5 minutes |
| `/users/*` (actor docs) | Public | 1 minute |
| `/@*` (profile/post pages) | Public | 1 minute |
| `/users/*/feed.*` (RSS/Atom) | Public | 5 minutes |
| `/api/*`, `/oauth/*`, `/inbox` | No-store | Never cached |
| `/api/v1/streaming/*` | N/A | WebSocket, pass-through |

**CloudFront setup:** Create a distribution with your domain as the origin. Set "Cache based on origin Cache-Control headers" and it just works.

**Cloudflare setup:** Point DNS through Cloudflare. Default caching rules respect our headers. Enable WebSocket support in the dashboard for streaming.

## Multiple personas

One smallhold instance supports multiple personas under the same domain:

```bash
./smallhold persona create writer --display-name="Professional"
./smallhold persona create personal --display-name="Personal"
./smallhold persona create bot --display-name="Bot Account" --bot
```

Each persona is an independent ActivityPub actor with its own keypair, inbox, followers, and timeline. Mastodon clients see them as separate accounts — select which persona to use at the OAuth login screen.

## Custom theming

### Design tokens (for brand teams)

Drop a `tokens.json` file and set `branding.theme_tokens_path` in config:

```json
{
  "color": {
    "primary": { "$value": "#0066cc", "$type": "color" },
    "background": { "$value": "#ffffff", "$type": "color" },
    "text": { "$value": "#1d1d1f", "$type": "color" }
  },
  "color-dark": {
    "primary": { "$value": "#2997ff", "$type": "color" },
    "background": { "$value": "#1d1d1f", "$type": "color" },
    "text": { "$value": "#f5f5f7", "$type": "color" }
  }
}
```

### Custom CSS

Drop a CSS file and set `branding.custom_css_path` in config:

```css
:root { --link: #e4002b; }
body { font-family: "Helvetica Neue", sans-serif; }
```

## Monitoring

The `/health` endpoint returns `{"status":"ok"}` when the server is running. Point your uptime monitor at it.

Logs go to stdout/journald:

```bash
journalctl -u smallhold -f              # live tail
journalctl -u smallhold --since today   # today's logs
```

Set `RUST_LOG=smallhold=debug` for verbose output during debugging.

## Updating

```bash
# Build new version
cargo build --release

# Deploy (zero-downtime with systemd)
cp target/release/smallhold /opt/smallhold/smallhold.new
systemctl stop smallhold
mv /opt/smallhold/smallhold.new /opt/smallhold/smallhold
systemctl start smallhold
```

SQLite schema migrations run automatically on startup.

## Security checklist

- [ ] Reverse proxy terminates TLS (smallhold never handles TLS)
- [ ] `config.toml` is readable only by the service user (`chmod 600`)
- [ ] `smallhold.db` is readable only by the service user
- [ ] Firewall allows only 22, 80, 443 inbound
- [ ] Admin password is set and strong
- [ ] `authorized_fetch = true` in config (signed GETs for actor resolution)
- [ ] Backups run daily

## Resource usage

At the target scale (a few dozen personas, thousands of activities/day):

- **Memory:** Under 150 MB steady state
- **Disk:** SQLite database grows slowly; media is the main disk consumer
- **CPU:** Negligible. Image processing on upload is the only CPU-intensive operation.
- **Cold start:** Under 2 seconds

A $5-6/month VPS (1 vCPU, 1 GB RAM) is more than sufficient.
