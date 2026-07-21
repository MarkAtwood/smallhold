# smallhold

A single-binary, SQLite-backed Rust server for the fediverse. One backend, every fediverse client API.

**One binary. One config file. One SQLite database. No Redis. No sidecars. No signup flow.**

Designed for a solo operator running a few dozen personas under one domain. Federation volume in the thousands of activities per day, not millions. Cold start under two seconds, steady-state memory under 150 MB.

---

## Client compatibility

Smallhold speaks eight fediverse client APIs simultaneously. Use your preferred app:

| API | What | Clients |
|-----|------|---------|
| **Mastodon** | Microblogging — statuses, timelines, notifications, OAuth | Phanpy, Ivory, Elk, Tusky, Tuba, Ice Cubes |
| **Pixelfed** | Photo sharing — albums, trending, discover | Pixelfed web, Vernissage |
| **Lemmy** | Communities — threaded posts, comments, voting | Lemmy web, Jerboa, Voyager |
| **PeerTube** | Video — channels, uploads | PeerTube web |
| **Misskey** | Microblogging variant — emoji reactions, POST-only API | Misskey web, Milktea |
| **Funkwhale** | Audio — tracks, albums, channels, playlists | Funkwhale web |
| **Bookwyrm** | Books — shelves, reviews, ratings | Bookwyrm web |
| **WriteFreely** | Long-form — articles, blogs, collections, markdown | WriteFreely web, write.as clients |

All served from the same binary, same database, same personas. One account works with every client.

Smallhold does not ship a web frontend. It is a pure API server — bring whichever client you prefer. This is a deliberate choice: existing clients (Phanpy, Elk, Ivory, Tusky, etc.) are mature, well-maintained, and better than anything we'd build. We focus on the protocol layer.

---

## What this is not

- Not for public signups. Admin creates personas via CLI.
- Not horizontally scalable. SQLite on one machine.
- Not a drop-in Mastodon replacement. Missing: polls, admin API. Clients degrade gracefully.

---

## Quick start

```bash
cargo build --release
./smallhold init
# Edit config.toml — set your domain
./smallhold admin set-password
./smallhold persona create writer --display-name="Your Name"
./smallhold serve
```

Put a reverse proxy (Caddy or nginx) in front for TLS. See [DEPLOY.md](DEPLOY.md) for full instructions.

---

## Features

**Federation:**
- Full ActivityPub S2S — follow, post, reply, boost, like, edit, delete, block, move
- HTTP Signatures (draft-cavage-11) with authorized fetch
- Delivery worker with exponential backoff and per-domain circuit breaker
- DID support (did:scid, did:key, did:web) with BIP-39 mnemonic recovery
- Verified working with Mastodon, Misskey, Lemmy, Pixelfed, PeerTube

**Content modes:**
- Microblogging (Mastodon/Misskey) — statuses, replies, boosts, favourites
- Photo sharing (Pixelfed) — albums, photo grid gallery, trending
- Video hosting (PeerTube) — channels, HLS transcoding pipeline
- Communities (Lemmy) — threaded posts, comments, upvotes/downvotes
- Audio/Music (Funkwhale) — tracks, albums, playlists, podcast RSS
- Book tracking (Bookwyrm) — shelves, reviews, ratings, search
- Long-form writing (WriteFreely) — articles, collections, markdown rendering

**Web pages:**
- Profile pages with posts, stats, metadata fields
- Photo gallery (`/users/{name}/photos`) — responsive CSS grid
- RSS and Atom feeds per persona
- Dark mode via `prefers-color-scheme`
- W3C Design Tokens theming + custom CSS

**Media:**
- Image upload (JPEG, PNG, GIF, WebP) with EXIF stripping
- Blurhash computation, decompression bomb protection
- MIME sniffing from magic bytes

**Search:**
- Full-text search via tantivy

---

## Architecture

Built on [fieldwork](https://github.com/MarkAtwood/fedistract) — shared fediverse building blocks.

```
reverse proxy (Caddy / nginx)
         |
smallhold binary  (axum, tokio)
  ├── Client APIs (Mastodon, Pixelfed, Lemmy, PeerTube, Misskey, Funkwhale, Bookwyrm, WriteFreely)
  ├── ActivityPub S2S (inbox, outbox, actors, DID)
  ├── WebFinger / NodeInfo
  ├── Full-text search (tantivy)
  ├── SQLite via sqlx (WAL mode)
  ├── Streaming (SSE + WebSocket)
  └── Delivery worker (retry, circuit breaker)
```

---

## Security

- SSRF protection on all outbound HTTP
- HTML sanitization via ammonia
- HTTP signature verification with Date freshness check
- OAuth: redirect_uri validation, constant-time secret comparison
- Media: MIME sniffing, EXIF stripping, decompression bomb limits
- Rate limiting on login and token exchange

---

## Multiple personas

```bash
smallhold persona create writer --display-name="Professional"
smallhold persona create personal --display-name="Personal"
smallhold persona create bot --display-name="Bot" --bot
```

Each persona is an independent ActivityPub actor with its own keypair, inbox, followers, and DID. All personas share one domain, one process, one database.

---

## License

AGPL-3.0.
