# Minimalist Rust Mastodon-Compatible Server: Project Spec

(Working name: smallhold)

## What this is

A single-binary, SQLite-backed, Rust ActivityPub server that speaks the Mastodon Client API well enough that off-the-shelf Mastodon clients (Ivory, Phanpy, Elk, Tusky, Tuba) work against it without modification. Solo admin, multiple personas under one domain, designed for a few dozen actors total and federation volume you can measure in thousands of activities per day, not millions.

This is deliberately not Kitsune. Kitsune failed by scope creep (nomadic identity, experimental FEPs, multi-account-per-human, ambitious rewrites). See `kitsune-soc/kitsune` issue #681 for the retrospective before you write a line of code. The lesson: scope discipline is the primary engineering problem. Everything in this spec is a constraint, not a suggestion.

## Non-goals (explicit, enforce these)

- No signup flow, no invite system, no email verification, no captchas. Admin creates personas via CLI.
- No web admin UI. CLI only.
- No reports UI, no moderator queue, no user-facing blocking tools (you are your own moderator via CLI).
- No separate Redis, no separate job daemon, no separate search daemon. If it needs a sidecar service, you are doing too much.
- No experimental FEPs. No nomadic identity. No Bovine. No FEP-ef61. No multi-account-per-human.
- No per-persona domains. Same domain for all personas. Pseudonymity-requiring personas get a separate instance on a separate domain, not a virtual host on this one.
- No polls in v1. No lists in v1. No keyword filters in v1. No bookmarks in v1 (local-only, easy to add later). Return empty arrays or 404 for these endpoints. Clients handle it.
- No relay support in v1.
- No account migration *out*, but implement inbound `Move` and `alsoKnownAs` so migration *in* works. (Tiny cost, massive optionality.)
- No video transcoding. Images and GIFs only. Reject video uploads with a clean 422.
- No scale engineering. No Redis-backed timeline fanout. No sharding. Home timeline computes on read with a SQL query; at 30 users this is under 10 ms.
- No custom emoji *upload* in v1. Accept remote custom emoji inbound (cache them), don't offer upload UI.
- No Webpush notifications in v1 (VAPID keys, subscription management, payload encryption). Clients degrade to polling. Add in v2 if wanted.

## Hard constraints

- One binary. Statically linked where feasible (musl on Linux).
- One config file (`config.toml`).
- One data directory containing: SQLite file, WAL/SHM files, `media/` subdirectory, `keys/` subdirectory (optional, keys can live in DB).
- No network services other than the HTTP server itself.
- TLS termination via reverse proxy (caddy or nginx). Do not embed TLS.
- Memory footprint target: under 150 MB steady state for 30 active personas.
- Cold start to serving: under 2 seconds.

## Architecture overview

```
┌─────────────────────────────────────────────────────────┐
│                 reverse proxy (caddy)                   │
│              TLS, static media caching                  │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                   server binary (axum)                  │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │  Mastodon   │  │ ActivityPub │  │   WebFinger /   │ │
│  │  Client API │  │  S2S (in +  │  │   NodeInfo /    │ │
│  │  (axum)     │  │  out)       │  │   host-meta     │ │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘ │
│         │                │                   │          │
│  ┌──────▼────────────────▼───────────────────▼────────┐ │
│  │              core domain (posts, accounts,         │ │
│  │              follows, timelines, media)            │ │
│  └──────┬────────────────┬───────────────────┬────────┘ │
│         │                │                   │          │
│  ┌──────▼────────┐  ┌───▼──────────┐  ┌─────▼────────┐ │
│  │ SQLite (WAL)  │  │ tokio        │  │ filesystem   │ │
│  │ sqlx          │  │ broadcast    │  │ media/       │ │
│  │               │  │ (streaming)  │  │              │ │
│  └───────────────┘  └──────────────┘  └──────────────┘ │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  in-process delivery worker (tokio task)         │   │
│  │  polls delivery_queue table, does HTTP POST      │   │
│  │  with HTTP signatures, exponential backoff       │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘

       admin CLI (same binary, subcommand) talks to
       the SQLite directly; server does not have to
       be running for most admin ops
```

## Dependencies (pinned choices, not suggestions)

| Concern | Crate | Notes |
|---|---|---|
| HTTP server | `axum` | Tower middleware ecosystem |
| DB | `sqlx` with `sqlite` feature | Compile-time query checking, async |
| ActivityPub | `activitypub-federation` (LemmyNet) | HTTP sigs, delivery queue primitives, inbox verification |
| HTTP client | `reqwest` | With `rustls-tls`, not openssl |
| JSON | `serde_json` | |
| HTML sanitize | `ammonia` | Sanitize inbound remote HTML, sanitize outbound render |
| Markdown | `pulldown-cmark` | If accepting markdown input on local posts |
| Image processing | `image` + `fast_image_resize` | |
| Blurhash | `blurhash` | Mastodon clients expect this on every media attachment |
| Password hash | `argon2` | |
| OAuth2 | minimal custom impl | `oxide-auth` is heavyweight and had Kitsune-scale churn; rolling a minimal OAuth2 server for admin-issued tokens is maybe 500 lines |
| Snowflake IDs | custom | See section below. Do not take a dep for this. |
| Full-text search | `tantivy` | Deferred to v2 |
| Config | `serde` + `toml` | No `config` crate, no `figment` |
| Logging | `tracing` + `tracing-subscriber` | |
| CLI | `clap` v4 with derive | |
| Async runtime | `tokio` | |

`activitypub-federation` is the Lemmy crate. It's production-tested, it handles HTTP signature verification, outbound delivery with retries, and inbox dispatch. Caveat: it's designed around Lemmy's data model (communities, link posts), so the microblog mapping requires some friction. You'll wrap its traits around your own types. Do not rewrite HTTP signature handling. It is subtle and Kitsune got it wrong more than once.

## Data model

SQLite schema. `INTEGER` for IDs everywhere (64-bit time-sortable snowflakes, generated in code). All timestamps as Unix milliseconds (`INTEGER NOT NULL`). Do not use SQLite's `DATETIME`, it's a text type with no nanosecond precision and fights with your snowflake generator.

```sql
-- singleton, always id=1
CREATE TABLE admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,   -- argon2id
    totp_secret   TEXT,            -- optional TOTP
    created_at    INTEGER NOT NULL
);

CREATE TABLE accounts (
    id              INTEGER PRIMARY KEY,   -- snowflake
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    bio             TEXT NOT NULL DEFAULT '',
    bio_html        TEXT NOT NULL DEFAULT '',   -- rendered, sanitized
    private_key_pem TEXT NOT NULL,   -- RSA 2048 PKCS8 PEM
    public_key_pem  TEXT NOT NULL,   -- SPKI PEM
    avatar_media_id INTEGER REFERENCES media(id),
    header_media_id INTEGER REFERENCES media(id),
    is_locked       INTEGER NOT NULL DEFAULT 0,   -- manual follow approval
    discoverable    INTEGER NOT NULL DEFAULT 1,
    bot             INTEGER NOT NULL DEFAULT 0,
    fields_json     TEXT NOT NULL DEFAULT '[]',   -- profile metadata key/value pairs
    created_at      INTEGER NOT NULL,
    last_status_at  INTEGER
);
CREATE INDEX idx_accounts_username ON accounts(username);

-- remote actors we've interacted with
CREATE TABLE remote_accounts (
    id                  INTEGER PRIMARY KEY,   -- snowflake, local id for pagination
    actor_uri           TEXT NOT NULL UNIQUE,
    username            TEXT NOT NULL,
    domain              TEXT NOT NULL,
    display_name        TEXT NOT NULL,
    bio_html            TEXT NOT NULL DEFAULT '',
    avatar_url          TEXT,
    header_url          TEXT,
    public_key_pem      TEXT NOT NULL,
    public_key_id       TEXT NOT NULL UNIQUE,
    inbox_url           TEXT NOT NULL,
    shared_inbox_url    TEXT,
    followers_url       TEXT,
    is_locked           INTEGER NOT NULL DEFAULT 0,
    bot                 INTEGER NOT NULL DEFAULT 0,
    last_fetched_at     INTEGER NOT NULL,
    fetched_failed_at   INTEGER,        -- when resolution last failed
    fetch_fail_count    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_remote_accounts_webfinger ON remote_accounts(username, domain);

CREATE TABLE posts (
    id                INTEGER PRIMARY KEY,   -- snowflake
    account_id        INTEGER NOT NULL REFERENCES accounts(id),
    ap_id             TEXT NOT NULL UNIQUE,  -- our URL for this post
    in_reply_to_id    INTEGER,               -- local post id
    in_reply_to_uri   TEXT,                  -- remote URI if reply to remote
    boost_of_id       INTEGER,               -- local post id (boost target)
    boost_of_uri      TEXT,                  -- remote URI (boost of remote)
    content           TEXT NOT NULL,         -- original input (plaintext or markdown)
    content_html      TEXT NOT NULL,         -- rendered, sanitized, mention-linked
    spoiler_text      TEXT NOT NULL DEFAULT '',
    visibility        TEXT NOT NULL,         -- public | unlisted | private | direct
    sensitive         INTEGER NOT NULL DEFAULT 0,
    language          TEXT,                  -- BCP-47
    created_at        INTEGER NOT NULL,
    edited_at         INTEGER
);
CREATE INDEX idx_posts_account_created ON posts(account_id, created_at DESC);
CREATE INDEX idx_posts_in_reply_to ON posts(in_reply_to_id);

-- posts from remote actors (we cache these, they may be referenced as replies, boosts, etc.)
CREATE TABLE remote_posts (
    id                INTEGER PRIMARY KEY,   -- snowflake, local id for pagination
    ap_uri            TEXT NOT NULL UNIQUE,
    remote_account_id INTEGER NOT NULL REFERENCES remote_accounts(id),
    in_reply_to_uri   TEXT,
    content_html      TEXT NOT NULL,
    spoiler_text      TEXT NOT NULL DEFAULT '',
    visibility        TEXT NOT NULL,
    sensitive         INTEGER NOT NULL DEFAULT 0,
    language          TEXT,
    created_at        INTEGER NOT NULL,
    fetched_at        INTEGER NOT NULL
);
CREATE INDEX idx_remote_posts_account_created ON remote_posts(remote_account_id, created_at DESC);

-- one row per mention; links either a local post or a remote post to a mentioned account
CREATE TABLE mentions (
    post_id            INTEGER,   -- our post
    remote_post_id     INTEGER,   -- cached remote post
    mentioned_account_id INTEGER, -- local
    mentioned_remote_id  INTEGER, -- remote_accounts.id
    CHECK ((post_id IS NOT NULL) != (remote_post_id IS NOT NULL)),
    CHECK ((mentioned_account_id IS NOT NULL) != (mentioned_remote_id IS NOT NULL))
);
CREATE INDEX idx_mentions_post ON mentions(post_id);
CREATE INDEX idx_mentions_local ON mentions(mentioned_account_id);

CREATE TABLE media (
    id             INTEGER PRIMARY KEY,   -- snowflake
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    post_id        INTEGER REFERENCES posts(id),   -- null until attached
    file_path      TEXT NOT NULL,         -- relative to media/ dir
    mime_type      TEXT NOT NULL,
    file_size      INTEGER NOT NULL,
    width          INTEGER,
    height         INTEGER,
    blurhash       TEXT,
    description    TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL
);

CREATE TABLE follows (
    follower_id         INTEGER NOT NULL REFERENCES accounts(id),
    followee_id         INTEGER REFERENCES accounts(id),       -- local followee
    followee_remote_id  INTEGER REFERENCES remote_accounts(id), -- remote followee
    created_at          INTEGER NOT NULL,
    show_reblogs        INTEGER NOT NULL DEFAULT 1,
    notify              INTEGER NOT NULL DEFAULT 0,
    CHECK ((followee_id IS NOT NULL) != (followee_remote_id IS NOT NULL)),
    UNIQUE (follower_id, followee_id, followee_remote_id)
);
CREATE INDEX idx_follows_follower ON follows(follower_id);
CREATE INDEX idx_follows_followee ON follows(followee_id);
CREATE INDEX idx_follows_followee_remote ON follows(followee_remote_id);

CREATE TABLE follow_requests (
    id                  INTEGER PRIMARY KEY,
    requester_remote_id INTEGER NOT NULL REFERENCES remote_accounts(id),
    target_account_id   INTEGER NOT NULL REFERENCES accounts(id),
    ap_id               TEXT NOT NULL UNIQUE,   -- the Follow activity URI
    created_at          INTEGER NOT NULL
);

-- inbound followers: remote accounts that follow a local account
CREATE TABLE followers (
    local_account_id    INTEGER NOT NULL REFERENCES accounts(id),
    remote_account_id   INTEGER NOT NULL REFERENCES remote_accounts(id),
    accepted_at         INTEGER NOT NULL,
    UNIQUE (local_account_id, remote_account_id)
);
CREATE INDEX idx_followers_local ON followers(local_account_id);

CREATE TABLE favourites (
    account_id      INTEGER NOT NULL REFERENCES accounts(id),
    post_id         INTEGER REFERENCES posts(id),
    remote_post_id  INTEGER REFERENCES remote_posts(id),
    created_at      INTEGER NOT NULL,
    CHECK ((post_id IS NOT NULL) != (remote_post_id IS NOT NULL)),
    UNIQUE (account_id, post_id, remote_post_id)
);

CREATE TABLE notifications (
    id             INTEGER PRIMARY KEY,   -- snowflake
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    kind           TEXT NOT NULL,   -- mention | favourite | reblog | follow | follow_request
    from_account_id        INTEGER REFERENCES accounts(id),
    from_remote_account_id INTEGER REFERENCES remote_accounts(id),
    post_id        INTEGER REFERENCES posts(id),
    remote_post_id INTEGER REFERENCES remote_posts(id),
    created_at     INTEGER NOT NULL,
    read_at        INTEGER
);
CREATE INDEX idx_notifications_account_created ON notifications(account_id, created_at DESC);

CREATE TABLE oauth_apps (
    id            INTEGER PRIMARY KEY,
    client_id     TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,
    name          TEXT NOT NULL,
    website       TEXT,
    redirect_uri  TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE oauth_tokens (
    id             INTEGER PRIMARY KEY,
    token_hash     TEXT NOT NULL UNIQUE,   -- SHA-256 hex of the actual token
    app_id         INTEGER NOT NULL REFERENCES oauth_apps(id),
    account_id     INTEGER REFERENCES accounts(id),   -- null for app-only tokens
    scopes         TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    last_used_at   INTEGER,
    revoked_at     INTEGER
);

CREATE TABLE oauth_authz_codes (
    code_hash     TEXT PRIMARY KEY,
    app_id        INTEGER NOT NULL REFERENCES oauth_apps(id),
    account_id    INTEGER NOT NULL REFERENCES accounts(id),
    scopes        TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    expires_at    INTEGER NOT NULL
);

CREATE TABLE domain_blocks (
    domain         TEXT PRIMARY KEY,
    severity       TEXT NOT NULL,   -- silence | suspend
    reject_media   INTEGER NOT NULL DEFAULT 0,
    reject_reports INTEGER NOT NULL DEFAULT 0,
    reason         TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL
);

CREATE TABLE delivery_queue (
    id             INTEGER PRIMARY KEY,   -- snowflake
    target_inbox   TEXT NOT NULL,
    sender_account_id INTEGER NOT NULL REFERENCES accounts(id),
    activity_json  TEXT NOT NULL,         -- fully formed AP activity with @context
    attempts       INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_error     TEXT,
    created_at     INTEGER NOT NULL,
    delivered_at   INTEGER,
    dead_at        INTEGER                -- permanent failure
);
CREATE INDEX idx_delivery_pending ON delivery_queue(next_attempt_at) WHERE delivered_at IS NULL AND dead_at IS NULL;

CREATE TABLE idempotency_keys (
    key_hash       TEXT PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    post_id        INTEGER NOT NULL REFERENCES posts(id),
    created_at     INTEGER NOT NULL
);

-- migration support
CREATE TABLE also_known_as (
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    uri            TEXT NOT NULL,
    UNIQUE (account_id, uri)
);
```

Notes on the schema:
- The `(post_id OR remote_post_id)` CHECK pattern appears repeatedly. It's ugly but it avoids polymorphic FKs and keeps integrity. Consider a `post_refs` table if it bothers you, but the duplication is fine.
- No `statuses` (Mastodon's name). We call them `posts` internally; the Mastodon API layer translates to the `Status` object at serialization time.
- IDs are 64-bit time-sortable. See next section.
- `delivery_queue.target_inbox` lets us collapse outbound deliveries by shared inbox URL before enqueueing.

## Snowflake IDs

Mastodon clients depend on IDs being monotonically time-sortable 64-bit integers serialized as strings. `since_id`, `max_id`, `min_id` pagination *assumes* this. UUIDs do not work. Use a snowflake:

- 48 bits: Unix milliseconds (covers until year ~10889)
- 16 bits: per-process sequence counter (65k IDs/ms, more than enough)
- Stored as `INTEGER` in SQLite (it's 64-bit signed, fine)
- Serialized as string in JSON (`"id": "109381722483712"`) because JavaScript

Write a `SnowflakeGen` struct with `AtomicU64` or a `Mutex<u64>`. ~50 lines. Do not take a dep.

## Identity model

- One admin identity. Admin password hashed, TOTP optional.
- N persona accounts (`accounts` table). Each is a first-class ActivityPub actor with its own keypair, own actor URI (`https://yourdomain/users/writer`), own inbox (`https://yourdomain/users/writer/inbox`), own outbox, own followers/following collections.
- Shared inbox at `https://yourdomain/inbox` for remote servers delivering to multiple local actors.
- Admin mints OAuth2 tokens scoped to a single persona. Each client login uses one persona's token. Clients see N independent accounts.
- Cross-persona interaction is permitted (@writer can follow @editor). No internal firewall, because a leaky firewall is worse than no firewall. If you need real separation, separate instance, separate domain.

## Authentication

### Admin
- CLI only. `smallhold admin set-password`, `smallhold admin enable-totp`.
- No admin web UI.
- Admin can run `smallhold` subcommands directly against the SQLite file; server does not need to be running.

### OAuth2 (for Mastodon clients)
- Implement just enough of OAuth2 to make Mastodon clients work:
  - `POST /api/v1/apps` (register an app, returns client_id/client_secret)
  - `GET /oauth/authorize` (authorization page: admin logs in with password, selects persona, grants scopes)
  - `POST /oauth/token` (exchange code for token, or password grant for CLI-minted tokens)
  - `POST /oauth/revoke`
  - `POST /api/v1/apps/verify_credentials`
  - `GET /api/v1/accounts/verify_credentials` (clients hit this on login)
- Scopes: `read`, `write`, `follow`, `push`, `admin` (we ignore admin scope; no admin API).
- Authorization flow: admin logs in with password, picks which persona this token should authenticate as, submits.
- Token format: 64 random bytes, base64url. Stored in DB as SHA-256 hex. Never log tokens.
- Admin CLI can mint tokens directly for a persona: `smallhold admin mint-token writer --scopes=read,write,follow` prints the token once, never again.

## ActivityPub server-to-server

### What to implement (required for interop)

**Activity types to handle inbound:**
- `Create` of `Note` (new post, reply, mention, DM)
- `Create` of `Question` (poll from remote server; store as regular post, mark `has_poll=false` in our response, skip poll UI)
- `Update` of `Note` (edit)
- `Delete` of `Note` (or `Tombstone`)
- `Follow` (from remote actor to local actor; auto-accept unless `is_locked`)
- `Accept` of `Follow` (remote server accepted our outbound follow)
- `Reject` of `Follow`
- `Undo` of `Follow` (unfollow)
- `Undo` of `Like`
- `Undo` of `Announce` (unboost)
- `Like` (favorite)
- `Announce` (boost)
- `Block` (remote actor blocks us; remove their follow from our followers)
- `Undo` of `Block`
- `Move` (remote account migration; update `alsoKnownAs` on the moving actor, migrate our follow)
- `Update` of actor (remote actor updated profile)

**Activity types to generate outbound:**
- `Create` of `Note`
- `Update` of `Note`
- `Delete` of `Note`
- `Follow` / `Undo Follow`
- `Accept` of inbound `Follow` (auto, unless locked)
- `Like` / `Undo Like`
- `Announce` / `Undo Announce`
- `Update` of actor (when persona profile changes)

### What to skip
- Flag (reports). Drop inbound, don't generate outbound.
- Add/Remove (featured collections). Not supported.
- Listen, View, etc. (very rare, not in Mastodon's vocabulary).
- Public key rotation via `Update` is weird across implementations; don't rotate keys in v1. Add a CLI command that rotates + sends `Update` and test against Mastodon.social before shipping.

### HTTP signatures

Mastodon and most of the fediverse use draft-cavage-http-signatures-11, *not* RFC 9421. `activitypub-federation` handles this. Gotchas you'll hit:

- **POST** requests: sign `(request-target)`, `host`, `date`, `digest`. Digest is `SHA-256=<base64(sha256(body))>`.
- **GET** requests (authorized fetch): sign `(request-target)`, `host`, `date`. No digest. Mastodon 4.x has authorized fetch on by default for many instances; you must sign outbound GETs when fetching remote actor docs.
- `Date` header within 30 seconds of now, UTC, RFC 7231 format (`Tue, 07 Jun 2022 12:00:00 GMT`). Some servers are stricter.
- `keyId` resolves via HTTP GET (with `Accept: application/activity+json`) to the actor document. The `#main-key` fragment is part of the keyId; do not strip it.
- When verifying, fetch the keyId URL, parse the actor document, extract `publicKey.publicKeyPem`. Cache this aggressively (remote_accounts.public_key_pem, invalidate on signature failure).
- Signature algorithm: `rsa-sha256`. Do not accept `hs2019` from Mastodon; hs2019 is the spec but nobody uses it.

### Content-type negotiation

When fetching actor documents or activities, send `Accept: application/activity+json, application/ld+json; profile="https://www.w3.org/ns/activitystreams"`. When serving actor documents at `/users/:username`, content-negotiate:
- HTML request (browser): redirect to profile page or render minimal HTML
- `application/activity+json` or `application/ld+json`: serve the actor document

Some servers (looking at you, Pleroma) send `Accept: application/json` on fetches and get confused if you don't serve the AP document then. Default to serving the AP doc for `application/json` as well. This is a deviation from spec but it's what Mastodon does.

### JSON-LD

Don't do real JSON-LD processing. Nobody does. Emit hardcoded `@context` arrays that include all the extension terms you use:

```json
"@context": [
  "https://www.w3.org/ns/activitystreams",
  "https://w3id.org/security/v1",
  {
    "Hashtag": "as:Hashtag",
    "sensitive": "as:sensitive",
    "toot": "http://joinmastodon.org/ns#",
    "featured": {"@id": "toot:featured", "@type": "@id"},
    "discoverable": "toot:discoverable",
    "manuallyApprovesFollowers": "as:manuallyApprovesFollowers",
    "alsoKnownAs": {"@id": "as:alsoKnownAs", "@type": "@id"},
    "movedTo": {"@id": "as:movedTo", "@type": "@id"},
    "blurhash": "toot:blurhash",
    "focalPoint": {"@container": "@list", "@id": "toot:focalPoint"},
    "Emoji": "toot:Emoji"
  }
]
```

When parsing inbound, do key-lookup on the flat JSON. Ignore `@context` entirely on input. This is what everyone does; JSON-LD processing is not worth the pain.

## Mastodon Client API

Endpoint priority tiers. Implement strictly in order.

### Tier 1 (MVP; clients can log in and read)
- `GET /api/v1/instance` (instance metadata)
- `GET /api/v2/instance` (v2 variant, clients prefer this)
- `GET /api/v1/apps/verify_credentials`
- `GET /api/v1/accounts/verify_credentials`
- `POST /api/v1/apps`
- `GET /oauth/authorize`
- `POST /oauth/token`
- `GET /api/v1/accounts/:id`
- `GET /api/v1/accounts/lookup` (acct search, used by clients to resolve handles)
- `GET /api/v1/accounts/:id/statuses`
- `GET /api/v1/statuses/:id`
- `GET /api/v1/statuses/:id/context` (thread)
- `GET /api/v1/timelines/home`
- `GET /api/v1/timelines/public` (local + federated)
- `GET /api/v1/timelines/tag/:hashtag`
- `GET /api/v1/notifications`
- `GET /api/v1/preferences`
- `GET /api/v1/custom_emojis` (return `[]` for v1)
- `GET /api/v1/filters` (return `[]`)
- `GET /api/v2/filters` (return `[]`)
- `GET /api/v1/lists` (return `[]`)
- `GET /api/v1/markers` (timeline read position; local-only, simple)
- `POST /api/v1/markers`

### Tier 2 (posting, following, interacting)
- `POST /api/v1/statuses` (with `Idempotency-Key` handling)
- `DELETE /api/v1/statuses/:id`
- `POST /api/v1/statuses/:id/favourite`, `/unfavourite`
- `POST /api/v1/statuses/:id/reblog`, `/unreblog`
- `POST /api/v1/statuses/:id/bookmark`, `/unbookmark` (local-only)
- `POST /api/v1/accounts/:id/follow`, `/unfollow`
- `POST /api/v1/accounts/:id/block`, `/unblock`
- `POST /api/v1/accounts/:id/mute`, `/unmute`
- `GET /api/v1/accounts/relationships`
- `GET /api/v1/accounts/:id/followers`
- `GET /api/v1/accounts/:id/following`
- `POST /api/v1/media`, `POST /api/v2/media` (async media upload; clients poll with GET)
- `PUT /api/v1/media/:id` (update description)
- `GET /api/v1/media/:id`

### Tier 3 (nice to have)
- `GET /api/v1/accounts/:id/search`
- `GET /api/v2/search` (query, type filter)
- `GET /api/v1/bookmarks`
- `GET /api/v1/favourites`
- `GET /api/v1/follow_requests`
- `POST /api/v1/follow_requests/:id/authorize`
- `POST /api/v1/follow_requests/:id/reject`
- `PATCH /api/v1/accounts/update_credentials`
- `GET /api/v1/suggestions` (return `[]`)
- `GET /api/v1/trends/*` (return `[]`)
- `GET /api/v1/directory` (return `[]`)

### Tier 4 (skip in v1, return 404/501)
- Polls (`GET/POST /api/v1/polls/:id/*`)
- Lists (`GET/POST /api/v1/lists/*`)
- Push notifications (`POST /api/v1/push/subscription`, etc.)
- Scheduled statuses
- Conversations (DM-specific endpoint; DMs still work via regular statuses with `direct` visibility)
- Announcements
- Admin API (`/api/v1/admin/*`)
- Reports (`POST /api/v1/reports`)

### Streaming

`GET /api/v1/streaming/*` (SSE) and `GET /api/v1/streaming` (WebSocket). Both required, clients differ. Use tokio broadcast channel keyed by `(account_id, channel)`.

Channels to implement:
- `user` (home timeline + notifications for the authed persona)
- `public` (federated timeline)
- `public:local`
- `hashtag`, `hashtag:local`
- `direct` (DMs for the authed persona)

Event types: `update` (new status), `notification`, `delete` (just the status id), `status.update` (edit), `conversation` (new DM thread). That's it. Skip `filters_changed`, `announcement`, etc.

### Response shape quirks clients depend on

- `id` field is always a string, always numeric, always sort-ordered by creation time.
- `in_reply_to_id` and `in_reply_to_account_id` are either a string ID or `null`. Not empty string, not absent.
- `media_attachments` is always an array, never `null`, empty array if none.
- `mentions`, `tags`, `emojis` are always arrays.
- `Status.account.id` must match an account we can serve via `GET /api/v1/accounts/:id`. If a remote author, give them a local snowflake in `remote_accounts.id` and use that consistently.
- `Status.url` is the web URL; `Status.uri` is the ActivityPub ID. For local posts these may be the same.
- `Status.visibility` is one of `public`, `unlisted`, `private`, `direct`. Never `limited` (that's a Misskey-ism).
- `Status.reblog` is `null` for normal posts, or a full nested `Status` object for boosts. The outer Status is the "boost wrapper" with empty content and `reblog` pointing at the original.
- Thread order in `/api/v1/statuses/:id/context`: `ancestors` sorted oldest-first (root to parent), `descendants` sorted oldest-first (top-down tree flatten). Clients break if you reverse these.
- `Account.acct`: for local accounts, just `username`. For remote accounts, `username@domain`. Do *not* include the domain for local accounts; clients test this field to decide local vs remote.
- `Application`: the `application` field on a Status is the OAuth app the status was posted through. If admin-posted via CLI, put `{"name": "Web", "website": null}` to avoid client surprise.

### Pagination

`Link` header with `rel="next"` and `rel="prev"`:

```
Link: <https://yourdomain/api/v1/timelines/home?max_id=123456>; rel="next",
      <https://yourdomain/api/v1/timelines/home?min_id=789012>; rel="prev"
```

Clients parse this header. Don't add pagination info to the response body; clients won't look there.

### Idempotency-Key

On `POST /api/v1/statuses`, if the request includes `Idempotency-Key: <value>`, hash the value with SHA-256, check the `idempotency_keys` table for an existing row with this hash + account_id, return the existing post if found. Keep rows for 24 hours, prune in a background task. Without this, Ivory and similar clients will duplicate-post on network retries.

## WebFinger, NodeInfo, host-meta

### `/.well-known/webfinger?resource=acct:username@yourdomain`

```json
{
  "subject": "acct:username@yourdomain",
  "aliases": [
    "https://yourdomain/users/username",
    "https://yourdomain/@username"
  ],
  "links": [
    {"rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": "https://yourdomain/@username"},
    {"rel": "self", "type": "application/activity+json", "href": "https://yourdomain/users/username"},
    {"rel": "http://ostatus.org/schema/1.0/subscribe", "template": "https://yourdomain/authorize_interaction?uri={uri}"}
  ]
}
```

Return 404 if the username doesn't exist or the domain doesn't match yours.

### `/.well-known/nodeinfo`

```json
{
  "links": [
    {"rel": "http://nodeinfo.diaspora.software/ns/schema/2.0", "href": "https://yourdomain/nodeinfo/2.0"}
  ]
}
```

### `/nodeinfo/2.0`

```json
{
  "version": "2.0",
  "software": {"name": "smallhold", "version": "0.1.0"},
  "protocols": ["activitypub"],
  "services": {"inbound": [], "outbound": []},
  "openRegistrations": false,
  "usage": {
    "users": {"total": 1, "activeMonth": 1, "activeHalfyear": 1},
    "localPosts": 0
  },
  "metadata": {}
}
```

Note: `users.total` is deliberately `1`, not your persona count. Instance-level metrics, not persona count, because you're the only human. This is defensible and keeps persona count out of aggregators.

### `/.well-known/host-meta`

Return an XML document with a template pointing at your WebFinger. Some servers check this. ~10 lines, always the same.

## Federation gotchas (known compat traps)

- **Pleroma/Akkoma** send `Content-Type: application/activity+json; charset=utf-8`. Accept the charset parameter.
- **Misskey** emits `Emoji` objects with `id` fields that aren't URIs (just short codes). Tolerate this on inbound.
- **GoToSocial** requires signed fetches by default. Sign outbound GETs.
- **Lemmy** uses `Page` object type for posts instead of `Note`. You don't need to render Lemmy content natively but do not 500 on it; accept and ignore.
- **Mastodon** sends `Follow` activities where `object` is sometimes an object and sometimes a URI string. Handle both shapes on inbound. This is the single most common bug in AP implementations.
- **Announce** (boost) activities: the `object` can be a URI to a remote post you haven't fetched yet. You must fetch it synchronously or async-resolve before you can render the boost. Cache in `remote_posts` on fetch.
- **Delete** activities arrive for posts you've never seen. Ignore silently.
- **Delete** of an actor (signed by that actor) means the whole account is gone. Prune their posts, their follows from your `followers` and `follows`.
- **shared inbox delivery**: the `to` and `cc` fields on the activity tell you which local actors it's for. Route within your server.

## Delivery worker

In-process tokio task, polls `delivery_queue` every N seconds (configurable, default 5s). Fetches rows where `next_attempt_at <= now AND delivered_at IS NULL AND dead_at IS NULL ORDER BY next_attempt_at LIMIT <batch>`.

- Retry schedule: 1 min, 5 min, 30 min, 2 hr, 8 hr, 24 hr. Max 6 attempts, then mark `dead_at`.
- On 410 Gone: mark dead immediately, don't retry.
- On 4xx (other): mark dead after 1 retry.
- On 5xx or network error: exponential retry.
- Circuit breaker per target domain: if 10 consecutive failures against a domain, back off that domain for an hour.
- Dedup by shared inbox URL before enqueue: if three local personas all need to notify `https://mastodon.social/inbox`, enqueue one delivery with all three actors as senders. (Subtle: each actor signs its own activity. You can't share signatures. But you can share the HTTP connection via keepalive.)

## Media handling

- Upload: accept `multipart/form-data` on `POST /api/v2/media`. Return 202 with a status URL. Process async (spawn tokio task).
- Store original in `media/<first_two_chars_of_id>/<id>.<ext>`.
- Generate thumbnail: max 400x400 preserving aspect ratio, JPEG quality 85.
- Compute blurhash from a downscaled version (32x32 is plenty) using the `blurhash` crate.
- Reject video uploads with 422 and a helpful error.
- Accept: JPEG, PNG, WebP, GIF, HEIC (convert to JPEG on import if HEIC, uses `image` crate with `heif` feature).
- Max file size: 40 MB (Mastodon's default; clients validate against `/api/v1/instance` config).
- Expose via `GET /media/<path>` with long cache headers (1 year, immutable). Reverse proxy can serve these directly.

## Configuration

`config.toml`:

```toml
[server]
listen = "127.0.0.1:8080"
domain = "yourdomain.example"
secret_key = "<64 random hex chars; used for cookie signing>"

[storage]
database_path = "/var/lib/smallhold/db.sqlite"
media_dir = "/var/lib/smallhold/media"

[federation]
user_agent = "smallhold/0.1 (+https://yourdomain.example)"
delivery_timeout_secs = 30
delivery_concurrency = 16
fetch_timeout_secs = 20
max_incoming_body_mb = 10
authorized_fetch = true

[limits]
max_post_chars = 5000
max_attachments = 4
max_media_mb = 40

[defaults]
default_visibility = "public"
default_sensitive = false
default_language = "en"
```

## Admin CLI

```
smallhold init                            # create db, generate secret_key, write config skeleton
smallhold serve                           # start server
smallhold admin set-password
smallhold admin enable-totp
smallhold persona create <username> --display-name="..." [--locked] [--bot]
smallhold persona list
smallhold persona update <username> --bio="..." --display-name="..."
smallhold persona delete <username>       # sends Delete actor to followers, then removes
smallhold persona rotate-key <username>   # rotates RSA key, sends Update
smallhold token mint <username> --scopes=read,write,follow
smallhold token list
smallhold token revoke <token-id>
smallhold follow <username> <acct>        # persona follows remote, e.g. smallhold follow writer gargron@mastodon.social
smallhold unfollow <username> <acct>
smallhold domain-block <domain> --severity=silence|suspend [--reject-media] [--reason="..."]
smallhold domain-unblock <domain>
smallhold domain-block-list
smallhold queue inspect                   # show pending deliveries
smallhold queue retry-dead                # reset dead rows, try again
smallhold compat-test --target=mastodon.social --persona=writer
                                          # runs a canned suite of interop probes
```

Write the CLI first. It drives the data model. If the CLI is clean, the model is right.

## Build order (actual commit order for Claude Code)

### Phase 0: skeleton
1. Workspace layout, crates, config parsing, logging.
2. SQLite init + migrations (embed migration SQL with `sqlx-migrate`).
3. Snowflake generator.
4. Admin CLI skeleton with `init` and `persona create` commands.

### Phase 1: actor publication
5. Actor document endpoint (`GET /users/:username`, AP content negotiation).
6. WebFinger + NodeInfo + host-meta.
7. Web profile page (plain HTML, `GET /@username`, minimal).
8. Basic HTTP client with signed GETs (resolve remote actors).
9. `remote_accounts` cache + resolution pipeline.

**Definition of done:** you can curl your actor URI and get a valid AP document. Mastodon.social can fetch your WebFinger and display your profile. You can resolve a remote actor and cache them.

### Phase 2: inbound federation
10. Inbox endpoint with HTTP signature verification (`activitypub-federation`).
11. Handle inbound `Follow` (auto-accept, send `Accept`).
12. Handle `Undo Follow`.
13. Handle inbound `Create Note` (add to `remote_posts`, add mentions, create notifications if local actor mentioned).
14. Handle `Delete`, `Update`, `Like`, `Announce`, `Undo`.

**Definition of done:** a Mastodon user can follow your persona and see your (not yet existent) posts in their timeline. They can reply to you and you get a notification row.

### Phase 3: OAuth + client reads
15. `POST /api/v1/apps`, `POST /oauth/token` (client credentials + password + authz code).
16. `GET /oauth/authorize` with minimal HTML form for admin login.
17. Bearer auth middleware.
18. `GET /api/v1/instance`, `GET /api/v2/instance`.
19. `GET /api/v1/accounts/verify_credentials`.
20. `GET /api/v1/accounts/:id`, `/api/v1/accounts/lookup`.
21. `GET /api/v1/accounts/:id/statuses` (empty until you can post).
22. Tier 1 empty-array endpoints (`filters`, `lists`, `custom_emojis`, etc.).

**Definition of done:** Ivory or Elk can log in, land on the home timeline, show the profile. No posts yet.

### Phase 4: posting
23. `POST /api/v1/statuses` (with idempotency), renders HTML, parses mentions, parses hashtags.
24. Outbound `Create Note` to followers (via `delivery_queue`).
25. Delivery worker tokio task with retry + circuit breaker.
26. `GET /api/v1/statuses/:id`.
27. `DELETE /api/v1/statuses/:id` + outbound `Delete`.

**Definition of done:** you can post from a Mastodon client, your followers on mastodon.social see the post in their home timeline. You can delete it; they see the deletion.

### Phase 5: interactions
28. Favourite / unfavourite (+ outbound `Like` / `Undo Like`).
29. Boost / unboost (+ outbound `Announce` / `Undo Announce`).
30. Follow / unfollow (+ outbound `Follow` / `Undo Follow`).
31. `GET /api/v1/timelines/home` (SQL join across follows + local posts + favourited remote posts).
32. `GET /api/v1/timelines/public` (local and federated variants).
33. `GET /api/v1/statuses/:id/context` (thread reconstruction; this one will have bugs, test it explicitly).

### Phase 6: media
34. `POST /api/v2/media`, resize, blurhash, async processing.
35. Status with media_attachments.
36. `GET /api/v1/accounts/:id/followers`, `/following`.

### Phase 7: streaming
37. SSE streaming endpoint.
38. WebSocket streaming endpoint.
39. Notifications timeline (`GET /api/v1/notifications`).

### Phase 8: polish
40. `PATCH /api/v1/accounts/update_credentials`.
41. Profile fields, avatar, header upload.
42. Reply threading, `in_reply_to_account_id` resolution.
43. `alsoKnownAs` and inbound `Move` handling.
44. Domain block enforcement.
45. Hashtag timelines, `GET /api/v1/timelines/tag/:tag`.
46. Conversations via `direct` visibility posts (no dedicated endpoint needed, Mastodon clients work with just the `direct` visibility).
47. `GET /api/v2/search` (account/hashtag only; full-text deferred).

### Phase 9: compat hardening (do this against a live fediverse instance, not a mock)
48. Bugs found testing against mastodon.social, akkoma.social, misskey.io, sharkey.example, gotosocial.org, lemmy.world.
49. Client compat: Ivory, Elk, Phanpy, Tusky, Tuba.
50. Idempotency, rate limit headers, error response shapes.

## Compat test matrix

Maintain `docs/compat.md` with a table:

| Target | Follow in | Follow out | Reply in | Reply out | Boost in | Boost out | Like in | Like out | DM | Media | Edit | Delete | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mastodon.social (4.3) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |
| akkoma.dev | | | | | | | | | | | | | |
| misskey.io | | | | | | | | | | | | | |
| sharkey.*.* | | | | | | | | | | | | | |
| gts.superseriousbusiness.org | | | | | | | | | | | | | |
| lemmy.world | n/a | — | ✓ | — | ✓ | — | ✓ | — | n/a | — | — | — | reply/boost compat only |
| pixelfed.social | | | | | | | | | | | | | |

Update this every time you fix a bug. Release criterion: mastodon.social row all ✓, at least 3 of the others all ✓.

Client compat matrix (`docs/clients.md`):

| Client | Login | Timeline | Post | Media | Reply | Notifications | Streaming | Notes |
|---|---|---|---|---|---|---|---|---|
| Ivory (iOS) | | | | | | | | |
| Phanpy (web) | | | | | | | | |
| Elk (web) | | | | | | | | |
| Tusky (Android) | | | | | | | | |
| Tuba (GTK) | | | | | | | | |

## Pseudonymity notes (informational, not v1 scope)

Same-domain means all personas are attributable to one operator. This is a feature for alts, a bug for literary-imprint separation. Things that will correlate same-domain personas beyond the obvious domain string:

- Post timing (consider outbound queue jitter if you care).
- TLS cert SANs (if only one persona is named on the cert, that's fine; don't SAN-list all personas).
- Server IP address (all personas post from the same v4/v6).
- Outbound TLS fingerprint (JA3/JA4; deterministic per-binary, not per-persona).
- `instance.contact_account` (default-leaks one persona; make it configurable or null).
- HTTP response error wordings (not persona-specific but instance-fingerprintable; not a persona correlation vector but an instance-identification vector).
- NodeInfo software version string (instance-level, not persona level).

If you need real pseudonymity for a specific persona (literary imprint), run a separate instance on a separate VPS on a separate domain with a separate TLS cert, connected via a separate outbound IP. Same codebase is fine; same process is not.

## Development methodology notes for Claude Code

- **Write the CLI first.** If you can `smallhold persona create writer` and inspect the DB to see a sane row, your data model is right. If the CLI is awkward, stop and reshape the model before writing one HTTP handler.
- **Compat test harness in week one.** Before you write `/api/v1/statuses`, have a Docker Compose that runs your server plus a local Mastodon instance plus (at minimum) Phanpy pointed at your server. Every commit that touches the client API surface runs the harness.
- **Do not try to implement the whole Mastodon API before federating.** Phase 1 (actor doc + WebFinger) plus Phase 2 (inbox) gets you federating as a read-only entity that Mastodon users can follow. That's the riskiest interop surface; derisk it first.
- **Use `activitypub-federation` even if it chafes.** Its data model is shaped for Lemmy. You will wrap. Do not rewrite HTTP signature handling. You will get it wrong.
- **Canary against mastodon.social.** The reference Ruby implementation is the spec. If it differs from your implementation, your implementation is wrong, regardless of what the docs say.
- **Monotonic snowflake IDs, string-serialized, 64-bit. Do not negotiate on this.** Ten different things depend on this invariant.
- **Do not log tokens, activity bodies in full at INFO level, or remote actor private details.** Log activity type + target + status at INFO; full bodies at TRACE only.
- **SQLite PRAGMAs on startup:** `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000`, `cache_size=-64000` (64 MB).
- **No `unwrap()` in handler paths.** Handlers return `Result<Response, AppError>` where `AppError` maps to HTTP status codes. Mastodon clients depend on specific error response shapes (`{"error": "<human message>"}` for 4xx).
- **Response format matching:** when in doubt, curl mastodon.social's response for the same endpoint with the same params and match the shape byte-for-byte modulo values.

## Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| HTTP signature edge case breaks federation with one major impl | High | Medium | Use `activitypub-federation`, canary against mastodon.social on every release |
| Client compat regression silently breaks Ivory/Phanpy | High | High | Compat harness in CI, manual smoke test before tag |
| SQLite WAL corruption under concurrent delivery worker + web server | Low | Catastrophic | `busy_timeout`, single writer thread convention, periodic `PRAGMA integrity_check` |
| Delivery queue wedging on dead remote domains | Medium | Medium | Circuit breaker per domain, `dead_at` marker, `queue inspect` CLI |
| Persona key compromise | Low | High | Keys in DB, filesystem perms 600, `rotate-key` CLI exists for recovery |
| ActivityPub spec shift (FEP adoption) | Medium | Low | Scope excludes FEPs; ignore inbound fields you don't know |
| Mastodon API adds a required field in a future version | Medium | Low | Clients degrade gracefully for unknown fields; add in response to bug reports |
| Operator (you) getting bored after phase 4 | High | Catastrophic | Phase 4 is a working single-user instance. Ship phase 4 as 0.1.0, accept that later phases are optional |

## References

- Mastodon docs: `https://docs.joinmastodon.org/api/` and `https://docs.joinmastodon.org/spec/activitypub/`
- ActivityPub spec: `https://www.w3.org/TR/activitypub/`
- ActivityStreams 2.0 vocab: `https://www.w3.org/TR/activitystreams-vocabulary/`
- WebFinger RFC 7033
- HTTP Signatures draft-cavage-11: `https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-11`
- `activitypub-federation-rust`: `https://github.com/LemmyNet/activitypub-federation-rust`
- Kitsune postmortem: `https://github.com/kitsune-soc/kitsune/issues/681`
- GoToSocial (existence proof, Go): `https://github.com/superseriousbusiness/gotosocial`
- snac (minimalist C): `https://codeberg.org/grunfink/snac2`
- honk (minimalist Go): `https://humungus.tedunangst.com/r/honk`
- microblog.pub (minimalist Python): `https://microblog.pub`

## Questions that need answers before coding

1. Name. See top of doc.
2. License. AGPLv3 (matches Kitsune, Mastodon; strongest network copyleft) vs MIT (easier adoption, weaker protection). Recommend AGPLv3; this is not a library.
3. Deployment target. Single Linux binary via musl? Docker image? Both? Recommend musl binary first, Docker image is trivial follow-on.
4. Initial persona list and domain. Both needed before you can start federation testing.
5. Should admin `/oauth/authorize` login page include captcha or rate-limiting? Recommend no captcha, yes rate-limit (3 failed logins per minute, IP-based, in-memory).
6. Do you want a minimal public-facing web UI (see profile, see single post) or redirect everything to raw JSON? Recommend a ~200 line server-rendered HTML view. People will paste your post URLs and expect them to render.
7. Are any personas going to be high-volume (hundreds of posts/day)? If yes, reconsider the "home timeline on read" plan for that persona specifically.

## Final meta-note for Claude Code

If a design decision in this doc conflicts with what a running Mastodon instance actually does, Mastodon wins. If a decision conflicts with what `activitypub-federation-rust` expects, take the path of least resistance (wrap, don't fight). If something in this doc is ambiguous, prefer the simpler interpretation and note the deviation in the commit message.

Resist adding features. The Mastodon API is large enough that the temptation to implement Tier 4 endpoints or "nice to have" features is constant. Every endpoint you add beyond Tier 3 is surface area you have to maintain compat on forever. The constraint is not "what does Mastodon have" but "what do the clients require to function." Those are different sets.
