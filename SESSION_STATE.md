# Session State — smallhold planning session

Date: 2026-04-22

## What happened this session

This was a pure planning session. No Rust code was written. The deliverables were:

1. **CLAUDE.md** — project-specific AI agent instructions (tech stack, build phases, critical invariants, API conventions, DB conventions, federation gotchas, delivery worker spec)
2. **AGENTS.md** — agent workflow instructions (non-interactive shell flags, canary testing protocol, cargo quality gates, beads integration)
3. **README.md** — project README framed as shipped
4. **PRFAQ.md** — Amazon-style press release + FAQ framed as shipped
5. **Beads issue tracker** — fully populated with 260 issues across 10 build phases + 11 bonus features

## Beads state

**260 total issues, 257 open, 3 closed** (the 3 closed are duplicate epics that were superseded).

### Phase epics (build order)

| ID | Phase | Description |
|----|-------|-------------|
| smallhold-oji | Phase 0 | Workspace layout, config, SQLite migrations, snowflake gen, CLI skeleton |
| smallhold-dnc | Phase 1 | Actor doc, WebFinger, NodeInfo, host-meta, remote actor resolution |
| smallhold-pvj | Phase 2 | Inbox + HTTP sig verification, inbound Follow/Create/Delete/Like/Announce |
| smallhold-loj | Phase 3 | OAuth2 + client reads (Tier 1 endpoints) |
| smallhold-4xr | Phase 4 | Posting (POST /statuses, delivery worker, idempotency) |
| smallhold-w59 | Phase 5 | Interactions (favourite, boost, follow, home/public timelines, thread context) |
| smallhold-f1h | Phase 6 | Media (upload, resize, blurhash, async processing) |
| smallhold-v72 | Phase 7 | Streaming (SSE + WebSocket channels) |
| smallhold-s70 | Phase 8 | Polish (profile update, alsoKnownAs/Move, domain blocks, hashtag timelines, search) |
| smallhold-352 | Phase 9 | Compat hardening against live fediverse instances |

### Feature epics added this session (all v1 scope)

| ID | Feature | Effort |
|----|---------|--------|
| smallhold-m6xg | Content warnings (spoiler_text) | Trivial — column + serialization |
| smallhold-ijui | Pinned posts per persona | Trivial — column + 2 endpoints |
| smallhold-2e0y | Account mutes | Small — 1 table + timeline filter |
| smallhold-fxty | Health/readiness endpoints | Trivial — 3 lines |
| smallhold-ymt9 | RSS/Atom feed per persona | Small — pure string generation |
| smallhold-4iru | Scheduled posts | Small — extends delivery worker |
| smallhold-3pkx | Keyword filters | Small — table + LIKE filter in timeline |
| smallhold-chxy | Hashtag following | Small — 1 table + home timeline UNION |
| smallhold-zgdm | Prometheus metrics | Medium — middleware + delivery worker instrumentation |
| smallhold-c8oq | Lists (custom timelines) | Medium — 2 tables + timeline variant |
| smallhold-i28n | Full-text search via tantivy | Medium — tantivy crate + index lifecycle |

## Known messiness in beads

**Duplicate flat issues in Phase 9 (smallhold-352)**: The original Phase 9 epic had ~9 flat task children created during the initial epic burst. Then the Phase 9 expansion agent created 4 sub-epics (352.1–352.4) with 16 properly-detailed issues. Both sets exist. The flat originals (smallhold-1ub, smallhold-6ma, smallhold-8bl, smallhold-amf, smallhold-aox, smallhold-ff7, smallhold-imd, smallhold-xrx, smallhold-zm5) overlap in topic with the sub-epic issues. They can be closed as superseded when starting Phase 9 work, or ignored — the detailed sub-epic issues are the authoritative ones.

**Phase 4 and 5 duplicate epics**: smallhold-dq7 and smallhold-e4b were closed/superseded. Their sub-epics were re-linked to smallhold-4xr and smallhold-w59 respectively via `bd dep relate`. The originals (4xr, w59) are the authoritative parents.

## No code exists yet

Zero Rust code, zero Cargo.toml, zero src/ directory. The repo contains only:
- mastodon-rust-minimal-spec.md (the authoritative spec)
- CLAUDE.md
- AGENTS.md
- README.md
- PRFAQ.md
- SESSION_STATE.md (this file)
- .beads/ (issue tracker data)

## Where to start next session

Run `bd ready` — all 257 issues are technically unblocked (no beads dependency edges were set between phases, only `relate` links).

**The right sequence is to follow the phase order in CLAUDE.md**:

1. Start with Phase 0 (smallhold-oji): workspace layout, Cargo.toml, config.toml parsing, SQLite init with PRAGMAs, snowflake ID generator, `smallhold persona create writer` CLI command working end-to-end.

Phase 0 done criteria: `smallhold persona create writer --display-name="Test"` inserts a sane DB row and `smallhold persona list` shows it.

## Critical invariants to internalize before writing any code

1. **IDs are 64-bit snowflakes serialized as JSON strings** — not UUIDs, not integers
2. **SQLite PRAGMAs on every startup**: WAL, synchronous=NORMAL, foreign_keys=ON, busy_timeout=5000, cache_size=-64000
3. **No `.unwrap()` in handler paths** — AppError → `{"error":"..."}` JSON
4. **Never log tokens or full activity bodies at INFO** — activity type+status at INFO, bodies at TRACE only
5. **activitypub-federation crate from LemmyNet** — do not rewrite HTTP signature handling
6. **Mastodon wins** — when spec docs conflict with mastodon.social behavior, match mastodon.social

## Tech stack

- axum + Tower (HTTP server)
- sqlx with sqlite feature (WAL, compile-time query checking)
- activitypub-federation (LemmyNet crate)
- reqwest + rustls-tls (HTTP client — not openssl)
- ammonia (HTML sanitize)
- pulldown-cmark (Markdown → HTML for bios)
- image + fast_image_resize (media processing)
- blurhash (media thumbnails)
- argon2 (password hashing)
- serde + toml (config)
- tracing + tracing-subscriber (logging)
- clap v4 derive (CLI)
- tokio (async runtime)
- tantivy (full-text search — new in this session)
- metrics + metrics-exporter-prometheus (Prometheus — new in this session)

## Cargo quality gates (run before closing any code issue)

```bash
cargo fmt --all
typos src/
cargo clippy --all-features -- -D warnings
cargo test --all-targets
```

Pre-PR additionally:
```bash
cargo hack check --feature-powerset --no-dev-deps
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features
```

## Cost estimate for building this

Using claude-sonnet-4-6:
- Optimistic: ~$150
- Realistic: ~$300
- Pessimistic (lots of federation debugging): ~$500–700

Phase 9 compat hardening is the biggest uncertainty — getting mastodon.social green can require many short debug cycles.
