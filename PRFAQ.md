# PRFAQ: smallhold

---

## PRESS RELEASE

**FOR IMMEDIATE RELEASE**

**smallhold Gives Independent Operators a Fediverse Presence Without the Infrastructure Tax**

*Seattle, WA* — A new open-source Rust project called **smallhold** makes it possible to run a fully functional, federated ActivityPub server as a single statically-linked binary with no database server, no job queue, and no search daemon. The server speaks the Mastodon Client API, meaning every major Mastodon-compatible client — Ivory, Phanpy, Elk, Tusky, and Tuba — works against it without modification or configuration.

smallhold is aimed squarely at the operator who wants to own their fediverse presence without operating a production infrastructure stack. Where a full Mastodon deployment requires PostgreSQL, Redis, Sidekiq, and Elasticsearch alongside the Rails application, smallhold requires a reverse proxy for TLS and nothing else. A working instance on a $6/month VPS is a ten-minute exercise.

"The fediverse has a participation problem that isn't about software features," said the project author. "It's about the gap between 'I want my own instance' and 'I am willing to operate a five-service Docker Compose stack forever.' smallhold closes that gap."

The server supports multiple personas under a single domain. An operator can maintain a professional persona, a casual personal persona, and a bot account — each a fully independent ActivityPub actor with its own keypair, followers collection, and inbox — while running a single process on a single machine. Mastodon clients authenticate to individual personas via a standard OAuth2 flow; each client session sees one account.

Outbound federation uses an in-process delivery worker with exponential backoff and per-domain circuit breaking. Inbound federation handles the full range of ActivityPub activity types required for interoperability: follows, posts, replies, boosts, likes, edits, deletions, and account migrations. The project has been tested for compatibility against Mastodon 4.x, Akkoma, Misskey, GoToSocial, Lemmy, and Pixelfed.

smallhold is released under the AGPL-3.0 license. Binaries are available for Linux x86_64 (musl, statically linked). Source builds are supported on any platform with a current Rust toolchain.

---

## FREQUENTLY ASKED QUESTIONS

### Customer / User FAQs

**Q: Who is this for?**

A: Operators who want a personal or small-group fediverse presence with full federation — the ability to follow and be followed by anyone on Mastodon, Misskey, GoToSocial, etc. — but who are not willing or able to run a production Mastodon stack. The target is a single human running a few accounts, possibly with one or two trusted collaborators, at a volume that can be served comfortably by a small VPS.

**Q: Can I use my existing Mastodon client?**

A: Yes. Ivory, Phanpy, Elk, Tusky, and Tuba all work without modification. The server implements the Mastodon Client API at the level those clients require. Some features clients expose — polls, keyword filters, push notifications — return empty results or 404, and clients degrade gracefully on all of them.

**Q: Can I migrate my existing Mastodon account to smallhold?**

A: Inbound migration is supported: smallhold handles the ActivityPub `Move` activity and `alsoKnownAs` field, so accounts on other servers can migrate their followers to a smallhold persona. Outbound migration (moving away from smallhold to another server) is not supported in the current release.

**Q: Will people on mastodon.social be able to follow me and see my posts?**

A: Yes. That is the primary test criterion for the project. Full federation with mastodon.social — follow, post, reply, boost, like, DM, media, edit, delete — is the release gate.

**Q: How many accounts can one instance support?**

A: The design target is a few dozen personas. There is no hard limit. Home timeline computation is a SQL read query; at 30 personas and typical activity volumes it runs in under 10 ms. If you are running hundreds of highly active accounts, smallhold is the wrong tool.

**Q: What happens to DMs?**

A: Direct messages work as posts with `direct` visibility. They appear in the client's DM section. There is no separate conversation endpoint — Mastodon clients surface DMs through the regular status API filtered by visibility, which is what smallhold provides.

**Q: Are my posts searchable?**

A: Local account and hashtag search are supported. Full-text post search is deferred to a future release. Mastodon clients degrade gracefully when full-text search is unavailable.

**Q: Can I run multiple smallhold instances on different domains for different personas?**

A: Yes, and that is the recommended approach when you need real separation between identities — for example, a public professional account and a pseudonymous personal account. Same binary, different `config.toml`, different VPS. Same-domain personas share an IP address and TLS fingerprint that can correlate them; separate instances do not.

---

### Technical FAQs

**Q: Why SQLite? Won't it bottleneck?**

A: At the scale smallhold targets — a few dozen personas, thousands of activities per day — SQLite in WAL mode is not the bottleneck. Timeline reads are sub-10ms. The delivery worker runs in-process as a tokio task and is bounded by outbound network latency, not database throughput. If your fediverse server is bottlenecked on SQLite, you are operating at a scale that needs a different tool.

**Q: Why not embed TLS?**

A: Reverse proxies (Caddy, nginx) handle TLS correctly, renew certificates automatically, and serve static files with proper cache headers. Embedding TLS adds certificate renewal logic, ACME client complexity, and a new attack surface for a problem that is already solved. The binary does one thing; the reverse proxy does another.

**Q: What about HTTP signatures? ActivityPub signature handling is notoriously tricky.**

A: smallhold uses the `activitypub-federation` crate from the Lemmy project, which is production-tested against the fediverse at significant scale. The project does not implement its own HTTP signature handling. Mastodon and most of the fediverse use draft-cavage-http-signatures-11; the crate handles this correctly, including authorized fetch for outbound GETs.

**Q: How does outbound delivery work? What if a remote server is down?**

A: Activities are written to a `delivery_queue` table in SQLite and processed by an in-process tokio task. Retry schedule: 1 minute, 5 minutes, 30 minutes, 2 hours, 8 hours, 24 hours. After six attempts the delivery is marked permanently failed. A 410 Gone response marks delivery dead immediately. There is a per-domain circuit breaker: ten consecutive failures against a domain pause deliveries to that domain for one hour. The `smallhold queue inspect` and `smallhold queue retry-dead` commands provide operator visibility and manual override.

**Q: What does "multiple personas under one domain" mean for ActivityPub?**

A: Each persona has a distinct actor URI (`https://yourdomain/users/writer`, `https://yourdomain/users/editor`), its own RSA keypair, its own inbox, outbox, and followers collection. From the perspective of remote servers, they are independent accounts that happen to share a domain. The shared inbox at `https://yourdomain/inbox` accepts deliveries for all local actors and routes them internally.

**Q: Is this actually compatible with Mastodon? The API is large and poorly documented.**

A: The compatibility strategy is: when in doubt, curl mastodon.social's response for the same endpoint and match the shape exactly. The project maintains a compat matrix in `docs/compat.md` and `docs/clients.md`. The release gate is a complete green row for mastodon.social and at least three other major implementations. The Mastodon API is treated as the de facto spec, not the written documentation.

**Q: Why Rust?**

A: Compiled single binary with no runtime, low steady-state memory, and strong correctness guarantees around the data model. The goal of a sub-150 MB footprint and sub-2-second cold start is straightforwardly achievable in Rust and would require significant effort in most other ecosystems. The ActivityPub delivery and HTTP signature requirements also benefit from Rust's type system for correctness.

**Q: What about upgrades? SQLite schema migrations?**

A: Migrations are embedded in the binary using `sqlx-migrate` and run automatically on startup. `smallhold init` writes the initial schema. Subsequent releases apply incremental migrations. The migration history is append-only.

**Q: How do I back up my data?**

A: The entire instance state is the SQLite file plus the `media/` directory. Back up both. SQLite WAL mode means a filesystem snapshot of the database file is consistent as long as you also copy the WAL file. For live backup without downtime, `sqlite3 db.sqlite ".backup backup.sqlite"` produces a consistent copy.

---

### Business / Strategic FAQs

**Q: What is the project's scope going forward? What is v2?**

A: The v1 scope is fixed at Phase 4 (working posting and federation) through Phase 8 (profile editing, search, domain blocks, account migration in). The explicit v2 candidates from the spec are: full-text search via `tantivy`, Webpush notifications, and outbound account migration. Everything else requires a compelling case that existing clients actually break without it.

**Q: How does this compare to GoToSocial, honk, snac, or microblog.pub?**

A: All of these are minimalist ActivityPub servers. GoToSocial is Go, has a larger team, more features, and a longer track record. honk and snac are C and Go respectively — extremely minimal, deliberately rough around the edges. microblog.pub is Python with a built-in web UI. smallhold's differentiator is Mastodon Client API fidelity at the level required for polished third-party clients, combined with a zero-sidecar deployment model and native multi-persona support under one domain. The closest analog is GoToSocial, which also targets SQLite and single-binary deployment; smallhold is smaller in scope and has no plans for the GoToSocial-style admin web UI.

**Q: Could this run as a hosted service?**

A: Technically yes; operationally, smallhold's single-operator design would make multi-tenant hosting awkward. There is no signup flow, no per-user quota management, and no horizontal scaling path. A hosting operator would need to provision one smallhold instance per customer domain, which is a reasonable model for a white-glove fediverse hosting service but not for a mass-market platform.

---

> **What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
