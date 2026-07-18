# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` — use `-o BatchMode=yes`
- `ssh` — use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` — use `-y` flag

## Defensive Programming

This server faces the open internet. Every inbound HTTP request, every ActivityPub payload, every federated object, and every media upload is adversarial until proven otherwise. Code as if every remote server is actively trying to exploit you.

**Assume hostile input everywhere:**
- All ActivityPub inbox deliveries — malformed JSON, oversized payloads, spoofed signatures, type confusion (e.g. `type: "Create"` wrapping a `Delete`), nested object bombs, unexpected array-vs-object alternation
- All Mastodon Client API requests — forged tokens, out-of-bounds pagination, injection via display names / bios / post content, path traversal in media filenames
- All federated content rendered to clients — stored XSS via post HTML, malicious `href` in links, SVG script injection, overlong strings designed to blow up layout or memory
- All media — polyglot files (valid JPEG that is also valid HTML), EXIF-embedded scripts, decompression bombs, files that claim one MIME type but contain another

**Defensive defaults:**
- Validate and reject at the boundary. Do not pass unsanitized data deeper into the stack hoping something downstream will catch it.
- Enforce size limits on every input: request bodies, JSON fields, string lengths, collection sizes, media dimensions. Define constants, not magic numbers.
- Never trust `Content-Type` headers from remote servers. Sniff and verify.
- HTML-sanitize all federated content (ammonia) before storing. Do not sanitize on render — sanitize on ingest.
- Treat all string fields from remote actors (display name, bio, post content, attachment descriptions) as potential attack vectors. Length-cap and sanitize every one.
- Fail closed. If signature verification is ambiguous, reject. If a field is missing from an ActivityPub object, reject. If a media file doesn't pass validation, reject.
- No `.unwrap()` in any code path reachable from a network request. `AppError` with a JSON error body, always.
- Log enough to detect attacks (source IP, actor URI, rejection reason) but never log secrets, tokens, or full request bodies at INFO level.

## Test Coverage

Target 100% test coverage on all non-trivial code. "It compiles" is not a test. "It doesn't panic" is not a test.

**What to test:**
- Every public function. Every error path. Every boundary condition.
- Every input validation rule — test that valid input is accepted AND that each class of invalid input is rejected with the correct error.
- Every ActivityPub activity type handler — test with well-formed input, malformed input, missing fields, wrong types, oversized fields, and spoofed signatures.
- Every Mastodon Client API endpoint — test auth, success, and each documented error condition.
- Federation round-trips — test that outbound activities serialize correctly and inbound activities deserialize and process correctly.
- SQL queries — test with empty tables, single rows, boundary pagination, and the maximum expected dataset size.

**Test quality rules:**
- Tests must have an independent oracle. Never use the code under test to generate expected values.
- Test hostile inputs explicitly: strings at length limits, strings past length limits, null bytes, unicode edge cases (ZWJ sequences, RTL overrides, homoglyph attacks), nested objects 100 levels deep, arrays with 10,000 elements.
- Integration tests against real ActivityPub payloads captured from mastodon.social, Akkoma, Misskey, and GoToSocial. Commit these as fixtures.
- If a bug is found, add a regression test before fixing it. The test must fail before the fix and pass after.

## Canary Testing Protocol

**Before declaring a phase complete, test against a live instance.**

For federation phases (1–2, 9): use mastodon.social as the canary. If mastodon.social can't follow your persona or see your posts, the phase is not done.

For client phases (3–8): test against Phanpy (web, no install) as the minimum bar. Ivory and Elk are higher priority but require accounts.

Compat matrix lives in `docs/compat.md` and `docs/clients.md`. Update them on every bug fix.

## Cargo Quality Gates

Run these before closing any code-touching issue:

```bash
cargo fmt --all                          # commit result if anything changes
typos src/                               # cargo install typos-cli
cargo clippy --all-features -- -D warnings
cargo test --all-targets
```

For pre-PR:
```bash
cargo hack check --feature-powerset --no-dev-deps   # cargo install cargo-hack
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --no-deps --all-features
```

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full workflow context.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

**Beads is the only task and planning tool.** Do NOT use:
- TodoWrite / markdown TODO lists
- Scratchpad or audit files (`audit-*.md`, `plan-scratch.md`, or any similar throwaway planning file)
- MEMORY.md or any other markdown file as a knowledge store

The only permitted markdown planning artifact is a crate's `PLAN.md`, which is a permanent
design document checked into the repo — not a scratchpad. Use `bd remember` for persistent
knowledge and `bd create` for all task tracking.

## Code Review Gate

**MANDATORY**: After every logical chunk of code is generated or modified, immediately run `/codereview` against it **3 times** before moving on. A "logical chunk" is a function, module, endpoint, or coherent set of changes — not individual lines. All findings from `/codereview` must be filed as beads issues (tagged with `codereview`). Do not proceed to the next chunk until all 3 review passes are complete and findings are addressed or tracked.
