# Design: Key Storage Hardening

**Status:** Proposal
**Issue:** smallhold-plvk

## Problem

Actor private keys (RSA-2048 PEM) are stored as plaintext in the SQLite database (`accounts.private_key_pem`, `push_vapid.private_key_pem`). Database file theft = full actor impersonation.

## Threat Model

smallhold is a single-operator server with ~1-50 personas on one host. Threats:

| Threat | Likelihood | Impact |
|--------|-----------|--------|
| DB file stolen via backup leak | Medium | Full key compromise |
| DB file stolen via path traversal bug | Low | Full key compromise |
| Memory dump of running process | Low | Key material in heap |
| Physical server compromise (root) | Low | Everything compromised regardless |

Non-threats (out of scope for a single-operator server):
- Multi-tenant isolation (that's gaja's problem)
- Insider threat from other users (there are no other users)
- Nation-state adversary (use Signal, not ActivityPub)

## Recommendation: Encrypt at Rest with HKDF-derived Key

Wrap `private_key_pem` values with AES-256-GCM, keyed by an HKDF derivation of the existing `server.secret_key`.

### Why this approach

- **No external dependencies.** No cloud services, no hardware, no network calls.
- **Zero latency.** AES-256-GCM decryption is ~1μs. RSA signing is ~1ms. Overhead is noise.
- **Already have the deps.** `aes-gcm`, `hkdf`, `sha2` are in Cargo.toml.
- **DB theft is neutralized.** Without `secret_key` (in config file, not DB), keys are unrecoverable.
- **Transparent migration.** Detect plaintext PEM (`-----BEGIN`) vs encrypted blob; migrate on first read.

### What it doesn't protect against

- Process memory dump (keys are decrypted for signing)
- Root compromise (attacker reads config file + DB)
- `secret_key` stored adjacent to DB on same filesystem

### Design

```
                 ┌─────────────────┐
                 │  config.toml    │
                 │  secret_key     │
                 └────────┬────────┘
                          │ HKDF-SHA256
                          │ info: "smallhold-key-wrap-v1"
                          │ salt: per-row random (stored alongside)
                          ▼
                 ┌─────────────────┐
                 │  wrapping_key   │
                 │  (256 bits)     │
                 └────────┬────────┘
                          │ AES-256-GCM
                          │ nonce: 96-bit random (stored alongside)
                          ▼
┌──────────────────────────────────────────┐
│  DB column: private_key_enc              │
│  Format: version(1) || salt(32) ||       │
│          nonce(12) || ciphertext || tag   │
└──────────────────────────────────────────┘
```

### Schema change

```sql
-- Add encrypted column alongside existing plaintext column
ALTER TABLE accounts ADD COLUMN private_key_enc BLOB;
ALTER TABLE push_vapid ADD COLUMN private_key_enc BLOB;

-- After migration completes, drop plaintext:
-- ALTER TABLE accounts DROP COLUMN private_key_pem;
```

### Migration strategy

1. Add `private_key_enc` column (nullable)
2. On server startup, scan for rows where `private_key_enc IS NULL` and `private_key_pem` starts with `-----BEGIN`
3. Encrypt each key, write to `private_key_enc`, NULL out `private_key_pem`
4. After one release cycle, remove `private_key_pem` column

### API change to signing

```rust
// Before:
fn rsa_sha256_sign(private_key_pem: &str, message: &[u8]) -> Result<String>

// After:
fn rsa_sha256_sign(encrypted_key: &[u8], config: &Config, message: &[u8]) -> Result<String>
// Internally: derive wrapping key, decrypt PEM, parse, sign
```

Cache the parsed `RsaPrivateKey` in memory (already needed for performance per review finding smallhold-9ouq.1). The decryption adds negligible overhead to the PEM-parsing cost.

### Key rotation

If `secret_key` changes, all wrapped keys become unrecoverable. Document:
- `secret_key` is load-bearing — back it up separately from the DB
- Provide a CLI command: `smallhold admin rewrap-keys --old-config <path>` for rotation

## Alternatives Considered

### Cloud KMS wrapping

Encrypt DB keys with AWS KMS / GCP Cloud KMS master key. Decrypt on demand.

- **Pro:** Key never on disk in cleartext
- **Con:** Network dependency for every signing operation, cost ($1/10k API calls), requires cloud account, overkill for single-server

**Verdict:** Inappropriate for smallhold's deployment model (single binary, no cloud deps).

### HSM-backed signing (keys never leave hardware)

Sign operations happen inside CloudHSM/PKCS#11 device.

- **Pro:** Keys physically cannot be extracted
- **Con:** $1.50/hr CloudHSM cost, 10-50ms latency per sign, RSA-2048 ~500 ops/sec limit, requires PKCS#11 integration

**Verdict:** Wrong cost/complexity tradeoff for a personal fediverse server. Appropriate for instances with 10k+ users (gaja territory).

### OS keyring (libsecret / macOS Keychain)

Store wrapping key in platform secret store instead of config file.

- **Pro:** Separates key from filesystem
- **Con:** Platform-specific, doesn't work in containers (smallhold's primary deployment), adds PAM/unlock dependency

**Verdict:** Incompatible with Docker deployment. Could be a future option for bare-metal installs.

### Threshold signatures (Shamir/MPC)

Split key across N nodes, require K-of-N to sign.

- **Pro:** No single point of compromise
- **Con:** Requires multiple servers, coordination protocol, latency, massive complexity increase for no real user benefit on a single-operator server

**Verdict:** Academic interest only for this use case.

## Decision

Implement option 1: **HKDF + AES-256-GCM at-rest encryption** of private keys in the database, derived from the existing `server.secret_key`. This provides meaningful protection against the most realistic threat (DB file leak) with zero external dependencies, zero latency impact, and minimal code change.

## Implementation estimate

~100 lines of Rust: encrypt/decrypt helpers, migration logic, CLI rewrap command. Touches: `db.rs`, `delivery.rs`, `federation.rs`, `cli.rs`.
