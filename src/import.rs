use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::config::Config;

pub struct ImportStats {
    pub posts_imported: usize,
    pub posts_skipped: usize,
    pub media_imported: usize,
    pub avatar_imported: bool,
    pub header_imported: bool,
    pub follow_commands: Vec<String>,
    pub domains_blocked: usize,
    pub muted_accounts: Vec<String>,
    pub profile_updated: bool,
}

pub async fn import_mastodon_archive(
    pool: &fieldwork_db::db::Pool,
    config: &Config,
    username: &str,
    archive_path: &Path,
) -> Result<ImportStats> {
    let account_id = crate::db_extras::get_persona_id_for_import(pool, username)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Persona @{username} not found"))?;
    let domain = &config.server.domain;

    let tmp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    extract_archive(archive_path, tmp_dir.path())?;

    // Find the root — some archives nest everything under a subdirectory
    let extract_root = find_extract_root(tmp_dir.path());

    let media_dir = Path::new(&config.storage.media_dir);
    std::fs::create_dir_all(media_dir)
        .with_context(|| format!("Failed to create media dir: {}", media_dir.display()))?;

    let mut stats = ImportStats {
        posts_imported: 0,
        posts_skipped: 0,
        media_imported: 0,
        avatar_imported: false,
        header_imported: false,
        follow_commands: Vec::new(),
        domains_blocked: 0,
        muted_accounts: Vec::new(),
        profile_updated: false,
    };

    let mut tx = crate::db::begin_tx(pool).await?;

    // 1. Parse and apply actor.json (profile + avatar + header)
    let actor_path = extract_root.join("actor.json");
    if actor_path.exists() {
        apply_actor_profile(
            &mut tx,
            account_id,
            &actor_path,
            &extract_root,
            media_dir,
            &mut stats,
        )
        .await?;
    }

    // 2. Parse and import outbox.json
    let outbox_path = extract_root.join("outbox.json");
    if outbox_path.exists() {
        import_outbox(
            &mut tx,
            account_id,
            username,
            domain,
            &extract_root,
            &outbox_path,
            media_dir,
            &mut stats,
        )
        .await?;
    }

    // 3. Parse following_accounts.csv
    let following_path = extract_root.join("following_accounts.csv");
    if following_path.exists() {
        stats.follow_commands = parse_following_csv(&following_path, username)?;
    }

    // 4. Parse and import blocked_accounts.csv as domain blocks
    let blocked_path = extract_root.join("blocked_accounts.csv");
    if blocked_path.exists() {
        stats.domains_blocked = import_blocked_accounts(&mut tx, &blocked_path).await?;
    }

    // 5. Parse muted_accounts.csv (print for manual action)
    let muted_path = extract_root.join("muted_accounts.csv");
    if muted_path.exists() {
        stats.muted_accounts = parse_account_csv(&muted_path)?;
    }

    tx.commit().await?;

    Ok(stats)
}

/// Maximum total extracted bytes before aborting (zip bomb protection).
const MAX_EXTRACTED_BYTES: u64 = 1_073_741_824; // 1 GB

fn extract_archive(archive_path: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;
    let decompressor = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decompressor);
    let canonical_dest = dest
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize dest: {}", dest.display()))?;

    let mut total_bytes: u64 = 0;

    for entry_result in archive.entries().context("Failed to read tar entries")? {
        let mut entry = entry_result.context("Failed to read tar entry")?;
        let entry_path = entry
            .path()
            .context("Failed to read entry path")?
            .into_owned();

        // Zip bomb protection: track total extracted size.
        total_bytes = total_bytes.saturating_add(entry.size());
        if total_bytes > MAX_EXTRACTED_BYTES {
            anyhow::bail!(
                "archive exceeds {MAX_EXTRACTED_BYTES} byte extraction limit (zip bomb protection)"
            );
        }

        // Reject absolute paths and entries with path traversal components.
        if entry_path.is_absolute()
            || entry_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            anyhow::bail!(
                "tar entry has unsafe path (traversal or absolute): {}",
                entry_path.display()
            );
        }

        let target = canonical_dest.join(&entry_path);
        // Belt-and-suspenders: verify resolved path stays within dest.
        if !target.starts_with(&canonical_dest) {
            anyhow::bail!(
                "tar entry resolves outside target directory: {}",
                entry_path.display()
            );
        }

        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create dir: {}", parent.display()))?;
        }

        entry
            .unpack(&target)
            .with_context(|| format!("Failed to extract: {}", entry_path.display()))?;
    }
    Ok(())
}

/// Some Mastodon archives place files directly in the tar root, others nest
/// them under a single directory. Look for `outbox.json` to decide.
fn find_extract_root(base: &Path) -> std::path::PathBuf {
    if base.join("outbox.json").exists() {
        return base.to_path_buf();
    }
    // Check one level of subdirectories
    if let Ok(entries) = std::fs::read_dir(base) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() && p.join("outbox.json").exists() {
                return p;
            }
        }
    }
    base.to_path_buf()
}

async fn apply_actor_profile(
    tx: &mut crate::sqlx::Transaction<'static, crate::sqlx::Sqlite>,
    account_id: i64,
    path: &Path,
    extract_root: &Path,
    media_dir: &Path,
    stats: &mut ImportStats,
) -> Result<bool> {
    let data = std::fs::read_to_string(path).context("Failed to read actor.json")?;
    let actor: serde_json::Value = serde_json::from_str(&data).context("Invalid actor.json")?;

    let display_name = actor
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let bio = actor
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let bio_html = ammonia::clean(&bio);

    // Extract profile fields from attachment array
    let fields_json = if let Some(attachments) = actor.get("attachment").and_then(|v| v.as_array())
    {
        let fields: Vec<serde_json::Value> = attachments
            .iter()
            .filter(|a| a.get("type").and_then(|t| t.as_str()) == Some("PropertyValue"))
            .map(|a| {
                serde_json::json!({
                    "name": a.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    "value": a.get("value").and_then(|v| v.as_str()).unwrap_or("")
                })
            })
            .collect();
        serde_json::to_string(&fields).unwrap_or_else(|_| "[]".into())
    } else {
        "[]".into()
    };

    crate::db_extras::import_update_persona_profile(
        tx,
        account_id,
        &display_name,
        &bio,
        &bio_html,
        &fields_json,
    )
    .await?;
    stats.profile_updated = true;

    let now_ms = chrono::Utc::now().timestamp_millis();

    // Import avatar (icon)
    if let Some(icon_url) = actor
        .get("icon")
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
    {
        if let Some(media_id) =
            copy_profile_image(tx, account_id, icon_url, extract_root, media_dir, now_ms).await?
        {
            crate::db_extras::import_set_persona_avatar(tx, account_id, media_id).await?;
            stats.avatar_imported = true;
        }
    }

    // Import header (image)
    if let Some(image_url) = actor
        .get("image")
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
    {
        if let Some(media_id) =
            copy_profile_image(tx, account_id, image_url, extract_root, media_dir, now_ms).await?
        {
            crate::db_extras::import_set_persona_header(tx, account_id, media_id).await?;
            stats.header_imported = true;
        }
    }

    Ok(true)
}

/// Copy a profile image (avatar or header) from the archive to the media dir,
/// insert a media row, and return the media ID.
async fn copy_profile_image(
    tx: &mut crate::sqlx::Transaction<'static, crate::sqlx::Sqlite>,
    account_id: i64,
    url: &str,
    extract_root: &Path,
    media_dir: &Path,
    now_ms: i64,
) -> Result<Option<i64>> {
    let src = match resolve_media_path(extract_root, url) {
        Some(p) if p.exists() => p,
        _ => return Ok(None),
    };

    let media_id = crate::id::generate_id();
    let ext = src.extension().and_then(|e| e.to_str()).unwrap_or("bin");
    let id_hex = format!("{media_id:x}");
    let prefix = &id_hex[..2.min(id_hex.len())];
    let prefix_dir = media_dir.join(prefix);
    std::fs::create_dir_all(&prefix_dir).with_context(|| {
        format!(
            "Failed to create media prefix dir: {}",
            prefix_dir.display()
        )
    })?;

    let dest_filename = format!("{media_id}.{ext}");
    let dest_path = prefix_dir.join(&dest_filename);
    std::fs::copy(&src, &dest_path)
        .with_context(|| format!("Failed to copy profile image: {}", src.display()))?;

    let file_size = std::fs::metadata(&dest_path)
        .map(|m| m.len() as i64)
        .unwrap_or(0);

    let mime_type = mime_from_ext(ext);
    let rel_path = format!("media/{prefix}/{media_id}.{ext}");

    crate::db_extras::import_insert_media_no_post(
        tx,
        media_id,
        crate::db::DEFAULT_USER_ID,
        account_id,
        &rel_path,
        mime_type,
        file_size,
        "",
        now_ms,
    )
    .await?;

    Ok(Some(media_id))
}

fn mime_from_ext(ext: &str) -> &'static str {
    match ext.to_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
}

#[allow(clippy::too_many_arguments)]
async fn import_outbox(
    tx: &mut crate::sqlx::Transaction<'static, crate::sqlx::Sqlite>,
    account_id: i64,
    username: &str,
    domain: &str,
    extract_root: &Path,
    outbox_path: &Path,
    media_dir: &Path,
    stats: &mut ImportStats,
) -> Result<()> {
    let data = std::fs::read_to_string(outbox_path).context("Failed to read outbox.json")?;
    let outbox: serde_json::Value = serde_json::from_str(&data).context("Invalid outbox.json")?;

    let items = outbox
        .get("orderedItems")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("outbox.json missing orderedItems array"))?;

    // Collect Create{Note} activities and sort by published date (oldest first)
    let mut notes: Vec<&serde_json::Value> = Vec::new();
    for item in items {
        let activity_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if activity_type != "Create" {
            continue;
        }
        let object = match item.get("object") {
            Some(o) => o,
            None => continue,
        };
        let object_type = object.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if object_type != "Note" {
            continue;
        }
        notes.push(item);
    }

    // Sort oldest first by published timestamp
    notes.sort_by_key(|item| {
        item.get("published")
            .or_else(|| item.get("object").and_then(|o| o.get("published")))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp_millis())
            .unwrap_or(0)
    });

    // Track last timestamp for sequence deduplication
    let mut last_ms: i64 = 0;
    let mut last_seq: u32 = 0;

    for item in &notes {
        let object = item.get("object").unwrap(); // safe: filtered above

        let published_str = object
            .get("published")
            .or_else(|| item.get("published"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let published_ms = match chrono::DateTime::parse_from_rfc3339(published_str) {
            Ok(dt) => dt.timestamp_millis(),
            Err(_) => {
                stats.posts_skipped += 1;
                continue;
            }
        };

        // Generate snowflake ID preserving chronological order
        let (id, seq) = id_from_timestamp(published_ms, last_ms, last_seq);
        if published_ms == last_ms {
            last_seq = seq;
        } else {
            last_ms = published_ms;
            last_seq = seq;
        }

        let content_html = object
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let content_clean = ammonia::clean(&content_html);

        let spoiler_text = object
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let sensitive = object
            .get("sensitive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let in_reply_to_uri = object
            .get("inReplyTo")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let visibility = determine_visibility(item, object);

        let ap_id = format!("https://{domain}/users/{username}/statuses/{id}");

        let language = object
            .get("contentMap")
            .and_then(|m| m.as_object())
            .and_then(|m| m.keys().next())
            .map(|k| k.to_string())
            .or_else(|| {
                let plain = crate::posting::strip_html_tags(&content_clean);
                let detected = crate::posting::detect_language(&plain);
                if detected != "en" {
                    Some(detected.to_string())
                } else {
                    None
                }
            });

        // FEP-f228: imported posts get their own context URL.
        // ponytail: imports don't resolve reply chains for context inheritance; each post
        // gets its own context. A future `reindex-contexts` command could fix this.
        let context_url = format!("{ap_id}/context");

        // Insert the post
        let result = crate::db_extras::import_insert_post(
            tx,
            id,
            crate::db::DEFAULT_USER_ID,
            account_id,
            &ap_id,
            in_reply_to_uri.as_deref(),
            &context_url,
            &content_clean,
            &content_html,
            &spoiler_text,
            &visibility,
            sensitive,
            language.as_deref(),
            published_ms,
        )
        .await;

        if let Err(e) = result {
            tracing::warn!("Skipping post {published_str}: {e}");
            stats.posts_skipped += 1;
            continue;
        }

        // Insert hashtags
        if let Some(tags) = object.get("tag").and_then(|v| v.as_array()) {
            for tag in tags {
                let tag_type = tag.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if tag_type == "Hashtag" {
                    let tag_name: String = tag
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim_start_matches('#')
                        .chars()
                        .filter(|c| c.is_alphanumeric())
                        .collect::<String>()
                        .to_lowercase();
                    if !tag_name.is_empty() {
                        let _ = crate::db_extras::import_insert_tag(tx, id, &tag_name).await;
                    }
                }

                // Best-effort mention insertion
                if tag_type == "Mention" {
                    if let Some(href) = tag.get("href").and_then(|v| v.as_str()) {
                        let remote = crate::db_extras::import_find_remote_by_uri(tx, href)
                            .await
                            .unwrap_or(None);

                        if let Some(remote_id) = remote {
                            let _ =
                                crate::db_extras::import_insert_mention(tx, id, remote_id).await;
                        }
                    }
                }
            }
        }

        // Copy media attachments
        if let Some(attachments) = object.get("attachment").and_then(|v| v.as_array()) {
            for attachment in attachments {
                let media_type = attachment
                    .get("mediaType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("application/octet-stream");

                let description = attachment
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // The url field in the archive points to the original server URL.
                // The actual file is in media_attachments/files/... mirroring the URL path.
                let url = attachment.get("url").and_then(|v| v.as_str()).unwrap_or("");
                let source_path = resolve_media_path(extract_root, url);

                if let Some(src) = source_path {
                    if src.exists() {
                        let media_id = crate::id::generate_id();
                        let ext = src.extension().and_then(|e| e.to_str()).unwrap_or("bin");
                        let id_hex = format!("{media_id:x}");
                        let prefix = &id_hex[..2.min(id_hex.len())];
                        let prefix_dir = media_dir.join(prefix);
                        if let Err(e) = std::fs::create_dir_all(&prefix_dir) {
                            tracing::warn!(
                                "Failed to create media prefix dir {}: {e}",
                                prefix_dir.display()
                            );
                            continue;
                        }
                        let dest_filename = format!("{media_id}.{ext}");
                        let dest_path = prefix_dir.join(&dest_filename);

                        if let Err(e) = std::fs::copy(&src, &dest_path) {
                            tracing::warn!("Failed to copy media {}: {e}", src.display());
                            continue;
                        }

                        let file_size = std::fs::metadata(&dest_path)
                            .map(|m| m.len() as i64)
                            .unwrap_or(0);

                        // Write sidecar .meta file for recovery/debugging
                        let sidecar_path = dest_path.with_extension(format!(
                            "{}.meta",
                            dest_path
                                .extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or("bin")
                        ));
                        let sidecar_json = serde_json::json!({
                            "id": media_id,
                            "mime_type": media_type,
                            "file_size": file_size,
                            "description": description,
                            "created_at": published_ms,
                        });
                        if let Err(e) = std::fs::write(
                            &sidecar_path,
                            serde_json::to_string_pretty(&sidecar_json).unwrap_or_default(),
                        ) {
                            tracing::warn!(
                                "Failed to write media sidecar {}: {e}",
                                sidecar_path.display()
                            );
                        }

                        let rel_path = format!("media/{prefix}/{media_id}.{ext}");
                        let _ = crate::db_extras::import_insert_media(
                            tx,
                            media_id,
                            crate::db::DEFAULT_USER_ID,
                            account_id,
                            id,
                            &rel_path,
                            media_type,
                            file_size,
                            description,
                            published_ms,
                        )
                        .await;

                        stats.media_imported += 1;
                    }
                }
            }
        }

        stats.posts_imported += 1;
    }

    Ok(())
}

/// Parse following_accounts.csv and return `smallhold follow` commands.
/// Format: `Account address,Show boosts,Notify on new posts,Languages`
/// Automated follow resolution requires federation handshake (server must be running).
fn parse_following_csv(path: &Path, username: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let mut commands = Vec::new();
    for line in content.lines().skip(1) {
        let acct = line.split(',').next().unwrap_or("").trim();
        if !acct.is_empty() && acct.contains('@') {
            commands.push(format!("smallhold follow {username} {acct}"));
        }
    }
    Ok(commands)
}

/// Parse a CSV of account addresses (first column is `Account address`).
/// Returns the list of `user@domain` values.
fn parse_account_csv(path: &Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let mut accounts = Vec::new();
    for line in content.lines().skip(1) {
        let acct = line.split(',').next().unwrap_or("").trim();
        if !acct.is_empty() && acct.contains('@') {
            accounts.push(acct.to_string());
        }
    }
    Ok(accounts)
}

/// Import blocked accounts as domain-level blocks.
/// Per-account blocking requires federation (remote_account_id lookup); domain-level
/// is a reasonable default for archive import.
async fn import_blocked_accounts(
    tx: &mut crate::sqlx::Transaction<'static, crate::sqlx::Sqlite>,
    path: &Path,
) -> Result<usize> {
    let accounts = parse_account_csv(path)?;
    let now = chrono::Utc::now().timestamp_millis();
    let mut blocked_domains = std::collections::HashSet::new();

    for acct in &accounts {
        if let Some(domain) = acct.split('@').nth(1) {
            if blocked_domains.insert(domain.to_string()) {
                crate::db_extras::import_add_domain_block(
                    tx,
                    domain,
                    "suspend",
                    false,
                    "imported from Mastodon archive",
                    now,
                )
                .await?;
            }
        }
    }

    Ok(blocked_domains.len())
}

fn id_from_timestamp(published_ms: i64, last_ms: i64, last_seq: u32) -> (i64, u32) {
    let seq = if published_ms == last_ms {
        last_seq.saturating_add(1)
    } else {
        0
    };
    let id = ((published_ms as u64) << 16 | (seq as u64 & 0xFFFF)) as i64;
    (id, seq)
}

fn is_public(uri: &str) -> bool {
    uri == "https://www.w3.org/ns/activitystreams#Public" || uri == "as:Public" || uri == "Public"
}

fn determine_visibility(activity: &serde_json::Value, object: &serde_json::Value) -> String {
    let to = collect_addressing(activity, object, "to");
    let cc = collect_addressing(activity, object, "cc");

    if to.iter().any(|u| is_public(u)) {
        "public".into()
    } else if cc.iter().any(|u| is_public(u)) {
        "unlisted".into()
    } else if to.iter().any(|u| u.ends_with("/followers")) {
        "private".into()
    } else {
        "direct".into()
    }
}

fn collect_addressing(
    activity: &serde_json::Value,
    object: &serde_json::Value,
    field: &str,
) -> Vec<String> {
    let mut result = Vec::new();
    for source in [activity, object] {
        if let Some(val) = source.get(field) {
            match val {
                serde_json::Value::String(s) => result.push(s.clone()),
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            result.push(s.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
    result
}

/// Try to find the media file in the extracted archive.
/// Mastodon archives store media under `media_attachments/files/...`.
/// The URL field contains the full server URL; we extract the path portion
/// and look for it relative to the archive root.
fn resolve_media_path(extract_root: &Path, url: &str) -> Option<std::path::PathBuf> {
    // Try parsing as URL and using the path component
    if let Ok(parsed) = url::Url::parse(url) {
        let url_path = parsed.path().trim_start_matches('/');
        // Mastodon URLs look like: /system/media_attachments/files/...
        // The archive stores them as: media_attachments/files/...
        let candidate = if let Some(rest) = url_path.strip_prefix("system/") {
            extract_root.join(rest)
        } else {
            extract_root.join(url_path)
        };
        if candidate.exists() {
            return Some(candidate);
        }

        // Also try the full URL path as-is
        let direct = extract_root.join(url_path);
        if direct.exists() {
            return Some(direct);
        }
    }

    // Fallback: try just the filename
    let filename = url.rsplit('/').next()?;
    find_file_recursive(&extract_root.join("media_attachments"), filename)
}

fn find_file_recursive(dir: &Path, filename: &str) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file_recursive(&path, filename) {
                return Some(found);
            }
        } else if path.file_name().and_then(|n| n.to_str()) == Some(filename) {
            return Some(path);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// LibraryThing TSV import
// ---------------------------------------------------------------------------

pub struct LibraryThingStats {
    pub books_imported: usize,
    pub books_skipped: usize,
    pub shelved: usize,
    pub rated: usize,
    pub reviews_imported: usize,
}

/// Import books from a LibraryThing TSV export file.
///
/// LibraryThing exports tab-separated files with columns including:
/// `Book Id`, `Title`, `Author (First, Last)`, `ISBN`, `ISBN13`,
/// `Rating`, `Date Read`, `Date Added`, `Collections`, `Review`,
/// `Number of Pages`, `Publication`, `Language 1`, etc.
///
/// Deduplicates by ISBN — if a book with the same ISBN already exists
/// in the database, it is skipped but shelf/rating/review are still applied.
pub async fn import_librarything(
    pool: &fieldwork_db::db::Pool,
    config: &Config,
    tsv_path: &Path,
) -> Result<LibraryThingStats> {
    let _ = config; // reserved for future use (e.g. cover downloads)

    let mut stats = LibraryThingStats {
        books_imported: 0,
        books_skipped: 0,
        shelved: 0,
        rated: 0,
        reviews_imported: 0,
    };

    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(b'\t')
        .flexible(true)
        .from_path(tsv_path)
        .with_context(|| format!("Failed to open {}", tsv_path.display()))?;

    let headers = rdr.headers().context("Failed to read TSV headers")?.clone();
    let col = |name: &str| -> Option<usize> {
        headers
            .iter()
            .position(|h| h.trim_start_matches('\u{feff}') == name)
    };

    let i_title = col("Title")
        .or_else(|| col("'TITLE'"))
        .context("Missing 'Title' column")?;
    let i_author = col("Author (First, Last)")
        .or_else(|| col("'AUTHOR (First, Last)'"))
        .or_else(|| col("Primary Author"));
    let i_author_lf = col("Author (Last, First)").or_else(|| col("'AUTHOR (Last, First)'"));
    let i_isbn = col("ISBN").or_else(|| col("'ISBN'"));
    let i_isbn13 = col("ISBNs")
        .or_else(|| col("'ISBNs'"))
        .or_else(|| col("ISBN13"));
    let i_rating = col("Rating").or_else(|| col("'RATING'"));
    let i_collections = col("Collections").or_else(|| col("'COLLECTIONS'"));
    let i_review = col("Review").or_else(|| col("'REVIEW'"));
    let i_pages = col("Number of Pages")
        .or_else(|| col("'NUMBER OF PAGES'"))
        .or_else(|| col("Pages"));
    let i_date = col("Date")
        .or_else(|| col("'DATE'"))
        .or_else(|| col("Publication"));
    let i_language = col("Language 1")
        .or_else(|| col("'LANGUAGE 1'"))
        .or_else(|| col("Primary Language"));

    if i_author.is_none() && i_author_lf.is_none() {
        bail!("No author column found (expected 'Author (First, Last)' or 'Author (Last, First)')");
    }

    let user_id = crate::db::DEFAULT_USER_ID;
    let domain = &config.server.domain;

    for result in rdr.records() {
        let record = match result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  warning: skipping malformed row: {e}");
                continue;
            }
        };

        let get = |idx: Option<usize>| -> Option<&str> {
            idx.and_then(|i| record.get(i))
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
        };

        let title = match get(Some(i_title)) {
            Some(t) => t.to_string(),
            None => continue,
        };

        // Author: prefer "First, Last" format, fall back to "Last, First" flipped
        let author = if let Some(a) = get(i_author) {
            a.to_string()
        } else if let Some(a) = get(i_author_lf) {
            // "Stephenson, Neal" -> "Neal Stephenson"
            match a.split_once(',') {
                Some((last, first)) => format!("{} {}", first.trim(), last.trim()),
                None => a.to_string(),
            }
        } else {
            String::new()
        };

        // ISBN: LT wraps in brackets like [0441478123]
        let isbn = get(i_isbn)
            .map(|s| {
                s.trim_matches(|c: char| c == '[' || c == ']' || c.is_whitespace())
                    .to_string()
            })
            .filter(|s| !s.is_empty());

        // ISBN13: LT "ISBNs" field may contain multiple, take the first 13-digit one
        let isbn13 = get(i_isbn13).and_then(|s| {
            s.split(|c: char| c == ',' || c == ';' || c == '[' || c == ']' || c.is_whitespace())
                .map(|t| t.trim())
                .find(|t| t.len() == 13 && t.chars().all(|c| c.is_ascii_digit()))
                .map(|t| t.to_string())
        });

        // Dedup: check if a book with this ISBN already exists
        let existing_book_id = if let Some(ref isbn_val) = isbn {
            fieldwork_db::books_db::get_book_by_isbn(pool, isbn_val)
                .await
                .ok()
                .flatten()
                .map(|b| b.id)
        } else if let Some(ref isbn13_val) = isbn13 {
            fieldwork_db::books_db::get_book_by_isbn(pool, isbn13_val)
                .await
                .ok()
                .flatten()
                .map(|b| b.id)
        } else {
            None
        };

        let now = fieldwork::util::now_secs();

        let book_id = if let Some(id) = existing_book_id {
            stats.books_skipped += 1;
            id
        } else {
            let id = fieldwork::id::generate_id();
            let pages = get(i_pages).and_then(|s| s.parse::<i32>().ok());
            let published_year = get(i_date).and_then(|s| {
                // LT dates can be "2004", "2004-06", "June 2004", etc.
                s.chars()
                    .filter(|c| c.is_ascii_digit())
                    .take(4)
                    .collect::<String>()
                    .parse::<i32>()
                    .ok()
                    .filter(|&y| (1000..=2100).contains(&y))
            });
            let language = get(i_language).map(|s| s.to_string());

            let book = fieldwork_db::books_db::BookRow {
                id,
                title,
                author,
                isbn,
                isbn13,
                openlibrary_id: None,
                cover_url: None,
                description: String::new(),
                pages,
                published_year,
                language,
                created_at: now,
            };
            fieldwork_db::books_db::create_book(pool, &book)
                .await
                .with_context(|| format!("Failed to insert book: {}", &book.title))?;
            stats.books_imported += 1;
            id
        };

        // Shelf: map LT "Collections" to reading status
        if let Some(collections) = get(i_collections) {
            let status = lt_collections_to_status(collections);
            if let Some(status) = status {
                fieldwork_db::books_db::set_reading_status(pool, user_id, book_id, status, now)
                    .await
                    .ok();
                stats.shelved += 1;
            }
        }

        // Rating: LT uses 0-10 half-star scale, we use 1-5
        if let Some(rating_str) = get(i_rating) {
            if let Ok(lt_rating) = rating_str.parse::<f32>() {
                // LT 0-10 → our 1-5: divide by 2, round, clamp
                let rating = (lt_rating / 2.0).round() as i32;
                if (1..=5).contains(&rating) {
                    fieldwork_db::books_db::rate_book(pool, user_id, book_id, rating, now)
                        .await
                        .ok();
                    stats.rated += 1;
                }
            }
        }

        // Review
        if let Some(review_text) = get(i_review) {
            let id = fieldwork::id::generate_id();
            let review = fieldwork_db::books_db::ReviewRow {
                id,
                user_id,
                persona_id: user_id,
                book_id,
                content: review_text.to_string(),
                content_html: format!("<p>{}</p>", ammonia::clean(review_text)),
                rating: None,
                spoiler: false,
                ap_id: format!("https://{}/reviews/{}", domain, id),
                created_at: now,
            };
            fieldwork_db::books_db::create_review(pool, &review)
                .await
                .ok();
            stats.reviews_imported += 1;
        }
    }

    Ok(stats)
}

/// Map LibraryThing collection names to reading shelf status.
///
/// LT collections are free-form but common ones are "Your library",
/// "To Read", "Currently Reading", "Read but unowned", etc.
fn lt_collections_to_status(collections: &str) -> Option<&'static str> {
    let lower = collections.to_ascii_lowercase();
    if lower.contains("currently reading") || lower.contains("reading now") {
        Some("reading")
    } else if lower.contains("to read") || lower.contains("to-read") || lower.contains("wishlist") {
        Some("to-read")
    } else if lower.contains("read") || lower.contains("your library") {
        // "Read but unowned", "Read", or default "Your library" → read
        Some("read")
    } else {
        // Unknown collection — default to "read" since it's in their library
        Some("read")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lt_collections_to_status() {
        assert_eq!(lt_collections_to_status("Your library"), Some("read"));
        assert_eq!(lt_collections_to_status("To Read"), Some("to-read"));
        assert_eq!(
            lt_collections_to_status("Currently Reading"),
            Some("reading")
        );
        assert_eq!(lt_collections_to_status("Read but unowned"), Some("read"));
        assert_eq!(lt_collections_to_status("wishlist"), Some("to-read"));
        assert_eq!(lt_collections_to_status("reading now"), Some("reading"));
        assert_eq!(lt_collections_to_status("Custom Shelf"), Some("read"));
    }

    fn test_config() -> Config {
        toml::from_str(
            r#"
[server]
listen = "127.0.0.1:3000"
domain = "test.example"
secret_key = "test-secret-key-not-real"
[storage]
database_path = ":memory:"
media_dir = "/tmp/smallhold-test-media"
[federation]
[limits]
[defaults]
"#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn import_librarything_basic() {
        let pool = crate::db::test_pool().await;
        let config = test_config();

        // Write a test TSV file
        let dir = tempfile::tempdir().unwrap();
        let tsv_path = dir.path().join("export.tsv");
        std::fs::write(
            &tsv_path,
            "Title\tAuthor (First, Last)\tISBN\tRating\tCollections\tReview\tNumber of Pages\n\
             Snow Crash\tNeal Stephenson\t[0553380958]\t8\tYour library\tGreat book\t480\n\
             Neuromancer\tWilliam Gibson\t[0441007465]\t9\tTo Read\t\t271\n",
        )
        .unwrap();

        let stats = import_librarything(&pool, &config, &tsv_path)
            .await
            .unwrap();

        assert_eq!(stats.books_imported, 2);
        assert_eq!(stats.books_skipped, 0);
        assert_eq!(stats.shelved, 2);
        assert_eq!(stats.rated, 2);
        assert_eq!(stats.reviews_imported, 1);

        // Verify book was inserted correctly
        let book = fieldwork_db::books_db::get_book_by_isbn(&pool, "0553380958")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(book.title, "Snow Crash");
        assert_eq!(book.author, "Neal Stephenson");
        assert_eq!(book.pages, Some(480));

        // Verify shelf status
        let (status, _, _, _, _) =
            fieldwork_db::books_db::get_reading_status(&pool, crate::db::DEFAULT_USER_ID, book.id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(status, "read");

        // Verify "To Read" book
        let book2 = fieldwork_db::books_db::get_book_by_isbn(&pool, "0441007465")
            .await
            .unwrap()
            .unwrap();
        let (status2, _, _, _, _) =
            fieldwork_db::books_db::get_reading_status(&pool, crate::db::DEFAULT_USER_ID, book2.id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(status2, "to-read");
    }

    #[tokio::test]
    async fn import_librarything_dedup_by_isbn() {
        let pool = crate::db::test_pool().await;
        let config = test_config();

        // Pre-insert a book with the same ISBN
        let existing = fieldwork_db::books_db::BookRow {
            id: 42,
            title: "Snow Crash".into(),
            author: "Neal Stephenson".into(),
            isbn: Some("0553380958".into()),
            isbn13: None,
            openlibrary_id: None,
            cover_url: None,
            description: String::new(),
            pages: None,
            published_year: None,
            language: None,
            created_at: 0,
        };
        fieldwork_db::books_db::create_book(&pool, &existing)
            .await
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let tsv_path = dir.path().join("export.tsv");
        std::fs::write(
            &tsv_path,
            "Title\tAuthor (First, Last)\tISBN\tRating\tCollections\n\
             Snow Crash\tNeal Stephenson\t[0553380958]\t8\tYour library\n",
        )
        .unwrap();

        let stats = import_librarything(&pool, &config, &tsv_path)
            .await
            .unwrap();

        assert_eq!(stats.books_imported, 0);
        assert_eq!(stats.books_skipped, 1);
        // Rating and shelf should still be applied to existing book
        assert_eq!(stats.rated, 1);
        assert_eq!(stats.shelved, 1);
    }

    #[tokio::test]
    async fn import_librarything_last_first_author() {
        let pool = crate::db::test_pool().await;
        let config = test_config();

        let dir = tempfile::tempdir().unwrap();
        let tsv_path = dir.path().join("export.tsv");
        std::fs::write(
            &tsv_path,
            "Title\tAuthor (Last, First)\tISBN\n\
             Dune\tHerbert, Frank\t[0441172717]\n",
        )
        .unwrap();

        let stats = import_librarything(&pool, &config, &tsv_path)
            .await
            .unwrap();
        assert_eq!(stats.books_imported, 1);

        let book = fieldwork_db::books_db::get_book_by_isbn(&pool, "0441172717")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(book.author, "Frank Herbert");
    }

    #[tokio::test]
    async fn import_librarything_rating_conversion() {
        let pool = crate::db::test_pool().await;
        let config = test_config();

        let dir = tempfile::tempdir().unwrap();
        let tsv_path = dir.path().join("export.tsv");
        // LT rating 10 → 5, rating 1 → 1, rating 0 → skipped (rounds to 0)
        std::fs::write(
            &tsv_path,
            "Title\tAuthor (First, Last)\tISBN\tRating\n\
             Book A\tAuthor A\t[1111111111]\t10\n\
             Book B\tAuthor B\t[2222222222]\t1\n\
             Book C\tAuthor C\t[3333333333]\t0\n",
        )
        .unwrap();

        let stats = import_librarything(&pool, &config, &tsv_path)
            .await
            .unwrap();
        assert_eq!(stats.books_imported, 3);
        // Rating 0 → 0 after divide, out of 1..=5, so skipped
        assert_eq!(stats.rated, 2);
    }
}
