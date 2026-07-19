use anyhow::{Context, Result};
use sqlx::SqlitePool;
use std::path::Path;

use crate::config::Config;

pub struct ImportStats {
    pub posts_imported: usize,
    pub posts_skipped: usize,
    pub media_imported: usize,
    pub follows_found: usize,
    pub blocks_found: usize,
    pub mutes_found: usize,
    pub profile_updated: bool,
}

pub async fn import_mastodon_archive(
    pool: &SqlitePool,
    config: &Config,
    username: &str,
    archive_path: &Path,
) -> Result<ImportStats> {
    let account: (i64,) = sqlx::query_as("SELECT id FROM accounts WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Persona @{username} not found"))?;
    let account_id = account.0;
    let domain = &config.server.domain;

    let tmp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    extract_archive(archive_path, tmp_dir.path())?;

    // Find the root — some archives nest everything under a subdirectory
    let extract_root = find_extract_root(tmp_dir.path());

    let mut stats = ImportStats {
        posts_imported: 0,
        posts_skipped: 0,
        media_imported: 0,
        follows_found: 0,
        blocks_found: 0,
        mutes_found: 0,
        profile_updated: false,
    };

    // 1. Parse and apply actor.json
    let actor_path = extract_root.join("actor.json");
    if actor_path.exists() {
        stats.profile_updated = apply_actor_profile(pool, account_id, &actor_path).await?;
    }

    // 2. Parse and import outbox.json
    let outbox_path = extract_root.join("outbox.json");
    if outbox_path.exists() {
        import_outbox(
            pool,
            config,
            account_id,
            username,
            domain,
            &extract_root,
            &outbox_path,
            &mut stats,
        )
        .await?;
    }

    // 3. Parse following_accounts.csv
    let following_path = extract_root.join("following_accounts.csv");
    if following_path.exists() {
        stats.follows_found = count_csv_rows(&following_path)?;
    }

    // 4. Parse blocked_accounts.csv
    let blocked_path = extract_root.join("blocked_accounts.csv");
    if blocked_path.exists() {
        stats.blocks_found = count_csv_rows(&blocked_path)?;
    }

    // 5. Parse muted_accounts.csv
    let muted_path = extract_root.join("muted_accounts.csv");
    if muted_path.exists() {
        stats.mutes_found = count_csv_rows(&muted_path)?;
    }

    Ok(stats)
}

fn extract_archive(archive_path: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;
    let decompressor = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decompressor);
    let canonical_dest = dest
        .canonicalize()
        .with_context(|| format!("Failed to canonicalize dest: {}", dest.display()))?;

    for entry_result in archive.entries().context("Failed to read tar entries")? {
        let mut entry = entry_result.context("Failed to read tar entry")?;
        let entry_path = entry
            .path()
            .context("Failed to read entry path")?
            .into_owned();

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

async fn apply_actor_profile(pool: &SqlitePool, account_id: i64, path: &Path) -> Result<bool> {
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

    sqlx::query(
        "UPDATE accounts SET display_name = ?, bio = ?, bio_html = ?, fields_json = ? WHERE id = ?",
    )
    .bind(&display_name)
    .bind(&bio)
    .bind(&bio_html)
    .bind(&fields_json)
    .bind(account_id)
    .execute(pool)
    .await?;

    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn import_outbox(
    pool: &SqlitePool,
    config: &Config,
    account_id: i64,
    username: &str,
    domain: &str,
    extract_root: &Path,
    outbox_path: &Path,
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

    let media_dir = Path::new(&config.storage.media_dir);
    std::fs::create_dir_all(media_dir)
        .with_context(|| format!("Failed to create media dir: {}", media_dir.display()))?;

    // Track last timestamp for sequence deduplication
    let mut last_ms: i64 = 0;
    let mut last_seq: u32 = 0;

    let mut tx = pool.begin().await?;

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

        // Insert the post
        let result = sqlx::query(
            "INSERT INTO posts (id, account_id, ap_id, in_reply_to_uri, content, content_html, spoiler_text, visibility, sensitive, language, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(account_id)
        .bind(&ap_id)
        .bind(in_reply_to_uri.as_deref())
        .bind(&content_clean)
        .bind(&content_html)
        .bind(&spoiler_text)
        .bind(&visibility)
        .bind(sensitive as i32)
        .bind(language.as_deref())
        .bind(published_ms)
        .execute(&mut *tx)
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
                        let _ = sqlx::query(
                            "INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)",
                        )
                        .bind(id)
                        .bind(&tag_name)
                        .execute(&mut *tx)
                        .await;
                    }
                }

                // Best-effort mention insertion
                if tag_type == "Mention" {
                    if let Some(href) = tag.get("href").and_then(|v| v.as_str()) {
                        // Try to find this account in our DB by actor URI
                        let remote: Option<(i64,)> =
                            sqlx::query_as("SELECT id FROM remote_accounts WHERE actor_uri = ?")
                                .bind(href)
                                .fetch_optional(&mut *tx)
                                .await
                                .unwrap_or(None);

                        if let Some((remote_id,)) = remote {
                            let _ = sqlx::query(
                                "INSERT OR IGNORE INTO mentions (post_id, mentioned_remote_id) VALUES (?, ?)",
                            )
                            .bind(id)
                            .bind(remote_id)
                            .execute(&mut *tx)
                            .await;
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
                        let dest_filename = format!("{media_id}.{ext}");
                        let dest_path = media_dir.join(&dest_filename);

                        if let Err(e) = std::fs::copy(&src, &dest_path) {
                            tracing::warn!("Failed to copy media {}: {e}", src.display());
                            continue;
                        }

                        let file_size = std::fs::metadata(&dest_path)
                            .map(|m| m.len() as i64)
                            .unwrap_or(0);

                        let _ = sqlx::query(
                            "INSERT INTO media (id, account_id, post_id, file_path, mime_type, file_size, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        )
                        .bind(media_id)
                        .bind(account_id)
                        .bind(id)
                        .bind(&dest_filename)
                        .bind(media_type)
                        .bind(file_size)
                        .bind(description)
                        .bind(published_ms)
                        .execute(&mut *tx)
                        .await;

                        stats.media_imported += 1;
                    }
                }
            }
        }

        stats.posts_imported += 1;
    }

    tx.commit().await?;

    Ok(())
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
    uri == "https://www.w3.org/ns/activitystreams#Public"
        || uri == "as:Public"
        || uri == "Public"
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

fn count_csv_rows(path: &Path) -> Result<usize> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    // Subtract 1 for header row, handle empty files
    let lines: usize = content.lines().count();
    Ok(lines.saturating_sub(1))
}
