use crate::api::{now_millis, AuthenticatedAccount};
use crate::error::AppError;
use crate::id::generate_id;
use crate::server::AppState;
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use image::GenericImageView;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

const ALLOWED_MIMES: &[&str] = &["image/jpeg", "image/png", "image/gif", "image/webp"];
const MAX_DESCRIPTION_CHARS: usize = 1500;

fn ext_for_mime(mime: &str) -> Option<&'static str> {
    match mime {
        "image/jpeg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        _ => None,
    }
}

fn is_video_mime(mime: &str) -> bool {
    mime.starts_with("video/")
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)] // All fields are needed by FromRow; not all are used in rendering
struct MediaRow {
    id: i64,
    file_path: String,
    mime_type: String,
    width: Option<i64>,
    height: Option<i64>,
    blurhash: Option<String>,
    description: Option<String>,
    created_at: i64,
}

fn media_attachment_json(row: &MediaRow, domain: &str) -> Value {
    let url = format!("https://{domain}/{}", row.file_path);

    let (meta_original, meta_small) = match (row.width, row.height) {
        (Some(w), Some(h)) if w > 0 && h > 0 => {
            let aspect = w as f64 / h as f64;
            let (sw, sh) = downscale_dimensions(w as u32, h as u32, 400);
            let small_aspect = sw as f64 / sh as f64;
            (
                json!({
                    "width": w,
                    "height": h,
                    "size": format!("{w}x{h}"),
                    "aspect": (aspect * 1000.0).round() / 1000.0,
                }),
                json!({
                    "width": sw,
                    "height": sh,
                    "size": format!("{sw}x{sh}"),
                    "aspect": (small_aspect * 1000.0).round() / 1000.0,
                }),
            )
        }
        _ => (json!(null), json!(null)),
    };

    json!({
        "id": row.id.to_string(),
        "type": "image",
        "url": url,
        "preview_url": url,
        "remote_url": null,
        "text_url": null,
        "meta": {
            "original": meta_original,
            "small": meta_small,
        },
        "description": row.description,
        "blurhash": row.blurhash,
    })
}

/// Compute dimensions for the "small" metadata, fitting within max_width while preserving aspect ratio.
fn downscale_dimensions(w: u32, h: u32, max_width: u32) -> (u32, u32) {
    if w <= max_width {
        return (w, h);
    }
    let ratio = max_width as f64 / w as f64;
    let sh = (h as f64 * ratio).round() as u32;
    (max_width, sh.max(1))
}

async fn process_upload(
    state: &Arc<AppState>,
    auth: &AuthenticatedAccount,
    mut multipart: Multipart,
) -> Result<MediaRow, AppError> {
    let max_bytes = state.config.limits.max_media_mb * 1024 * 1024;
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_mime: Option<String> = None;
    let mut description: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(format!("Invalid multipart data: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "file" => {
                let content_type = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();

                if is_video_mime(&content_type) {
                    return Err(AppError::unprocessable("Video uploads are not supported"));
                }

                if !ALLOWED_MIMES.contains(&content_type.as_str()) {
                    return Err(AppError::unprocessable(format!(
                        "Unsupported media type: {content_type}"
                    )));
                }

                let data = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::bad_request(format!("Failed to read file: {e}")))?;

                if data.len() > max_bytes {
                    return Err(AppError::unprocessable(format!(
                        "File exceeds maximum size of {} MB",
                        state.config.limits.max_media_mb
                    )));
                }

                file_mime = Some(content_type);
                file_data = Some(data.to_vec());
            }
            "description" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::bad_request(format!("Failed to read description: {e}")))?;
                if !text.is_empty() {
                    let truncated: String = text.chars().take(MAX_DESCRIPTION_CHARS).collect();
                    description = Some(truncated);
                }
            }
            _ => {}
        }
    }

    let data = file_data.ok_or_else(|| AppError::bad_request("Missing file field"))?;
    let mime = file_mime.unwrap(); // safe: set together with file_data
    let ext = ext_for_mime(&mime).unwrap(); // safe: validated against ALLOWED_MIMES

    let id = generate_id();
    let id_hex = format!("{id:x}");
    let prefix = &id_hex[..2.min(id_hex.len())];
    let rel_path = format!("media/{prefix}/{id}.{ext}");

    let abs_dir = std::path::Path::new(&state.config.storage.media_dir).join(prefix);
    tokio::fs::create_dir_all(&abs_dir)
        .await
        .map_err(|e| AppError::internal(format!("Failed to create media directory: {e}")))?;

    let abs_path = std::path::Path::new(&state.config.storage.media_dir)
        .join(prefix)
        .join(format!("{id}.{ext}"));

    tokio::fs::write(&abs_path, &data)
        .await
        .map_err(|e| AppError::internal(format!("Failed to write media file: {e}")))?;

    // Decode image for dimensions and blurhash
    let (width, height, blurhash) = tokio::task::spawn_blocking({
        let data = data.clone();
        move || -> Result<(u32, u32, String), AppError> {
            let img = image::load_from_memory(&data)
                .map_err(|e| AppError::unprocessable(format!("Invalid image data: {e}")))?;

            let (w, h) = img.dimensions();

            let thumb = image::imageops::resize(
                &img.to_rgba8(),
                32,
                32,
                image::imageops::FilterType::Triangle,
            );

            let hash = blurhash::encode(4, 3, 32, 32, thumb.as_raw())
                .map_err(|e| AppError::internal(format!("Blurhash encoding failed: {e}")))?;

            Ok((w, h, hash))
        }
    })
    .await
    .map_err(|e| AppError::internal(format!("Image processing task failed: {e}")))?
    ?;

    let now = now_millis();
    let file_size = data.len() as i64;

    sqlx::query(
        "INSERT INTO media (id, account_id, file_path, mime_type, file_size, width, height, blurhash, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(auth.account_id)
    .bind(&rel_path)
    .bind(&mime)
    .bind(file_size)
    .bind(width as i64)
    .bind(height as i64)
    .bind(&blurhash)
    .bind(&description)
    .bind(now)
    .execute(&state.pool)
    .await?;

    Ok(MediaRow {
        id,
        file_path: rel_path,
        mime_type: mime,
        width: Some(width as i64),
        height: Some(height as i64),
        blurhash: Some(blurhash),
        description,
        created_at: now,
    })
}

/// POST /api/v2/media — async upload, returns 202
async fn upload_media_v2(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    multipart: Multipart,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let row = process_upload(&state, &auth, multipart).await?;
    let domain = &state.config.server.domain;
    Ok((StatusCode::ACCEPTED, Json(media_attachment_json(&row, domain))))
}

/// POST /api/v1/media — sync upload, returns 200
async fn upload_media_v1(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let row = process_upload(&state, &auth, multipart).await?;
    let domain = &state.config.server.domain;
    Ok(Json(media_attachment_json(&row, domain)))
}

/// PUT /api/v1/media/{id} — update description
async fn update_media(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<UpdateMediaRequest>,
) -> Result<Json<Value>, AppError> {
    let media_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Media not found"))?;

    let row: Option<MediaRow> = sqlx::query_as(
        "SELECT id, file_path, mime_type, width, height, blurhash, description, created_at FROM media WHERE id = ? AND account_id = ?",
    )
    .bind(media_id)
    .bind(auth.account_id)
    .fetch_optional(&state.pool)
    .await?;

    let mut row = row.ok_or_else(|| AppError::not_found("Media not found"))?;

    let description = body
        .description
        .map(|d| d.chars().take(MAX_DESCRIPTION_CHARS).collect::<String>());

    sqlx::query("UPDATE media SET description = ? WHERE id = ?")
        .bind(&description)
        .bind(media_id)
        .execute(&state.pool)
        .await?;

    row.description = description;

    let domain = &state.config.server.domain;
    Ok(Json(media_attachment_json(&row, domain)))
}

#[derive(Deserialize)]
struct UpdateMediaRequest {
    description: Option<String>,
}

/// GET /api/v1/media/{id} — get media metadata
async fn get_media(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let media_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Media not found"))?;

    let row: Option<MediaRow> = sqlx::query_as(
        "SELECT id, file_path, mime_type, width, height, blurhash, description, created_at FROM media WHERE id = ?",
    )
    .bind(media_id)
    .fetch_optional(&state.pool)
    .await?;

    let row = row.ok_or_else(|| AppError::not_found("Media not found"))?;
    let domain = &state.config.server.domain;
    Ok(Json(media_attachment_json(&row, domain)))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/media", post(upload_media_v1))
        .route("/api/v2/media", post(upload_media_v2))
        .route("/api/v1/media/{id}", get(get_media).put(update_media))
}
