use crate::api::{now_millis, AuthenticatedAccount};
use crate::error::AppError;
use crate::id::generate_id;
use crate::server::{fw_pool, AppState};
use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use image::GenericImageView;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

const MAX_DESCRIPTION_CHARS: usize = 1500;
const MAX_DIMENSION: u32 = 4096;

/// Sniff MIME type from magic bytes. Returns None if unrecognized.
fn sniff_mime(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\x89PNG") {
        Some("image/png")
    } else if data.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if data.starts_with(b"GIF8") {
        Some("image/gif")
    } else if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// Map MIME type to image::ImageFormat for re-encoding.
fn image_format_for_mime(mime: &str) -> Option<image::ImageFormat> {
    match mime {
        "image/jpeg" => Some(image::ImageFormat::Jpeg),
        "image/png" => Some(image::ImageFormat::Png),
        "image/gif" => Some(image::ImageFormat::Gif),
        "image/webp" => Some(image::ImageFormat::WebP),
        _ => None,
    }
}

fn ext_for_mime(mime: &str) -> Option<&'static str> {
    match mime {
        "image/jpeg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        _ => None,
    }
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

/// Convert a fieldwork MediaRow to a local MediaRow for JSON serialization.
fn fw_media_to_local(fw: &fieldwork::media_db::MediaRow) -> MediaRow {
    MediaRow {
        id: fw.id,
        file_path: fw.file_path.clone(),
        mime_type: fw.mime_type.clone(),
        width: fw.width.map(|w| w as i64),
        height: fw.height.map(|h| h as i64),
        blurhash: fw.blurhash.clone(),
        description: if fw.description.is_empty() { None } else { Some(fw.description.clone()) },
        created_at: fw.created_at,
    }
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

                // Sniff MIME from magic bytes — don't trust the Content-Type header
                let sniffed = sniff_mime(&data).ok_or_else(|| {
                    AppError::unprocessable(
                        "Unsupported media type: could not identify image format from file contents",
                    )
                })?;

                file_mime = Some(sniffed.to_string());
                file_data = Some(data.to_vec());
            }
            "description" => {
                let text = field.text().await.map_err(|e| {
                    AppError::bad_request(format!("Failed to read description: {e}"))
                })?;
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

    // Decode image with decompression bomb limits, strip EXIF by re-encoding,
    // and resize if dimensions exceed MAX_DIMENSION.
    let fmt = image_format_for_mime(&mime)
        .ok_or_else(|| AppError::unprocessable("Unsupported image format for processing"))?;

    let (width, height, blurhash, clean_data) = tokio::task::spawn_blocking({
        let sniffed_mime = mime.clone();
        move || -> Result<(u32, u32, String, Vec<u8>), AppError> {
            // GIF frame bomb protection: reject GIFs with excessive frame counts
            if sniffed_mime == "image/gif" {
                let decoder = image::codecs::gif::GifDecoder::new(std::io::Cursor::new(&data))
                    .map_err(|e| AppError::unprocessable(format!("Invalid GIF data: {e}")))?;
                use image::AnimationDecoder;
                let frame_count = decoder.into_frames().count();
                if frame_count > 500 {
                    return Err(AppError::unprocessable(format!(
                        "GIF has too many frames ({frame_count}, max 500)"
                    )));
                }
            }

            let mut reader = image::ImageReader::new(std::io::Cursor::new(&data))
                .with_guessed_format()
                .map_err(|e| AppError::unprocessable(format!("Invalid image data: {e}")))?;
            let mut limits = image::Limits::default();
            limits.max_alloc = Some(64 * 1024 * 1024); // 64MB decoded max
            reader.limits(limits);
            let mut img = reader
                .decode()
                .map_err(|e| AppError::unprocessable(format!("Invalid image data: {e}")))?;

            let (w, h) = img.dimensions();

            // Resize if either dimension exceeds MAX_DIMENSION
            if w > MAX_DIMENSION || h > MAX_DIMENSION {
                img = img.resize(
                    MAX_DIMENSION,
                    MAX_DIMENSION,
                    image::imageops::FilterType::Lanczos3,
                );
            }

            let (w, h) = img.dimensions();

            // Re-encode to strip EXIF metadata (GPS, camera info, embedded scripts)
            let mut buf = std::io::Cursor::new(Vec::new());
            img.write_to(&mut buf, fmt)
                .map_err(|e| AppError::internal(format!("Image re-encoding failed: {e}")))?;
            let clean = buf.into_inner();

            let thumb = image::imageops::resize(
                &img.to_rgba8(),
                32,
                32,
                image::imageops::FilterType::Triangle,
            );

            let hash = blurhash::encode(4, 3, 32, 32, thumb.as_raw())
                .map_err(|e| AppError::internal(format!("Blurhash encoding failed: {e}")))?;

            Ok((w, h, hash, clean))
        }
    })
    .await
    .map_err(|e| AppError::internal(format!("Image processing task failed: {e}")))??;

    // Write the re-encoded (EXIF-stripped) image to disk
    tokio::fs::write(&abs_path, &clean_data)
        .await
        .map_err(|e| AppError::internal(format!("Failed to write media file: {e}")))?;

    let now = now_millis();
    let file_size = clean_data.len() as i64;

    fieldwork::media_db::insert_media(
        &fw_pool(&state.pool),
        &fieldwork::media_db::MediaRow {
            id,
            user_id: crate::db::DEFAULT_USER_ID.to_string(),
            persona_id: auth.account_id.clone(),
            post_id: None,
            file_path: rel_path.clone(),
            mime_type: mime.clone(),
            file_size,
            width: Some(width as i32),
            height: Some(height as i32),
            blurhash: Some(blurhash.clone()),
            integrity: None,
            description: description.clone().unwrap_or_default(),
            created_at: now,
        },
    )
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
    auth.require_scope("write")?;
    let row = process_upload(&state, &auth, multipart).await?;
    let domain = &state.config.server.domain;
    Ok((
        StatusCode::ACCEPTED,
        Json(media_attachment_json(&row, domain)),
    ))
}

/// POST /api/v1/media — sync upload, returns 200
async fn upload_media_v1(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;
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

    // ponytail: fieldwork::media_db::get_media doesn't filter by user_id
    // (ownership). Single-user smallhold doesn't need it, but we check persona_id
    // for safety via the fieldwork row.
    let fw_row = fieldwork::media_db::get_media(&fw_pool(&state.pool), media_id)
        .await?
        .ok_or_else(|| AppError::not_found("Media not found"))?;

    if fw_row.persona_id != auth.account_id {
        return Err(AppError::not_found("Media not found"));
    }

    let mut row = fw_media_to_local(&fw_row);

    let description = body
        .description
        .map(|d| d.chars().take(MAX_DESCRIPTION_CHARS).collect::<String>());

    // ponytail: fieldwork::media_db has no update_description function.
    // This is a single-column update not worth a new fieldwork function.
    // REMAINING: query

    // REMAINING: media query
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

    let fw_row = fieldwork::media_db::get_media(&fw_pool(&state.pool), media_id)
        .await?
        .ok_or_else(|| AppError::not_found("Media not found"))?;

    let row = fw_media_to_local(&fw_row);
    let domain = &state.config.server.domain;
    Ok(Json(media_attachment_json(&row, domain)))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/media", post(upload_media_v1))
        .route("/api/v2/media", post(upload_media_v2))
        .route("/api/v1/media/{id}", get(get_media).put(update_media))
}
