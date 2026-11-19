use axum::extract::{Path, State};
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::db;
use crate::turnstile::Turnstile;

const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MIN_CIPHERTEXT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const MIN_TTL_SECONDS: i64 = 60;
const MAX_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const MIN_VIEWS: i64 = 1;
const MAX_VIEWS: i64 = 10;

#[derive(Clone)]
pub(crate) struct AppState {
    pool: SqlitePool,
    turnstile: Turnstile,
}

#[derive(Deserialize)]
struct CreateRequest {
    ciphertext: String,
    nonce: String,
    ttl_seconds: i64,
    max_views: i64,
    #[serde(default)]
    turnstile_token: String,
}

#[derive(Serialize)]
struct CreateResponse {
    id: String,
    expires_at: i64,
}

#[derive(Serialize)]
struct RevealResponse {
    ciphertext: String,
    nonce: String,
    views_remaining: i64,
    expires_at: i64,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

enum ApiError {
    Invalid(&'static str),
    Gone,
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            ApiError::Invalid(message) => (StatusCode::BAD_REQUEST, message),
            ApiError::Gone => (StatusCode::GONE, "gone"),
            ApiError::Unavailable => (StatusCode::INTERNAL_SERVER_ERROR, "unavailable"),
        };
        (
            status,
            Json(ErrorBody {
                error: error.to_string(),
            }),
        )
            .into_response()
    }
}

pub fn app(pool: SqlitePool, turnstile: Turnstile) -> Router {
    Router::new()
        .route("/", get(index_page))
        .route("/n/{id}", get(note_page))
        .route("/static/app.js", get(app_js))
        .route("/static/style.css", get(style_css))
        .route("/api/notes", post(create_note))
        .route("/api/notes/{id}/reveal", post(reveal))
        .layer(middleware::from_fn(security_headers))
        .with_state(AppState { pool, turnstile })
}

async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self'; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    response
}

async fn index_page(State(state): State<AppState>) -> Html<String> {
    Html(
        include_str!("../static/index.html")
            .replace("__TURNSTILE_SITE_KEY__", state.turnstile.site_key()),
    )
}

async fn note_page(Path(_id): Path<String>) -> Html<&'static str> {
    Html(include_str!("../static/note.html"))
}

async fn app_js() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../static/app.js"),
    )
        .into_response()
}

async fn style_css() -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../static/style.css"),
    )
        .into_response()
}

async fn create_note(
    State(state): State<AppState>,
    Json(body): Json<CreateRequest>,
) -> Result<(StatusCode, Json<CreateResponse>), ApiError> {
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&body.ttl_seconds) {
        return Err(ApiError::Invalid(
            "Lifetime must be between 1 minute and 7 days",
        ));
    }
    if !(MIN_VIEWS..=MAX_VIEWS).contains(&body.max_views) {
        return Err(ApiError::Invalid("Views must be between 1 and 10"));
    }
    let ciphertext = STANDARD
        .decode(body.ciphertext.trim())
        .map_err(|_| ApiError::Invalid("Ciphertext or nonce is not valid base64"))?;
    let nonce = STANDARD
        .decode(body.nonce.trim())
        .map_err(|_| ApiError::Invalid("Ciphertext or nonce is not valid base64"))?;
    if nonce.len() != NONCE_BYTES {
        return Err(ApiError::Invalid("Nonce must be 12 bytes"));
    }
    if !(MIN_CIPHERTEXT_BYTES..=MAX_CIPHERTEXT_BYTES).contains(&ciphertext.len()) {
        return Err(ApiError::Invalid(
            "Ciphertext must be between 16 bytes and 64 KiB",
        ));
    }
    let token = body.turnstile_token.trim();
    if token.is_empty() || token.len() > 2048 {
        return Err(ApiError::Invalid("Complete the Turnstile check."));
    }
    match state.turnstile.verify(token).await {
        Ok(true) => {}
        Ok(false) => return Err(ApiError::Invalid("Complete the Turnstile check.")),
        Err(error) => {
            eprintln!("turnstile verification failed: {error}");
            return Err(ApiError::Unavailable);
        }
    }

    let created_at = db::now_unix();
    let expires_at = created_at + body.ttl_seconds;

    for _ in 0..3 {
        let id = new_id();
        match db::insert_note(
            &state.pool,
            &id,
            &ciphertext,
            &nonce,
            created_at,
            expires_at,
            body.max_views,
        )
        .await
        {
            Ok(()) => {
                return Ok((StatusCode::CREATED, Json(CreateResponse { id, expires_at })));
            }
            Err(error) if is_unique(&error) => continue,
            Err(error) => {
                eprintln!("insert note failed: {error}");
                return Err(ApiError::Unavailable);
            }
        }
    }
    eprintln!("insert note failed: exhausted id retries");
    Err(ApiError::Unavailable)
}

async fn reveal(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RevealResponse>, ApiError> {
    if id.len() > 64 {
        return Err(ApiError::Gone);
    }
    match db::reveal_note(&state.pool, &id).await {
        Ok(Some(note)) => Ok(Json(RevealResponse {
            ciphertext: STANDARD.encode(note.ciphertext),
            nonce: STANDARD.encode(note.nonce),
            views_remaining: note.views_remaining,
            expires_at: note.expires_at,
        })),
        Ok(None) => Err(ApiError::Gone),
        Err(error) => {
            eprintln!("reveal note failed: {error}");
            Err(ApiError::Unavailable)
        }
    }
}

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("system random source");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn is_unique(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database) => database.is_unique_violation(),
        _ => false,
    }
}
