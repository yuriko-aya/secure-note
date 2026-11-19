use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;

use crate::db::{self, insert_note};
use crate::routes::app;
use crate::turnstile::Turnstile;

async fn pool() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    pool
}

fn request(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(Body::from(
            body.map(|value| value.to_string()).unwrap_or_default(),
        ))
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn sample_payload(ttl_seconds: i64, max_views: i64) -> Value {
    json!({
        "ciphertext": STANDARD.encode([7u8; 16]),
        "nonce": STANDARD.encode([3u8; 12]),
        "ttl_seconds": ttl_seconds,
        "max_views": max_views,
        "turnstile_token": "XXXX.DUMMY.TOKEN.XXXX",
    })
}

fn test_app(pool: sqlx::SqlitePool) -> axum::Router {
    app(pool, Turnstile::test_allow())
}

#[tokio::test]
async fn reveal_once_then_gone() {
    let pool = pool().await;
    let router = test_app(pool);
    let created = router
        .clone()
        .oneshot(request("POST", "/api/notes", Some(sample_payload(60, 1))))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body = json_body(created).await;
    let id = created_body["id"].as_str().unwrap();

    let first = router
        .clone()
        .oneshot(request("POST", &format!("/api/notes/{id}/reveal"), None))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let revealed = json_body(first).await;
    assert_eq!(revealed["ciphertext"], sample_payload(60, 1)["ciphertext"]);
    assert_eq!(revealed["nonce"], sample_payload(60, 1)["nonce"]);
    assert_eq!(revealed["views_remaining"], 0);

    let second = router
        .clone()
        .oneshot(request("POST", &format!("/api/notes/{id}/reveal"), None))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::GONE);
    assert_eq!(json_body(second).await["error"], "gone");
}

#[tokio::test]
async fn views_remaining_decrease_until_the_note_is_gone() {
    let pool = pool().await;
    let router = test_app(pool.clone());
    let created = router
        .clone()
        .oneshot(request("POST", "/api/notes", Some(sample_payload(60, 2))))
        .await
        .unwrap();
    let id = json_body(created).await["id"].as_str().unwrap().to_string();

    let first = router
        .clone()
        .oneshot(request("POST", &format!("/api/notes/{id}/reveal"), None))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(json_body(first).await["views_remaining"], 1);
    assert!(db::note_exists(&pool, &id).await.unwrap());

    let second = router
        .clone()
        .oneshot(request("POST", &format!("/api/notes/{id}/reveal"), None))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(json_body(second).await["views_remaining"], 0);
    assert!(!db::note_exists(&pool, &id).await.unwrap());

    let third = router
        .oneshot(request("POST", &format!("/api/notes/{id}/reveal"), None))
        .await
        .unwrap();
    assert_eq!(third.status(), StatusCode::GONE);
}

#[tokio::test]
async fn expired_note_is_gone() {
    let pool = pool().await;
    let id = "expired-note";
    let created_at = db::now_unix() - 120;
    insert_note(
        &pool,
        id,
        &[9u8; 16],
        &[1u8; 12],
        created_at,
        created_at + 60,
        1,
    )
    .await
    .unwrap();

    let response = test_app(pool.clone())
        .oneshot(request("POST", &format!("/api/notes/{id}/reveal"), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(json_body(response).await["error"], "gone");
    assert!(!db::note_exists(&pool, id).await.unwrap());
}

#[tokio::test]
async fn purge_removes_expired_notes() {
    let pool = pool().await;
    let now = db::now_unix();
    insert_note(&pool, "old", &[9u8; 16], &[1u8; 12], now - 10, now - 1, 3)
        .await
        .unwrap();
    insert_note(&pool, "fresh", &[9u8; 16], &[1u8; 12], now, now + 60, 3)
        .await
        .unwrap();

    let removed = db::purge_expired(&pool).await.unwrap();
    assert_eq!(removed, 1);
    assert!(!db::note_exists(&pool, "old").await.unwrap());
    assert!(db::note_exists(&pool, "fresh").await.unwrap());
}

#[tokio::test]
async fn rejects_out_of_range_limits() {
    let router = test_app(pool().await);
    let ttl = router
        .clone()
        .oneshot(request("POST", "/api/notes", Some(sample_payload(30, 1))))
        .await
        .unwrap();
    assert_eq!(ttl.status(), StatusCode::BAD_REQUEST);

    let views = router
        .oneshot(request("POST", "/api/notes", Some(sample_payload(60, 11))))
        .await
        .unwrap();
    assert_eq!(views.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_page_includes_the_turnstile_site_key() {
    let response = test_app(pool().await)
        .oneshot(request("GET", "/", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(html.contains("data-sitekey=\"1x00000000000000000000AA\""));
    assert!(html.contains("challenges.cloudflare.com/turnstile/v0/api.js"));
    assert!(!html.contains("1x0000000000000000000000000000000AA"));
}

#[tokio::test]
async fn missing_turnstile_token_is_rejected() {
    let pool = pool().await;
    let mut payload = sample_payload(60, 1);
    payload["turnstile_token"] = Value::String(String::new());
    let response = test_app(pool.clone())
        .oneshot(request("POST", "/api/notes", Some(payload)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"],
        "Complete the Turnstile check."
    );
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn rejected_turnstile_token_does_not_store_a_note() {
    let pool = pool().await;
    let response = app(pool.clone(), Turnstile::test_reject())
        .oneshot(request("POST", "/api/notes", Some(sample_payload(60, 1))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"],
        "Complete the Turnstile check."
    );
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM notes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn missing_note_is_gone() {
    let response = test_app(pool().await)
        .oneshot(request("POST", "/api/notes/missing/reveal", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(json_body(response).await["error"], "gone");
}
