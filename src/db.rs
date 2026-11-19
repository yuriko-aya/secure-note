use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, SqlitePool};

#[derive(Debug, FromRow)]
pub(crate) struct StoredNote {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) nonce: Vec<u8>,
    pub(crate) expires_at: i64,
    pub(crate) max_views: i64,
    pub(crate) views: i64,
}

pub(crate) struct RevealedNote {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) nonce: Vec<u8>,
    pub(crate) expires_at: i64,
    pub(crate) views_remaining: i64,
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(crate) async fn connect(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(5));
    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
}

pub(crate) async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            max_views INTEGER NOT NULL,
            views INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS notes_expires_at ON notes (expires_at)")
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) async fn insert_note(
    pool: &SqlitePool,
    id: &str,
    ciphertext: &[u8],
    nonce: &[u8],
    created_at: i64,
    expires_at: i64,
    max_views: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO notes (id, ciphertext, nonce, created_at, expires_at, max_views, views)
         VALUES (?, ?, ?, ?, ?, ?, 0)",
    )
    .bind(id)
    .bind(ciphertext)
    .bind(nonce)
    .bind(created_at)
    .bind(expires_at)
    .bind(max_views)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reads a note and consumes one view. Expired notes and notes with no views
/// left are deleted and reported as missing. A note that reaches its view
/// limit is deleted in the same transaction, after its ciphertext is read.
pub(crate) async fn reveal_note(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<RevealedNote>, sqlx::Error> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let row = sqlx::query_as::<_, StoredNote>(
        "SELECT ciphertext, nonce, expires_at, max_views, views FROM notes WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };

    let now = now_unix();
    if row.expires_at <= now || row.views >= row.max_views {
        sqlx::query("DELETE FROM notes WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(None);
    }

    let new_views = row.views + 1;
    if new_views >= row.max_views {
        sqlx::query("DELETE FROM notes WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("UPDATE notes SET views = ? WHERE id = ?")
            .bind(new_views)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    Ok(Some(RevealedNote {
        ciphertext: row.ciphertext,
        nonce: row.nonce,
        expires_at: row.expires_at,
        views_remaining: row.max_views - new_views,
    }))
}

pub(crate) async fn purge_expired(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM notes WHERE expires_at <= ?")
        .bind(now_unix())
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
pub(crate) async fn note_exists(pool: &SqlitePool, id: &str) -> Result<bool, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM notes WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}
