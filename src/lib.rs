mod db;
mod routes;
mod turnstile;

pub use routes::app;
pub use turnstile::Turnstile;

pub async fn connect(database_url: &str) -> Result<sqlx::SqlitePool, sqlx::Error> {
    let pool = db::connect(database_url).await?;
    db::migrate(&pool).await?;
    Ok(pool)
}

pub async fn purge_expired(pool: &sqlx::SqlitePool) -> Result<u64, sqlx::Error> {
    db::purge_expired(pool).await
}

#[cfg(test)]
mod tests;
