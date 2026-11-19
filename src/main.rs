use std::path::Path;
use std::time::Duration;

use secure_note::{Turnstile, app, connect, purge_expired};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:data/notes.db".to_string());
    ensure_parent_dir(&database_url);

    let pool = connect(&database_url).await?;
    let cleanup = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Err(error) = purge_expired(&cleanup).await {
                eprintln!("purge expired notes failed: {error}");
            }
        }
    });

    let turnstile = Turnstile::from_env()?;
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("listening on http://{bind}");
    axum::serve(listener, app(pool, turnstile)).await?;
    Ok(())
}

fn ensure_parent_dir(database_url: &str) {
    let Some(path) = sqlite_file_path(database_url) else {
        return;
    };
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                eprintln!("could not create database directory: {error}");
            }
        }
    }
}

fn sqlite_file_path(database_url: &str) -> Option<&str> {
    let rest = database_url.strip_prefix("sqlite:")?;
    let rest = rest.trim_start_matches("//");
    let path = rest.split('?').next().unwrap_or(rest);
    if path.is_empty() || path.starts_with(":memory:") {
        None
    } else {
        Some(path)
    }
}
