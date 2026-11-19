# Secure Note

Temporary notes encrypted in the browser with AES-256-GCM. The server stores ciphertext in SQLite and deletes a note when its time limit or view limit is reached. There are no accounts.

## Run

```bash
cargo run
```

Open http://127.0.0.1:3000

- `BIND` — listen address, default `127.0.0.1:3000`
- `DATABASE_URL` — SQLite URL, default `sqlite:data/notes.db`
- `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` — Cloudflare Turnstile keys. When both are unset, the app uses Cloudflare's always-pass test keys and prints a warning. Set both before deploying.

Creating a note requires a Turnstile token. The create page shows the widget, and the server checks the token with Cloudflare before storing the ciphertext.

## How a note is shared

The browser generates a random 256-bit key and encrypts the message before upload. The key is placed in the URL fragment (`#...`). Browsers do not send fragments to the server. Opening the link does not use a view; the recipient presses Reveal, which is the only request that counts.

Limits: ciphertext at most 64 KiB, lifetime from 1 minute to 7 days, and 1 to 10 views.

## What the server can and cannot do

The server can refuse a note, delete it early, or withhold it. It never receives the key or the plaintext, so it cannot read the message. Anyone who has the full link, including the fragment, can read the note until it expires.

## Test

```bash
cargo test
```
