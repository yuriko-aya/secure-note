use std::time::Duration;

use serde::Deserialize;

const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
pub(crate) const TEST_SITE_KEY: &str = "1x00000000000000000000AA";
const TEST_SECRET_KEY: &str = "1x0000000000000000000000000000000AA";

#[derive(Clone)]
pub struct Turnstile {
    site_key: String,
    checker: Checker,
}

#[derive(Clone)]
enum Checker {
    Cloudflare {
        secret: String,
        client: reqwest::Client,
    },
    #[cfg(test)]
    AllowAny,
    #[cfg(test)]
    RejectAll,
}

#[derive(Deserialize)]
struct SiteverifyResponse {
    success: bool,
    #[serde(default, rename = "error-codes")]
    error_codes: Vec<String>,
}

impl Turnstile {
    pub fn from_env() -> Result<Self, String> {
        match (
            std::env::var("TURNSTILE_SITE_KEY").ok(),
            std::env::var("TURNSTILE_SECRET_KEY").ok(),
        ) {
            (Some(site_key), Some(secret_key)) => Self::cloudflare(site_key, secret_key),
            (None, None) => {
                eprintln!(
                    "warning: TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY are unset; using Cloudflare's always-pass test keys"
                );
                Self::cloudflare(TEST_SITE_KEY.to_string(), TEST_SECRET_KEY.to_string())
            }
            _ => Err(
                "set both TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY, or leave both unset"
                    .to_string(),
            ),
        }
    }

    pub fn cloudflare(site_key: String, secret_key: String) -> Result<Self, String> {
        if !key_ok(&site_key) {
            return Err(
                "TURNSTILE_SITE_KEY is empty or contains unsupported characters".to_string(),
            );
        }
        if !key_ok(&secret_key) {
            return Err(
                "TURNSTILE_SECRET_KEY is empty or contains unsupported characters".to_string(),
            );
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| format!("could not build the Turnstile client: {error}"))?;
        Ok(Self {
            site_key,
            checker: Checker::Cloudflare {
                secret: secret_key,
                client,
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn test_allow() -> Self {
        Self {
            site_key: TEST_SITE_KEY.to_string(),
            checker: Checker::AllowAny,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_reject() -> Self {
        Self {
            site_key: TEST_SITE_KEY.to_string(),
            checker: Checker::RejectAll,
        }
    }

    pub(crate) fn site_key(&self) -> &str {
        &self.site_key
    }

    pub(crate) async fn verify(&self, token: &str) -> Result<bool, String> {
        match &self.checker {
            Checker::Cloudflare { secret, client } => {
                let response = client
                    .post(SITEVERIFY_URL)
                    .json(&serde_json::json!({
                        "secret": secret,
                        "response": token,
                    }))
                    .send()
                    .await
                    .map_err(|error| error.to_string())?;
                if !response.status().is_success() {
                    return Err(format!("siteverify returned {}", response.status()));
                }
                let body: SiteverifyResponse =
                    response.json().await.map_err(|error| error.to_string())?;
                if !body.success {
                    eprintln!("turnstile rejected: {}", body.error_codes.join(", "));
                }
                Ok(body.success)
            }
            #[cfg(test)]
            Checker::AllowAny => Ok(true),
            #[cfg(test)]
            Checker::RejectAll => Ok(false),
        }
    }
}

fn key_ok(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value.chars().all(|character| {
            character.is_ascii_graphic() && !matches!(character, '"' | '\'' | '<' | '>' | '&')
        })
}
