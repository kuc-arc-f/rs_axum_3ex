//! ログインセッション（Cookie）の発行・検証
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, header, request::Parts},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{AppState, error::AppError};

pub const SESSION_COOKIE: &str = "session";
const SESSION_TTL_DAYS: i32 = 7;

/// 認証済みユーザー。ハンドラの引数に書くだけでログイン必須になる
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CurrentUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = cookie_value(&parts.headers, SESSION_COOKIE)
            .ok_or(AppError::Unauthorized("ログインが必要です"))?;

        sqlx::query_as::<_, CurrentUser>(
            "SELECT u.id, u.username, u.display_name
               FROM sessions s
               JOIN passkey_users u ON u.id = s.user_id
              WHERE s.token_hash = $1 AND s.expires_at > now()",
        )
        .bind(hash_token(&token))
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::Unauthorized("セッションが無効です"))
    }
}

/// セッションを新規作成し、Cookie に入れる生トークンを返す
pub async fn create_session(db: &PgPool, user_id: Uuid) -> Result<String, AppError> {
    let token = new_token();
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at)
         VALUES ($1, $2, now() + make_interval(days => $3))",
    )
    .bind(hash_token(&token))
    .bind(user_id)
    .bind(SESSION_TTL_DAYS)
    .execute(db)
    .await?;
    Ok(token)
}

pub fn set_cookie(token: &str, secure: bool) -> String {
    let max_age = i64::from(SESSION_TTL_DAYS) * 24 * 60 * 60;
    format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{}",
        secure_attr(secure)
    )
}

pub fn clear_cookie(secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{}",
        secure_attr(secure)
    )
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// 256bit の乱数トークン
fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// DB には生トークンを保存せず SHA-256 を保存する
pub fn hash_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn secure_attr(secure: bool) -> &'static str {
    if secure { "; Secure" } else { "" }
}
