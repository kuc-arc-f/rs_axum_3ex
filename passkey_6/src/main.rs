//! Axum + SQLite + WebAuthn(Passkey / Windows Hello) 認証サンプル
use std::{collections::HashMap, env, str::FromStr, sync::Arc};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use tokio::sync::Mutex;
use tower_http::services::ServeDir;
use webauthn_rs::prelude::*;

mod models;
mod mod_auth;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS passkey_users (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);
CREATE TABLE IF NOT EXISTS passkeys (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES passkey_users(id) ON DELETE CASCADE,
    passkey TEXT NOT NULL  -- Passkey の JSON
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES passkey_users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);
"#;

const SESSION_TTL_SECS: i64 = 7 * 24 * 3600;

// ---------- 状態 ----------
struct PendingReg {
    user_id: Uuid,
    username: String,
    state: PasskeyRegistration,
}
struct PendingAuth {
    user_id: String,
    state: PasskeyAuthentication,
}

#[derive(Clone)]
struct AppState {
    webauthn: Arc<Webauthn>,
    db: SqlitePool,
    // チャレンジ状態はメモリ保持(再起動で消える。本番は TTL 付きで管理推奨)
    reg: Arc<Mutex<HashMap<Uuid, PendingReg>>>,
    auth: Arc<Mutex<HashMap<Uuid, PendingAuth>>>,
}

// ---------- エラー ----------
struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
impl<E: std::fmt::Display> From<E> for AppError {
    fn from(e: E) -> Self {
        eprintln!("internal error: {e}");
        AppError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}
fn bad(msg: &str) -> AppError {
    AppError(StatusCode::BAD_REQUEST, msg.into())
}
type ApiResult<T> = Result<T, AppError>;

// ---------- main ----------
#[tokio::main]
async fn main() -> anyhow_free::Result<()> {
    let rp_id = env::var("RP_ID").unwrap_or_else(|_| "localhost".into());
    let rp_origin =
        env::var("RP_ORIGIN").unwrap_or_else(|_| "http://localhost:3000".into());
    let rp_origin = Url::parse(&rp_origin)?;

    let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
        .rp_name("Passkey Axum Demo")
        .build()?;

    let opts = SqliteConnectOptions::from_str("sqlite://app.db")?
        .create_if_missing(true)
        .foreign_keys(true);
    let db = SqlitePoolOptions::new().max_connections(5).connect_with(opts).await?;
    sqlx::raw_sql(SCHEMA).execute(&db).await?;

    let state = AppState {
        webauthn: Arc::new(webauthn),
        db,
        reg: Default::default(),
        auth: Default::default(),
    };

    let app = Router::new()
        .route("/api/signup", post(user_create))
        .route("/api/register/start", post(register_start))
        .route("/api/register/finish", post(register_finish))
        .route("/api/login", post(user_login))
        .route("/api/login/start", post(login_start))
        .route("/api/login/finish", post(login_finish))
        .route("/api/user_get_id", post(user_get_id))
        .route("/api/me", get(me))
        .route("/api/logout", post(logout))
        .fallback_service(ServeDir::new("static"))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("listening on http://localhost:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn user_get_id(
    State(s): State<AppState>,
    Json(payload): Json<models::UserIdReq>,
) -> ApiResult<Json<Value>> {
    let mut user = models::UserRes {
        email: "".to_string(),
        password: "".to_string(),
    };
    println!("#user_login");
    println!("{:?}", payload);
    let exists: Option<(i64, String)> = sqlx::query_as("SELECT id , password_hash FROM users WHERE email = ?")
        .bind(&payload.email)
        .fetch_optional(&s.db)
        .await?;
    println!("#exists");
    println!("{:?}", exists);
    if exists.is_none() {
        return Err(bad("error , user is NONE"));
    }  
    let user_id = exists.unwrap().0;
    Ok(Json(json!({ 
        "ret": 0 , "user_id": user_id
    })))
}

async fn user_create(
    State(s): State<AppState>,
    Json(payload): Json<models::UserCreateReq>,
) -> ApiResult<Json<Value>> {
    let mut user = models::UserRes {
        email: "".to_string(),
        password: "".to_string(),
    };

    println!("{:?}", payload);
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE email = ?")
        .bind(&payload.email)
        .fetch_optional(&s.db)
        .await?;
    if exists.is_some() {
        return Err(AppError(StatusCode::CONFLICT, "そのユーザー名は使用済みです".into()));
    }
    let pw = payload.password.clone();

    let phc = mod_auth::hash_password(&pw).expect("error , hash_password");
    println!("phc: {}", phc);

    let ok = mod_auth::verify_password(&pw, &phc).expect("error , veryfy password");
    println!("password ok? {}", ok);

    let mut tx = s.db.begin().await?;
    sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
        .bind(&payload.email)
        .bind(&phc)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;      

    Ok(Json(json!({ "challenge_id": 0, "options": "".to_string() })))
}

async fn user_login(
    State(s): State<AppState>,
    Json(payload): Json<models::UserCreateReq>,
) -> ApiResult<Json<Value>> {
    let mut user = models::UserRes {
        email: "".to_string(),
        password: "".to_string(),
    };
    println!("#user_login");
    println!("{:?}", payload);
    let exists: Option<(i64, String)> = sqlx::query_as("SELECT id , password_hash FROM users WHERE email = ?")
        .bind(&payload.email)
        .fetch_optional(&s.db)
        .await?;
    println!("#exists");
    println!("{:?}", exists);
    if exists.is_none() {
        return Err(bad("error , user is NONE"));
    }  
    let db_pw = exists.unwrap().1;
    println!("db_pw={}", &db_pw);
    let pw = payload.password.clone();
    let phc = "".to_string();
    let phc = db_pw.clone();
    println!("phc: {}", phc);

    let ok = mod_auth::verify_password(&pw, &phc).expect("error , veryfy password");
    println!("password ok? {}", ok);    
    if ok == false {
        return Err(bad("error , passwd = NG"));
    }
    Ok(Json(json!({ "ret": 0 })))
}


mod anyhow_free {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
}

// ---------- 登録 ----------
#[derive(Deserialize)]
struct UsernameReq {
    username: String,
}

async fn register_start(
    State(s): State<AppState>,
    Json(req): Json<UsernameReq>,
) -> ApiResult<Json<Value>> {
    let username = req.username.trim().to_string();
    if username.is_empty() || username.chars().count() > 64 {
        return Err(bad("ユーザー名は1〜64文字で入力してください"));
    }
    let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM passkey_users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&s.db)
        .await?;
    if exists.is_some() {
        return Err(AppError(StatusCode::CONFLICT, "そのユーザー名は使用済みです".into()));
    }

    let user_id = Uuid::new_v4();
    let (ccr, state) = s
        .webauthn
        .start_passkey_registration(user_id, &username, &username, None)?;

    let challenge_id = Uuid::new_v4();
    s.reg
        .lock()
        .await
        .insert(challenge_id, PendingReg { user_id, username, state });

    Ok(Json(json!({ "challenge_id": challenge_id, "options": ccr })))
}
#[derive(Debug, Deserialize)]
struct RegFinishReq {
    challenge_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

async fn register_finish(
    State(s): State<AppState>,
    Json(req): Json<RegFinishReq>,
) -> ApiResult<Json<Value>> {
    let pending = s
        .reg
        .lock()
        .await
        .remove(&req.challenge_id)
        .ok_or_else(|| bad("チャレンジが無効または期限切れです"))?;
    println!("#req");
    println!("{:?}", req);
    //println!("{:?}", exists);

    let passkey = s
        .webauthn
        .finish_passkey_registration(&req.credential, &pending.state)
        .map_err(|e| {
            eprintln!("register verify failed: {e}");
            bad("パスキーの検証に失敗しました")
        })?;

    let mut tx = s.db.begin().await?;
    sqlx::query("INSERT INTO passkey_users (id, username) VALUES (?, ?)")
        .bind(pending.user_id.to_string())
        .bind(&pending.username)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO passkeys (user_id, passkey) VALUES (?, ?)")
        .bind(pending.user_id.to_string())
        .bind(serde_json::to_string(&passkey)?)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(json!({ "ok": true })))
}

// ---------- ログイン ----------
async fn login_start(
    State(s): State<AppState>,
    Json(req): Json<UsernameReq>,
) -> ApiResult<Json<Value>> {
    let fail = || bad("認証を開始できません");
    let user: Option<(String,)> = sqlx::query_as("SELECT id FROM passkey_users WHERE username = ?")
        .bind(req.username.trim())
        .fetch_optional(&s.db)
        .await?;
    let (user_id,) = user.ok_or_else(fail)?;
    println!("username={}", req.username);
    println!("user_id={}", &user_id);

    let rows: Vec<(String,)> = sqlx::query_as("SELECT passkey FROM passkeys WHERE user_id = ?")
        .bind(&user_id)
        .fetch_all(&s.db)
        .await?;
    let passkeys = rows
        .iter()
        .map(|(j,)| serde_json::from_str::<Passkey>(j))
        .collect::<Result<Vec<_>, _>>()?;
    if passkeys.is_empty() {
        return Err(fail());
    }

    let (rcr, state) = s.webauthn.start_passkey_authentication(&passkeys)?;
    let challenge_id = Uuid::new_v4();
    s.auth
        .lock()
        .await
        .insert(challenge_id, PendingAuth { user_id, state });

    Ok(Json(json!({ "challenge_id": challenge_id, "options": rcr })))
}

#[derive(Deserialize)]
struct LoginFinishReq {
    challenge_id: Uuid,
    credential: PublicKeyCredential,
}

async fn login_finish(
    State(s): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginFinishReq>,
) -> ApiResult<(CookieJar, Json<Value>)> {
    let pending = s
        .auth
        .lock()
        .await
        .remove(&req.challenge_id)
        .ok_or_else(|| bad("チャレンジが無効または期限切れです"))?;

    let result = s
        .webauthn
        .finish_passkey_authentication(&req.credential, &pending.state)
        .map_err(|e| {
            eprintln!("auth verify failed: {e}");
            AppError(StatusCode::UNAUTHORIZED, "認証に失敗しました".into())
        })?;

    // 署名カウンタ等を更新して保存(クローン検知のため)
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, passkey FROM passkeys WHERE user_id = ?")
            .bind(&pending.user_id)
            .fetch_all(&s.db)
            .await?;
    for (id, json) in rows {
        let mut pk: Passkey = serde_json::from_str(&json)?;
        if pk.update_credential(&result) == Some(true) {
            sqlx::query("UPDATE passkeys SET passkey = ? WHERE id = ?")
                .bind(serde_json::to_string(&pk)?)
                .bind(id)
                .execute(&s.db)
                .await?;
        }
    }

    // セッション発行
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    sqlx::query("INSERT INTO sessions (token, user_id) VALUES (?, ?)")
        .bind(&token)
        .bind(&pending.user_id)
        .execute(&s.db)
        .await?;

    let cookie = Cookie::build(("session", token))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        // .secure(true) // HTTPS 運用時は必ず有効化
        .build();

    Ok((jar.add(cookie), Json(json!({ "ok": true }))))
}

// ---------- セッション ----------
async fn me(State(s): State<AppState>, jar: CookieJar) -> ApiResult<Json<Value>> {
    let token = jar
        .get("session")
        .map(|c| c.value().to_string())
        .ok_or(AppError(StatusCode::UNAUTHORIZED, "未ログイン".into()))?;

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT u.username FROM sessions s JOIN passkey_users u ON u.id = s.user_id
         WHERE s.token = ? AND s.created_at > CAST(strftime('%s','now') AS INTEGER) - ?",
    )
    .bind(token)
    .bind(SESSION_TTL_SECS)
    .fetch_optional(&s.db)
    .await?;

    match row {
        Some((username,)) => Ok(Json(json!({ "username": username }))),
        None => Err(AppError(StatusCode::UNAUTHORIZED, "未ログイン".into())),
    }
}

async fn logout(State(s): State<AppState>, jar: CookieJar) -> ApiResult<(CookieJar, Json<Value>)> {
    if let Some(c) = jar.get("session") {
        sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(c.value().to_string())
            .execute(&s.db)
            .await?;
    }
    let jar = jar.remove(Cookie::build("session").path("/").build());
    Ok((jar, Json(json!({ "ok": true }))))
}
