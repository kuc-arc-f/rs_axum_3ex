use std::{env, str::FromStr, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use rand::{Rng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use subtle::ConstantTimeEq;

const OTP_TTL_SECS: i64 = 10 * 60; // OTP 有効期限 10 分
const OTP_RESEND_INTERVAL: i64 = 60; // 再送間隔 60 秒
const OTP_MAX_ATTEMPTS: i64 = 5; // 試行上限
const SESSION_TTL_SECS: i64 = 7 * 24 * 3600; // セッション 7 日
const SESSION_COOKIE: &str = "session";

struct AppState {
    db: SqlitePool,
    mailer: Option<AsyncSmtpTransport<Tokio1Executor>>,
    mail_from: String,
    pepper: String,
    cookie_secure: bool,
}
type Shared = Arc<AppState>;

// ---------- エラー型 ----------
struct AppError(StatusCode, String);

impl AppError {
    fn new(code: StatusCode, msg: &str) -> Self {
        Self(code, msg.to_string())
    }
}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("db error: {e}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "内部エラー")
    }
}
type AppResult<T> = Result<T, AppError>;

// ---------- ユーティリティ ----------
fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}
fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}
fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
fn otp_hash(state: &AppState, user_id: i64, code: &str) -> String {
    sha256_hex(&format!("{}:{}:{}", state.pepper, user_id, code))
}
fn normalize_email(e: &str) -> String {
    e.trim().to_lowercase()
}
fn valid_email(e: &str) -> bool {
    e.len() <= 254 && e.contains('@') && !e.starts_with('@') && !e.ends_with('@') && !e.contains(' ')
}

async fn hash_password(pw: String) -> AppResult<String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default().hash_password(pw.as_bytes(), &salt).map(|h| h.to_string())
    })
    .await
    .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "内部エラー"))?
    .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "内部エラー"))
}

async fn verify_password(pw: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

// ---------- OTP 送信 ----------
async fn send_otp(state: &AppState, user_id: i64, email: &str) -> AppResult<()> {
    // 再送レート制限
    let last: Option<(i64,)> =
        sqlx::query_as("SELECT created_at FROM otps WHERE user_id = ? ORDER BY id DESC LIMIT 1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    if let Some((t,)) = last {
        if now() - t < OTP_RESEND_INTERVAL {
            return Err(AppError::new(StatusCode::TOO_MANY_REQUESTS, "しばらく待ってから再送してください"));
        }
    }

    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
    sqlx::query("DELETE FROM otps WHERE user_id = ?").bind(user_id).execute(&state.db).await?;
    sqlx::query("INSERT INTO otps (user_id, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)")
        .bind(user_id)
        .bind(otp_hash(state, user_id, &code))
        .bind(now() + OTP_TTL_SECS)
        .bind(now())
        .execute(&state.db)
        .await?;

    match &state.mailer {
        Some(mailer) => {
            let msg = Message::builder()
                .from(state.mail_from.parse().map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "メール設定エラー"))?)
                .to(email.parse().map_err(|_| AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"))?)
                .subject("【確認コード】メールアドレスの認証")
                .body(format!("確認コード: {code}\n\n有効期限は {} 分です。心当たりがない場合は無視してください。", OTP_TTL_SECS / 60))
                .map_err(|_| AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "メール作成エラー"))?;
            mailer.send(msg).await.map_err(|e| {
                tracing::error!("smtp error: {e}");
                AppError::new(StatusCode::BAD_GATEWAY, "メール送信に失敗しました")
            })?;
        }
        None => tracing::warn!("[DEV] OTP for {email}: {code}"), // 開発モード
    }
    Ok(())
}

// ---------- ハンドラ ----------
#[derive(Deserialize)]
struct RegisterReq { email: String, password: String }

async fn send_code(
    State(s): State<Shared>, Json(req): Json<RegisterReq>
) -> AppResult<Json<Value>> {
    let email = normalize_email(&req.email);
    if !valid_email(&email) {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    //if req.password.len() < 8 || req.password.len() > 128 {
    //    return Err(AppError::new(StatusCode::BAD_REQUEST, "パスワードは 8〜128 文字にしてください"));
    //}

    let existing: Option<(i64, i64)> = sqlx::query_as("SELECT id, email_verified FROM users WHERE email = ?")
        .bind(&email).fetch_optional(&s.db).await?;
    println!("#existing");
    println!("{:?}", existing);
    let user_id = existing.unwrap().0;
    println!("user_id={}", user_id);
    send_otp(&s, user_id, &email).await?;
    let msg = json!({ "message": "確認コードを送信しました。メールを確認してください。" });
    Ok(Json(msg))
}
async fn user_register(
    State(s): State<Shared>, Json(req): Json<RegisterReq>
) -> AppResult<Json<Value>> {
    let email = normalize_email(&req.email);
    if !valid_email(&email) {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    if req.password.len() < 8 || req.password.len() > 128 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "パスワードは 8〜128 文字にしてください"));
    }

    let existing: Option<(i64, i64)> = sqlx::query_as("SELECT id, email_verified FROM users WHERE email = ?")
        .bind(&email).fetch_optional(&s.db).await?;

    let msg = json!({ "message": "OK , user add" });
    match existing {
        // 認証済み: アカウント存在を漏らさないため同じ応答を返す
        Some((_, 1)) => return Ok(Json(msg)),
        // 未認証: パスワードを更新して OTP 再送
        Some((id, _)) => {
            let hash = hash_password(req.password).await?;
            sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?").bind(hash).bind(id).execute(&s.db).await?;
        }
        None => {
            let hash = hash_password(req.password).await?;
            let id = sqlx::query("INSERT INTO users (email, password_hash, email_verified, created_at) VALUES (?, ?, 0, ?)")
                .bind(&email).bind(hash).bind(now())
                .execute(&s.db).await?.last_insert_rowid();
        }
    }
    Ok(Json(msg))
}
async fn register(State(s): State<Shared>, Json(req): Json<RegisterReq>) -> AppResult<Json<Value>> {
    let email = normalize_email(&req.email);
    if !valid_email(&email) {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    if req.password.len() < 8 || req.password.len() > 128 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "パスワードは 8〜128 文字にしてください"));
    }

    let existing: Option<(i64, i64)> = sqlx::query_as("SELECT id, email_verified FROM users WHERE email = ?")
        .bind(&email).fetch_optional(&s.db).await?;

    let msg = json!({ "message": "確認コードを送信しました。メールを確認してください。" });
    match existing {
        // 認証済み: アカウント存在を漏らさないため同じ応答を返す
        Some((_, 1)) => return Ok(Json(msg)),
        // 未認証: パスワードを更新して OTP 再送
        Some((id, _)) => {
            let hash = hash_password(req.password).await?;
            sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?").bind(hash).bind(id).execute(&s.db).await?;
            send_otp(&s, id, &email).await?;
        }
        None => {
            let hash = hash_password(req.password).await?;
            let id = sqlx::query("INSERT INTO users (email, password_hash, email_verified, created_at) VALUES (?, ?, 0, ?)")
                .bind(&email).bind(hash).bind(now())
                .execute(&s.db).await?.last_insert_rowid();
            send_otp(&s, id, &email).await?;
        }
    }
    Ok(Json(msg))
}

async fn user_get_id(
    State(s): State<Shared>, Json(req): Json<UserEmailReq>
) -> AppResult<Json<Value>> {
    //let email = normalize_email(&req.email);
    let unauth = || AppError::new(StatusCode::UNAUTHORIZED, "ログインが必要です");
    let bad = || AppError::new(StatusCode::UNAUTHORIZED, "メールアドレスまたはパスワードが違います");

    let userDat: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, email FROM users WHERE id = ?")
        .bind(&req.user_id).fetch_optional(&s.db).await?;
            
    if userDat == None {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    println!("userDat={:?}" , userDat);
    let email_str = userDat.unwrap().1;
    println!("email_str={}" , email_str);

    Ok(Json(json!({ "uid": &req.user_id, "email": email_str })))
}

async fn user_get_name(
    State(s): State<Shared>, Json(req): Json<UserMeReq>
) -> AppResult<Json<Value>> {
    let unauth = || AppError::new(StatusCode::UNAUTHORIZED, "ログインが必要です");
    let bad = || AppError::new(StatusCode::UNAUTHORIZED, "メールアドレスまたはパスワードが違います");

    if !valid_email(&req.email) {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    let userDat: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, email FROM users WHERE email = ?")
        .bind(&req.email).fetch_optional(&s.db).await?;
            
    if userDat == None {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    println!("userDat={:?}" , userDat);
    //let email_str = userDat.unwrap().0;
    //println!("email_str={}" , email_str);
    let user_id_val = userDat.unwrap().0;
    println!("user_id_val={}" , user_id_val);

    Ok(Json(json!({ "uid": user_id_val, "email": &req.email })))
}

async fn user_me(
    State(s): State<Shared>, Json(req): Json<UserMeReq>
) -> AppResult<Json<Value>> {
    let email = normalize_email(&req.email);
    let unauth = || AppError::new(StatusCode::UNAUTHORIZED, "ログインが必要です");
    let bad = || AppError::new(StatusCode::UNAUTHORIZED, "メールアドレスまたはパスワードが違います");

    if !valid_email(&email) {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    let userDat: Option<(i64, i64)> = sqlx::query_as("SELECT id, email_verified FROM users WHERE email = ?")
        .bind(&email).fetch_optional(&s.db).await?;
            
    if userDat == None {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    println!("userDat={:?}" , userDat);
    let user_id = userDat.unwrap().0;
    println!("user_id={}" , user_id);

    let user: Option<(i64, String)> = sqlx::query_as(
        "SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.user_id = ? AND s.expires_at > ?",
    )
    .bind(user_id)
    .bind(now())
    .fetch_optional(&s.db).await?;
    println!("user={:?}" , user);
    if user == None {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "error, sessions =NONE"));
    }    
    let user_uid = user.unwrap().0;
    println!("user_uid={:?}" , user_uid);

    Ok(Json(json!({ "uid": user_id, "email": email })))
}

async fn user_login(
    State(s): State<Shared>, Json(req): Json<LoginReq>
) -> AppResult<Json<Value>> {
    println!("#req");
    println!("{:?}", &req);
    let email = normalize_email(&req.email);
    let bad = || AppError::new(StatusCode::UNAUTHORIZED, "メールアドレスまたはパスワードが違います");

    if !valid_email(&email) {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    if req.password.len() < 8 || req.password.len() > 128 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "パスワードは 8〜128 文字にしてください"));
    }
    let user: Option<(i64, String, i64)> =
        sqlx::query_as("SELECT id, password_hash, email_verified FROM users WHERE email = ?")
            .bind(&email).fetch_optional(&s.db).await?;

    // ユーザー不在でも argon2 を 1 回実行してタイミング差を減らす
    let (uid, hash, verified) = match user {
        Some(u) => u,
        None => {
            let _ = hash_password(req.password).await;
            return Err(bad());
        }
    };
    println!("uid={}", uid);
    println!("hash={}", hash);
    if !verify_password(req.password, hash).await {
        println!("err, verify_password = FALSE");
        return Err(bad());
    }
    //if verified != 1 {
    //    return Err(AppError::new(StatusCode::FORBIDDEN, "メール認証が完了していません"));
    //}
    /*
    sqlx::query("DELETE FROM sessions WHERE user_id= ?")
        .bind(uid)
        .execute(&s.db).await?;

    let token = random_token();
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(sha256_hex(&token)).bind(uid).bind(now() + SESSION_TTL_SECS)
        .execute(&s.db).await?;    
    */
    let msg = json!({ "message": "ログインしました" });
    Ok(Json(msg))
}

#[derive(Deserialize)]
struct VerifyReq { email: String, code: String }

async fn verify_email(State(s): State<Shared>, Json(req): Json<VerifyReq>) -> AppResult<Json<Value>> {
    let invalid = || AppError::new(StatusCode::BAD_REQUEST, "コードが無効または期限切れです");
    let email = normalize_email(&req.email);

    let (uid,): (i64,) = sqlx::query_as("SELECT id FROM users WHERE email = ?")
        .bind(&email).fetch_optional(&s.db).await?.ok_or_else(invalid)?;

    let (otp_id, code_hash, expires_at, attempts): (i64, String, i64, i64) = sqlx::query_as(
        "SELECT id, code_hash, expires_at, attempts FROM otps WHERE user_id = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(uid).fetch_optional(&s.db).await?.ok_or_else(invalid)?;

    if expires_at < now() || attempts >= OTP_MAX_ATTEMPTS {
        sqlx::query("DELETE FROM otps WHERE id = ?").bind(otp_id).execute(&s.db).await?;
        return Err(invalid());
    }

    let ok: bool = otp_hash(&s, uid, req.code.trim()).as_bytes().ct_eq(code_hash.as_bytes()).into();
    if !ok {
        sqlx::query("UPDATE otps SET attempts = attempts + 1 WHERE id = ?").bind(otp_id).execute(&s.db).await?;
        return Err(invalid());
    }

    sqlx::query("UPDATE users SET email_verified = 1 WHERE id = ?").bind(uid).execute(&s.db).await?;
    sqlx::query("DELETE FROM otps WHERE user_id = ?").bind(uid).execute(&s.db).await?;
    Ok(Json(json!({ "message": "メール認証が完了しました。ログインできます。" })))
}

#[derive(Deserialize)]
struct ResendReq { email: String }

async fn resend_otp(State(s): State<Shared>, Json(req): Json<ResendReq>) -> AppResult<Json<Value>> {
    let email = normalize_email(&req.email);
    let user: Option<(i64, i64)> = sqlx::query_as("SELECT id, email_verified FROM users WHERE email = ?")
        .bind(&email).fetch_optional(&s.db).await?;
    if let Some((id, 0)) = user {
        send_otp(&s, id, &email).await?;
    }
    // 存在有無を漏らさない
    Ok(Json(json!({ "message": "該当する場合、確認コードを再送しました。" })))
}

#[derive(Debug, Deserialize)]
struct LoginReq { email: String, password: String }

#[derive(Debug, Deserialize)]
struct UserMeReq { email: String }

#[derive(Debug, Deserialize)]
struct UserEmailReq { user_id: i64 }

async fn login(
    State(s): State<Shared>, jar: CookieJar, Json(req): Json<LoginReq>
) -> AppResult<(CookieJar, Json<Value>)> {
    let email = normalize_email(&req.email);
    let bad = || AppError::new(StatusCode::UNAUTHORIZED, "メールアドレスまたはパスワードが違います");

    let user: Option<(i64, String, i64)> =
        sqlx::query_as("SELECT id, password_hash, email_verified FROM users WHERE email = ?")
            .bind(&email).fetch_optional(&s.db).await?;

    // ユーザー不在でも argon2 を 1 回実行してタイミング差を減らす
    let (uid, hash, verified) = match user {
        Some(u) => u,
        None => {
            let _ = hash_password(req.password).await;
            return Err(bad());
        }
    };
    println!("uid={}", uid);
    if !verify_password(req.password, hash).await {
        return Err(bad());
    }
    if verified != 1 {
        return Err(AppError::new(StatusCode::FORBIDDEN, "メール認証が完了していません"));
    }

    let token = random_token();
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(sha256_hex(&token)).bind(uid).bind(now() + SESSION_TTL_SECS)
        .execute(&s.db).await?;

    let cookie = Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .secure(s.cookie_secure)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::seconds(SESSION_TTL_SECS))
        .build();
    Ok((jar.add(cookie), Json(json!({ "message": "ログインしました" }))))
}

async fn current_user(s: &AppState, jar: &CookieJar) -> AppResult<(i64, String)> {
    let unauth = || AppError::new(StatusCode::UNAUTHORIZED, "ログインが必要です");
    let token = jar.get(SESSION_COOKIE).ok_or_else(unauth)?.value().to_string();
    sqlx::query_as::<_, (i64, String)>(
        "SELECT u.id, u.email FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > ?",
    )
    .bind(sha256_hex(&token)).bind(now())
    .fetch_optional(&s.db).await?.ok_or_else(unauth)
}

async fn me(State(s): State<Shared>, jar: CookieJar) -> AppResult<Json<Value>> {
    let (id, email) = current_user(&s, &jar).await?;
    Ok(Json(json!({ "id": id, "email": email })))
}

async fn logout(State(s): State<Shared>, jar: CookieJar) -> AppResult<(CookieJar, Json<Value>)> {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?").bind(sha256_hex(c.value())).execute(&s.db).await?;
    }
    let removal = Cookie::build((SESSION_COOKIE, "")).path("/").build();
    Ok((jar.remove(removal), Json(json!({ "message": "ログアウトしました" }))))
}

// ---------- 起動 ----------
async fn init_db(url: &str) -> Result<SqlitePool, Box<dyn std::error::Error>> {
    let opts = SqliteConnectOptions::from_str(url)?.create_if_missing(true).foreign_keys(true);
    let pool = SqlitePoolOptions::new().max_connections(5).connect_with(opts).await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email_verified INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL)",
    ] {
        sqlx::query(stmt).execute(&pool).await?;
    }
    Ok(pool)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().init();

    let db = init_db(&env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://app.db".into())).await?;

    let mailer = match env::var("SMTP_HOST") {
        Ok(host) => {
            let creds = Credentials::new(env::var("SMTP_USER")?, env::var("SMTP_PASS")?);
            Some(AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)?.credentials(creds).build())
        }
        Err(_) => {
            tracing::warn!("SMTP_HOST 未設定: OTP はログに出力されます (開発モード)");
            None
        }
    };

    let state = Arc::new(AppState {
        db,
        mailer,
        mail_from: env::var("SMTP_FROM").unwrap_or_else(|_| "App <no-reply@localhost>".into()),
        pepper: env::var("OTP_PEPPER").expect("OTP_PEPPER を設定してください"),
        cookie_secure: env::var("COOKIE_SECURE").map(|v| v == "true").unwrap_or(false),
    });

    let app = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/verify-email", post(verify_email))
        .route("/auth/resend-otp", post(resend_otp))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/user_register", post(user_register))        
        .route("/auth/user_login", post(user_login))
        .route("/auth/send_code", post(send_code))
        .route("/auth/user_me", post(user_me))
        .route("/auth/user_get_name", post(user_get_name))
        .route("/auth/user_get_id", post(user_get_id))
        .route("/me", get(me))
        .with_state(state);

    let addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    tracing::info!("listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(&addr).await?, app).await?;
    Ok(())
}
