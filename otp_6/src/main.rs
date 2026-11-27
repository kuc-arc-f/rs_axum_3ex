//! Axum + SQLite + TOTP(Google Authenticator 等) ログインのサンプル
//!
//! フロー:
//!   /register → (QR 表示 /setup でアプリに登録・初回コード確認)
//!   /login (ID+パスワード) → /otp (6桁コード) → /dashboard
use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{sqlite::SqliteConnectOptions, SqlitePool};
use std::str::FromStr;
use totp_rs::{Algorithm, Secret, TOTP};

mod models;

const ISSUER: &str = "MyWebApp"; // 認証アプリに表示されるサービス名
const COOKIE: &str = "sid";
const SESSION_TTL_SEC: i64 = 60 * 60 * 8;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
}
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
        //tracing::error!("db error: {e}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "内部エラー")
    }
}
type AppResult<T> = Result<T, AppError>;

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
// ---------- 起動 ----------
#[tokio::main]
async fn main() {
    let opts = SqliteConnectOptions::from_str("sqlite://app.db")
        .unwrap()
        .create_if_missing(true);
    let db = SqlitePool::connect_with(opts).await.unwrap();
    init_db(&db).await;

    let app = Router::new()
        .route("/", get(|| async { Redirect::to("/login") }))
        .route("/register", get(register_form).post(register))
        .route("/setup", get(setup_form).post(setup_verify))
        .route("/login", get(login_form).post(login))
        .route("/otp", get(otp_form).post(otp_verify))
        .route("/dashboard", get(dashboard))
        .route("/logout", post(logout))
        .route("/api/user_register", post(user_register))
        .route("/api/user_login", post(user_login))
        .route("/api/user_setup_finish", post(user_setup_finish))
        .route("/api/user_setup_start", post(user_setup_start))
        .route("/api/user_get_name", post(user_get_name))
        //.route("/api/user_get_id", post(user_get_id))
        .with_state(AppState { db });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn init_db(db: &SqlitePool) {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email_verified INTEGER NOT NULL DEFAULT 0,
            totp_secret TEXT NOT NULL,          -- base32
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            last_totp_step INTEGER NOT NULL DEFAULT 0  -- コード使い回し防止
        )",
    )
    .execute(db)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            state TEXT NOT NULL,               -- 'setup' | 'otp' | 'ok'
            expires_at INTEGER NOT NULL
        )",
    )
    .execute(db)
    .await
    .unwrap();
}

// ---------- ユーティリティ ----------
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:380px;margin:3rem auto;padding:0 1rem}}
input,button{{width:100%;padding:.6rem;margin:.3rem 0;box-sizing:border-box;font-size:1rem}}
.err{{color:#c00}} code{{word-break:break-all}}
</style></head><body><h1>{title}</h1>{body}</body></html>"#
    ))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn build_totp(secret_b32: &str, username: &str) -> TOTP {
    let bytes = Secret::Encoded(secret_b32.to_string()).to_bytes().unwrap();
    // SHA1 / 6桁 / skew 1 (前後30秒許容) / 30秒周期 … Google Authenticator 互換
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, Some(ISSUER.to_string()), username.to_string())
        .unwrap()
}

async fn new_session(db: &SqlitePool, jar: CookieJar, user_id: i64, state: &str) -> CookieJar {
    let token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(48).map(char::from).collect();
    sqlx::query("INSERT INTO sessions(token,user_id,state,expires_at) VALUES(?,?,?,?)")
        .bind(&token)
        .bind(user_id)
        .bind(state)
        .bind(now() + SESSION_TTL_SEC)
        .execute(db)
        .await
        .unwrap();
    let c = Cookie::build((COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        // .secure(true) // HTTPS 運用時は有効化
        .build();
    jar.add(c)
}

/// 現在のセッションが要求 state か確認して user_id を返す
async fn session_user(db: &SqlitePool, jar: &CookieJar, want: &str) -> Option<i64> {
    let token = jar.get(COOKIE)?.value().to_string();
    let row: Option<(i64, String, i64)> =
        sqlx::query_as("SELECT user_id,state,expires_at FROM sessions WHERE token=?")
            .bind(token)
            .fetch_optional(db)
            .await
            .ok()?;
    let (uid, state, exp) = row?;
    (state == want && exp > now()).then_some(uid)
}

async fn set_state(db: &SqlitePool, jar: &CookieJar, state: &str) {
    if let Some(c) = jar.get(COOKIE) {
        sqlx::query("UPDATE sessions SET state=? WHERE token=?")
            .bind(state)
            .bind(c.value())
            .execute(db)
            .await
            .ok();
    }
}

/// コード検証 + 同一 30 秒ステップの再利用を拒否
async fn verify_code(db: &SqlitePool, uid: i64, code: &str) -> bool {
    let (username, secret, last): (String, String, i64) =
        sqlx::query_as("SELECT username,totp_secret,last_totp_step FROM users WHERE id=?")
            .bind(uid)
            .fetch_one(db)
            .await
            .unwrap();
    let totp = build_totp(&secret, &username);
    let code = code.trim();
    if !totp.check_current(code).unwrap_or(false) {
        return false;
    }
    let step = now() / 30;
    if step <= last {
        return false; // 同じステップで使用済み
    }
    sqlx::query("UPDATE users SET last_totp_step=? WHERE id=?")
        .bind(step)
        .bind(uid)
        .execute(db)
        .await
        .unwrap();
    true
}

// ---------- 登録 ----------
async fn register_form() -> Html<String> {
    page("新規登録", r#"<form method="post">
<input name="username" placeholder="ユーザー名" required>
<input name="password" type="password" placeholder="パスワード (8文字以上)" minlength="8" required>
<button>登録</button></form><p><a href="/login">ログインへ</a></p>"#)
}

#[derive(Deserialize)]
struct Cred {
    username: String,
    password: String,
}

async fn user_setup_finish(
    State(s): State<AppState>, Json(req): Json<models::SetupReq>
) -> AppResult<Json<Value>> {
    // uid , code
    println!("#req");
    println!("{:?}", &req);
    let user_id : &i64 = &req.user_id;
    let bad = || AppError::new(StatusCode::UNAUTHORIZED, "メールアドレスまたはパスワードが違います");
    println!( "user_id={}", user_id);
    if verify_code(&s.db, *user_id, &req.code).await {
        sqlx::query("UPDATE users SET totp_enabled=1 WHERE id=?")
        .bind(user_id).execute(&s.db).await.unwrap();
    } else {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "コードが正しくありません"));
    }    
    let msg = json!({ "message": "ログインしました" });
    Ok(Json(msg))
}

async fn user_get_name(
    State(s): State<AppState>, 
    Json(req): Json<models::UserMeReq>
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
    let user_id_val = userDat.unwrap().0;
    println!("user_id_val={}" , user_id_val);

    Ok(Json(json!({ "uid": user_id_val, "email": &req.email })))
}

async fn user_setup_start(
    State(s): State<AppState>, Json(req): Json<models::UserEmailReq>
) -> AppResult<Json<Value>> {
    println!("#req");
    println!("{:?}", &req);

    let uid = &req.user_id;
    let bad = || AppError::new(StatusCode::UNAUTHORIZED, "メールアドレスまたはパスワードが違います");
    let (username, secret): (String, String) =
        sqlx::query_as("SELECT username,totp_secret FROM users WHERE id=?")
            .bind(uid)
            .fetch_one(&s.db)
            .await
            .unwrap();    
    let totp = build_totp(&secret, &username);
    let qr_b64 = totp.get_qr_base64().unwrap(); // PNG (base64) ← qrcode クレートで生成
    println!("#qr_b64");
    println!("{:?}", &qr_b64);

    let msg = json!({ "ret": 1 , "message": "" , "qr_b64": &qr_b64});
    Ok(Json(msg))
}

async fn user_get_id(
    State(s): State<AppState>, Json(req): Json<models::UserEmailReq>
) -> AppResult<Json<Value>> {
    println!("#req");
    println!("{:?}", &req);
    let bad = || AppError::new(StatusCode::UNAUTHORIZED, "メールアドレスまたはパスワードが違います");
    let msg = json!({ "message": "ログインしました" });
    Ok(Json(msg))
}

async fn user_login(
    State(s): State<AppState>, Json(req): Json<models::LoginReq>
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
    let msg = json!({ "message": "ログインしました" });
    Ok(Json(msg))
}

async fn user_register(
    State(s): State<AppState>, 
    Json(req): Json<models::RegisterReq>
) -> AppResult<Json<Value>> {
    println!("#req");
    println!("{:?}", &req);
    let email = normalize_email(&req.email);
    if !valid_email(&email) {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "メールアドレスが不正です"));
    }
    if req.password.len() < 8 || req.password.len() > 128 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "パスワードは 8〜128 文字にしてください"));
    }

    let existing: Option<(i64, i64)> = sqlx::query_as("SELECT id, email_verified FROM users WHERE email = ?")
        .bind(&email).fetch_optional(&s.db).await?;
    println!("#existing");
    println!("{:?}", &existing);

    let msg = json!({ "message": "OK , user add" });
    let secret = Secret::generate_secret().to_encoded().to_string(); // base32
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
            let username = &email;
            println!("email={}", &email);
            println!("username={}", &username);
            //let id = sqlx::query("INSERT INTO users (email, password_hash, email_verified, created_at) VALUES (?, ?, 0, ?)")
            //    .bind(&email).bind(&hash).bind(now())
            //    .execute(&s.db).await?.last_insert_rowid();
            let res = sqlx::query("INSERT INTO users(email, username,password_hash,totp_secret) VALUES(?,?,?,?)")
                .bind(&email)
                .bind(&username)
                .bind(&hash)
                .bind(secret)
                .execute(&s.db)
                .await;                
        }
    }
    Ok(Json(msg))
}

async fn register(
    State(s): State<AppState>, jar: CookieJar, Form(f): Form<Cred>) -> Response 
{
    if f.username.trim().is_empty() || f.password.len() < 8 {
        return page("新規登録", r#"<p class="err">入力が不正です</p><a href="/register">戻る</a>"#).into_response();
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(f.password.as_bytes(), &salt).unwrap().to_string();
    let secret = Secret::generate_secret().to_encoded().to_string(); // base32

    let res = sqlx::query("INSERT INTO users(username,password_hash,totp_secret) VALUES(?,?,?)")
        .bind(f.username.trim())
        .bind(hash)
        .bind(secret)
        .execute(&s.db)
        .await;
    match res {
        Ok(r) => {
            let jar = new_session(&s.db, jar, r.last_insert_rowid(), "setup").await;
            (jar, Redirect::to("/setup")).into_response()
        }
        Err(_) => page("新規登録", r#"<p class="err">そのユーザー名は使用済みです</p><a href="/register">戻る</a>"#).into_response(),
    }
}

// ---------- 2FA セットアップ (QR 表示) ----------
async fn setup_form(State(s): State<AppState>, jar: CookieJar) -> Response {
    let Some(uid) = session_user(&s.db, &jar, "setup").await else {
        return Redirect::to("/login").into_response();
    };
    render_setup(&s.db, uid, "").await.into_response()
}

async fn render_setup(db: &SqlitePool, uid: i64, msg: &str) -> Html<String> {
    let (username, secret): (String, String) =
        sqlx::query_as("SELECT username,totp_secret FROM users WHERE id=?")
            .bind(uid)
            .fetch_one(db)
            .await
            .unwrap();
    let totp = build_totp(&secret, &username);
    let qr_b64 = totp.get_qr_base64().unwrap(); // PNG (base64) ← qrcode クレートで生成
    page("2段階認証の設定", &format!(
        r#"<p>Google Authenticator 等で QR を読み取り、表示された6桁コードを入力してください。</p>
<img alt="QR" src="data:image/png;base64,{qr_b64}" style="width:100%;image-rendering:pixelated">
<p>読み取れない場合の手動キー:<br><code>{secret}</code></p>
<p class="err">{msg}</p>
<form method="post"><input name="code" inputmode="numeric" pattern="[0-9]{{6}}" maxlength="6" placeholder="123456" required>
<button>確認して有効化</button></form>"#,
        msg = esc(msg)
    ))
}

#[derive(Deserialize)]
struct CodeForm {
    code: String,
}

async fn setup_verify(State(s): State<AppState>, jar: CookieJar, Form(f): Form<CodeForm>) -> Response {
    let Some(uid) = session_user(&s.db, &jar, "setup").await else {
        return Redirect::to("/login").into_response();
    };
    if verify_code(&s.db, uid, &f.code).await {
        sqlx::query("UPDATE users SET totp_enabled=1 WHERE id=?").bind(uid).execute(&s.db).await.unwrap();
        set_state(&s.db, &jar, "ok").await;
        Redirect::to("/dashboard").into_response()
    } else {
        render_setup(&s.db, uid, "コードが正しくありません").await.into_response()
    }
}

// ---------- ログイン ----------
fn login_page(msg: &str) -> Html<String> {
    page("ログイン", &format!(r#"<p class="err">{}</p><form method="post">
<input name="username" placeholder="ユーザー名" required>
<input name="password" type="password" placeholder="パスワード" required>
<button>次へ</button></form><p><a href="/register">新規登録</a></p>"#, esc(msg)))
}

async fn login_form() -> Html<String> {
    login_page("")
}

async fn login(State(s): State<AppState>, jar: CookieJar, Form(f): Form<Cred>) -> Response {
    let row: Option<(i64, String, i64)> =
        sqlx::query_as("SELECT id,password_hash,totp_enabled FROM users WHERE username=?")
            .bind(f.username.trim())
            .fetch_optional(&s.db)
            .await
            .unwrap();

    // ユーザー不在でもハッシュ検証時間を揃える(簡易タイミング対策)
    let dummy = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFy";
    let (hash, uid, enabled) = match &row {
        Some((id, h, e)) => (h.as_str(), Some(*id), *e == 1),
        None => (dummy, None, false),
    };
    let ok = PasswordHash::new(hash)
        .map(|p| Argon2::default().verify_password(f.password.as_bytes(), &p).is_ok())
        .unwrap_or(false);

    match (ok, uid) {
        (true, Some(uid)) => {
            let state = if enabled { "otp" } else { "setup" };
            let jar = new_session(&s.db, jar, uid, state).await;
            let to = if enabled { "/otp" } else { "/setup" };
            (jar, Redirect::to(to)).into_response()
        }
        _ => (StatusCode::UNAUTHORIZED, login_page("ユーザー名またはパスワードが違います")).into_response(),
    }
}

// ---------- OTP 入力 ----------
fn otp_page(msg: &str) -> Html<String> {
    page("認証コード", &format!(r#"<p>認証アプリの6桁コードを入力</p><p class="err">{}</p>
<form method="post"><input name="code" inputmode="numeric" autocomplete="one-time-code"
pattern="[0-9]{{6}}" maxlength="6" autofocus required><button>ログイン</button></form>"#, esc(msg)))
}

async fn otp_form(State(s): State<AppState>, jar: CookieJar) -> Response {
    if session_user(&s.db, &jar, "otp").await.is_none() {
        return Redirect::to("/login").into_response();
    }
    otp_page("").into_response()
}

async fn otp_verify(State(s): State<AppState>, jar: CookieJar, Form(f): Form<CodeForm>) -> Response {
    let Some(uid) = session_user(&s.db, &jar, "otp").await else {
        return Redirect::to("/login").into_response();
    };
    if verify_code(&s.db, uid, &f.code).await {
        set_state(&s.db, &jar, "ok").await;
        Redirect::to("/dashboard").into_response()
    } else {
        // 本番では試行回数制限(レート制限/ロックアウト)を追加すること
        (StatusCode::UNAUTHORIZED, otp_page("コードが正しくありません")).into_response()
    }
}

// ---------- ログイン後 ----------
async fn dashboard(State(s): State<AppState>, jar: CookieJar) -> Response {
    let Some(uid) = session_user(&s.db, &jar, "ok").await else {
        return Redirect::to("/login").into_response();
    };
    let (name,): (String,) = sqlx::query_as("SELECT username FROM users WHERE id=?")
        .bind(uid).fetch_one(&s.db).await.unwrap();
    page("ダッシュボード", &format!(
        r#"<p>ようこそ、{} さん(2段階認証済み)</p><form method="post" action="/logout"><button>ログアウト</button></form>"#,
        esc(&name)
    )).into_response()
}

async fn logout(State(s): State<AppState>, jar: CookieJar) -> Response {
    if let Some(c) = jar.get(COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE token=?").bind(c.value()).execute(&s.db).await.ok();
    }
    (jar.remove(Cookie::build(COOKIE).path("/")), Redirect::to("/login")).into_response()
}
