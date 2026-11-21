//! パスキー（Windows Hello 等）の登録・ログインのハンドラ
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{
    AppState,
    error::{AppError, AppResult},
    session::{self, CurrentUser},
};

/// チャレンジの有効期限（秒）
const CHALLENGE_TTL_SECS: f64 = 300.0;

// ---------- リクエスト / レスポンス型 ----------

#[derive(Deserialize)]
pub struct RegisterStartReq {
    username: String,
    display_name: String,
}

#[derive(Deserialize)]
pub struct RegisterFinishReq {
    challenge_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub struct LoginStartReq {
    username: String,
}

#[derive(Deserialize)]
pub struct LoginFinishReq {
    challenge_id: Uuid,
    credential: PublicKeyCredential,
}

/// ブラウザに渡すオプション。challenge_id を finish 時に返してもらう
#[derive(Serialize)]
pub struct StartResp<T> {
    challenge_id: Uuid,
    options: T,
}

pub async fn user_login(
    State(st): State<AppState>,
    Json(req): Json<super::models::UserCreateReq>,
) -> AppResult<Json<super::models::UserRes>> {
    let mut user = super::models::UserRes {
        email: "".to_string(),
        password: "".to_string(),
    };   
    println!("#req"); 
    println!("{:?}", req); 
    let email = req.email.trim();
    if email.is_empty() {
        return Err(AppError::BadRequest(
            "error , email =NONE",
        ));        
    }
    let password = req.password.trim();
    if password.is_empty() {
        return Err(AppError::BadRequest(
            "error, password=NONE ",
        ));
    }
    let users: Vec<super::models::DbUser> = sqlx::query_as::<_, super::models::DbUser>(
        r#"
        SELECT email, password_hash
        FROM users
        WHERE email = $1
        "#
    )
    .bind(email)
    .fetch_all(&st.db)
    .await.unwrap();

    let mut user_count = 0;
    let mut db_pass = "".to_string();
    for user in users {
        db_pass = user.password_hash.clone();
        println!("email: {}", user.email);
        println!("password_hash: {}", db_pass);
        user_count += 1;
    }    
    println!("user_count={}", user_count);
    if user_count == 0 {
        println!("error , user_count == 0");
        return Err(AppError::BadRequest(
            "error , user_count == 0",
        ));        
    }
    let pw = password.clone();
    let phc = db_pass.clone();    
    let ok = super::mod_auth::verify_password(&pw, &db_pass).expect("error , veryfy password");
    println!("password ok? {}", ok);    
    if ok == false {
        return Err(AppError::BadRequest(
            "error , password=NG",
        ));        
    }    
    Ok(Json(
        user,
    ))
}
//
pub async fn user_create(
    State(st): State<AppState>,
    Json(req): Json<super::models::UserCreateReq>,
) -> AppResult<Json<super::models::UserRes>> {
    let mut user = super::models::UserRes {
        email: "".to_string(),
        password: "".to_string(),
    };   
    println!("#req"); 
    println!("{:?}", req); 
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM passkey_users WHERE username = $1)")
        .bind(&req.email)
        .fetch_one(&st.db)
        .await?;
    if exists {
        return Err(AppError::Conflict("そのユーザー名は既に使われています"));
    }
    let pw = &req.password.clone();
    let phc = super::mod_auth::hash_password(&pw).expect("error , hash_password");
    println!("phc: {}", phc);
    
    let result = sqlx::query(
        r#"
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id, email
        "#,
    )
    .bind(&req.email)
    .bind(phc)
    .execute(&st.db)
    .await.unwrap();    

    Ok(Json(
        user,
    ))
}

// ---------- 登録 ----------

/// POST /api/register/start
pub async fn register_start(
    State(st): State<AppState>,
    Json(req): Json<RegisterStartReq>,
) -> AppResult<Json<StartResp<CreationChallengeResponse>>> {
    let username = req.username.trim().to_string();
    let display_name = req.display_name.trim().to_string();
    if !valid_len(&username) || !valid_len(&display_name) {
        return Err(AppError::BadRequest(
            "ユーザー名と表示名は1〜64文字で入力してください",
        ));
    }

    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM passkey_users WHERE username = $1)")
        .bind(&username)
        .fetch_one(&st.db)
        .await?;
    if exists {
        return Err(AppError::Conflict("そのユーザー名は既に使われています"));
    }

    // まだ passkey_users に登録しない。finish 時にまとめて保存する
    let user_id = Uuid::new_v4();
    let (mut ccr, reg_state) =
        st.webauthn
            .start_passkey_registration(user_id, &username, &display_name, None)?;

    // Windows Hello（端末内蔵のプラットフォーム認証器）に限定する
    if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
        sel.authenticator_attachment = Some(AuthenticatorAttachment::Platform);
    }

    let challenge_id = save_challenge(
        &st.db,
        "registration",
        user_id,
        &username,
        Some(&display_name),
        serde_json::to_value(&reg_state)?,
    )
    .await?;

    Ok(Json(StartResp {
        challenge_id,
        options: ccr,
    }))
}

/// POST /api/register/finish
pub async fn register_finish(
    State(st): State<AppState>,
    Json(req): Json<RegisterFinishReq>,
) -> AppResult<Response> {
    let ch = take_challenge(&st.db, req.challenge_id, "registration").await?;
    let reg_state: PasskeyRegistration = serde_json::from_value(ch.state)?;

    // 署名・オリジン・RP ID などを検証して Passkey を得る
    let passkey = st
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)?;

    let display_name = ch.display_name.unwrap_or_else(|| ch.username.clone());

    let mut tx = st.db.begin().await?;
    sqlx::query("INSERT INTO passkey_users (id, username, display_name) VALUES ($1, $2, $3)")
        .bind(ch.user_id)
        .bind(&ch.username)
        .bind(&display_name)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?;
    sqlx::query("INSERT INTO passkeys (user_id, credential_id, passkey) VALUES ($1, $2, $3)")
        .bind(ch.user_id)
        .bind(passkey.cred_id().as_slice())
        .bind(serde_json::to_value(&passkey)?)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?;
    tx.commit().await?;

    // 登録直後にそのままログイン状態にする
    let user = CurrentUser {
        id: ch.user_id,
        username: ch.username,
        display_name,
    };
    let token = session::create_session(&st.db, user.id).await?;
    Ok((
        StatusCode::CREATED,
        [(
            header::SET_COOKIE,
            session::set_cookie(&token, st.cookie_secure),
        )],
        Json(user),
    )
        .into_response())
}

// ---------- ログイン ----------

/// POST /api/login/start
pub async fn login_start(
    State(st): State<AppState>,
    Json(req): Json<LoginStartReq>,
) -> AppResult<Json<StartResp<RequestChallengeResponse>>> {
    let username = req.username.trim().to_string();

    let user_id: Uuid = sqlx::query_scalar("SELECT id FROM passkey_users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&st.db)
        .await?
        .ok_or(AppError::NotFound("ユーザーが見つかりません"))?;

    let passkeys = load_passkeys(&st.db, user_id).await?;
    if passkeys.is_empty() {
        return Err(AppError::NotFound(
            "このユーザーにはパスキーが登録されていません",
        ));
    }

    let (rcr, auth_state) = st.webauthn.start_passkey_authentication(&passkeys)?;

    let challenge_id = save_challenge(
        &st.db,
        "authentication",
        user_id,
        &username,
        None,
        serde_json::to_value(&auth_state)?,
    )
    .await?;

    Ok(Json(StartResp {
        challenge_id,
        options: rcr,
    }))
}

/// POST /api/login/finish
pub async fn login_finish(
    State(st): State<AppState>,
    Json(req): Json<LoginFinishReq>,
) -> AppResult<Response> {
    let ch = take_challenge(&st.db, req.challenge_id, "authentication").await?;
    let auth_state: PasskeyAuthentication = serde_json::from_value(ch.state)?;

    let result = st
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)?;
    if !result.user_verified() {
        return Err(AppError::Unauthorized(
            "ユーザー確認（PIN / 顔 / 指紋）が必要です",
        ));
    }

    // 使われたパスキーを取得し、署名カウンタ等を更新する
    let (passkey_row_id, passkey_json): (i64, serde_json::Value) = sqlx::query_as(
        "SELECT id, passkey FROM passkeys WHERE user_id = $1 AND credential_id = $2",
    )
    .bind(ch.user_id)
    .bind(result.cred_id().as_slice())
    .fetch_optional(&st.db)
    .await?
    .ok_or(AppError::Unauthorized("認証に失敗しました"))?;

    let mut passkey: Passkey = serde_json::from_value(passkey_json)?;
    passkey.update_credential(&result);
    sqlx::query("UPDATE passkeys SET passkey = $2, last_used_at = now() WHERE id = $1")
        .bind(passkey_row_id)
        .bind(serde_json::to_value(&passkey)?)
        .execute(&st.db)
        .await?;

    let user: CurrentUser =
        sqlx::query_as("SELECT id, username, display_name FROM passkey_users WHERE id = $1")
            .bind(ch.user_id)
            .fetch_one(&st.db)
            .await?;

    let token = session::create_session(&st.db, user.id).await?;
    Ok((
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            session::set_cookie(&token, st.cookie_secure),
        )],
        Json(user),
    )
        .into_response())
}

// ---------- セッション ----------

/// GET /api/me
pub async fn me(user: CurrentUser) -> Json<CurrentUser> {
    Json(user)
}

/// POST /api/logout
pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> AppResult<Response> {
    if let Some(token) = session::cookie_value(&headers, session::SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(session::hash_token(&token))
            .execute(&st.db)
            .await?;
    }
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session::clear_cookie(st.cookie_secure))],
    )
        .into_response())
}

// ---------- 補助関数 ----------

#[derive(sqlx::FromRow)]
struct ChallengeRow {
    user_id: Uuid,
    username: String,
    display_name: Option<String>,
    state: serde_json::Value,
}

fn valid_len(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 64
}

async fn save_challenge(
    db: &PgPool,
    kind: &str,
    user_id: Uuid,
    username: &str,
    display_name: Option<&str>,
    state: serde_json::Value,
) -> AppResult<Uuid> {
    // 期限切れのチャレンジを掃除
    sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at <= now()")
        .execute(db)
        .await?;

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webauthn_challenges (id, kind, user_id, username, display_name, state, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
    )
    .bind(id)
    .bind(kind)
    .bind(user_id)
    .bind(username)
    .bind(display_name)
    .bind(state)
    .bind(CHALLENGE_TTL_SECS)
    .execute(db)
    .await?;
    Ok(id)
}

/// チャレンジを取り出して削除する（リプレイ防止のため 1 回限り）
async fn take_challenge(db: &PgPool, id: Uuid, kind: &str) -> AppResult<ChallengeRow> {
    sqlx::query_as::<_, ChallengeRow>(
        "DELETE FROM webauthn_challenges
          WHERE id = $1 AND kind = $2 AND expires_at > now()
      RETURNING user_id, username, display_name, state",
    )
    .bind(id)
    .bind(kind)
    .fetch_optional(db)
    .await?
    .ok_or(AppError::BadRequest(
        "チャレンジが無効または期限切れです。最初からやり直してください",
    ))
}

async fn load_passkeys(db: &PgPool, user_id: Uuid) -> AppResult<Vec<Passkey>> {
    let rows: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT passkey FROM passkeys WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(db)
            .await?;
    rows.into_iter()
        .map(|v| serde_json::from_value(v).map_err(AppError::from))
        .collect()
}

fn map_unique_violation(e: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_err) = &e
        && db_err.is_unique_violation()
    {
        return AppError::Conflict("そのユーザー名またはパスキーは既に登録されています");
    }
    AppError::from(e)
}
