use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use chrono::{Duration, Utc};
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::SocketAddr;
use crate::{
    error::{AppError, AppResult},
};

mod error;
mod models;
mod mod_auth;

#[derive(Clone)]
struct AppState {
    db: PgPool,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

#[derive(Deserialize)]
struct RequestOtpPayload {
    email: String,
}

#[derive(Deserialize)]
struct VerifyOtpPayload {
    email: String,
    code: String,
}

#[derive(Serialize)]
struct ApiResponse {
    message: String,
    token: Option<String>,
}
#[derive(Debug, Deserialize)]
struct UserMeReq { email: String }

#[derive(Debug, Deserialize)]
struct UserEmailReq { user_id: i32 }

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    // 1. DB接続
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    // 2. Gmail SMTP クライアントの構築 (TLS Wrapper: Port 465)
    let gmail_user = std::env::var("GMAIL_USER").expect("GMAIL_USER must be set");
    let gmail_pass = std::env::var("GMAIL_APP_PASSWORD").expect("GMAIL_APP_PASSWORD must be set");

    let creds = Credentials::new(gmail_user.clone(), gmail_pass);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .build();

    let state = AppState { db: pool, mailer };

    // 3. ルーティング
    let app = Router::new()
        .route("/api/user_get_name", post(user_get_name))
        .route("/auth/user_get_id", post(user_get_id))
        .route("/api/signup", post(user_create))
        .route("/api/login", post(user_login))
        .route("/auth/request-otp", post(request_otp))
        .route("/auth/verify-otp", post(verify_otp))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

pub async fn user_get_id(
    State(st): State<AppState>,
    Json(req): Json<UserEmailReq>,
) -> AppResult<Json<models::UserLoginRes>> {
    let mut user = models::UserLoginRes {
        id: 0,
        email: "".to_string(),
        password: "".to_string(),
    };   
    user.id = req.user_id;
    println!("#req"); 
    println!("{:?}", req); 
    let user_id = req.user_id;
    if user_id == 0 {
        return Err(AppError::BadRequest(
            "error , user_id =NONE",
        ));        
    }
    let users: Vec<models::DbUser> = sqlx::query_as::<_, models::DbUser>(
        r#"
        SELECT id, email, password_hash
        FROM users
        WHERE id = $1
        "#
    )
    .bind(&user_id)
    .fetch_all(&st.db)
    .await.unwrap();

    let mut user_count = 0;
    let mut user_id = 0;
    let mut email_str = "".to_string();
    for user in users {
        email_str = user.email.clone();
        println!("email: {}", user.email);
        user_count += 1;
    }    
    println!("user_count={}", user_count);
    println!("email_str={}", email_str);
    user.email = email_str.clone(); 
    if user_count == 0 {
        println!("error , user_count == 0");
        return Err(AppError::BadRequest(
            "error , user_count == 0",
        ));        
    }
    Ok(Json(
        user,
    ))
}
pub async fn user_get_name(
    State(st): State<AppState>,
    Json(req): Json<UserMeReq>,
) -> AppResult<Json<models::UserLoginRes>> {
    let mut user = models::UserLoginRes {
        id: 0,
        email: "".to_string(),
        password: "".to_string(),
    };   
    user.email = req.email.clone();
    println!("#req"); 
    println!("{:?}", req); 
    let email = req.email.trim();
    if email.is_empty() {
        return Err(AppError::BadRequest(
            "error , email =NONE",
        ));        
    }
    let users: Vec<models::DbUser> = sqlx::query_as::<_, models::DbUser>(
        r#"
        SELECT id, email, password_hash
        FROM users
        WHERE email = $1
        "#
    )
    .bind(&email)
    .fetch_all(&st.db)
    .await.unwrap();

    let mut user_count = 0;
    let mut user_id = 0;
    for user in users {
        user_id = user.id;
        println!("email: {}", user.email);
        user_count += 1;
    }    
    println!("user_count={}", user_count);
    println!("user_id={}", user_id);
    user.id = user_id; 
    if user_count == 0 {
        println!("error , user_count == 0");
        return Err(AppError::BadRequest(
            "error , user_count == 0",
        ));        
    }
    Ok(Json(
        user,
    ))
}
pub async fn user_login(
    State(st): State<AppState>,
    Json(req): Json<models::UserCreateReq>,
) -> AppResult<Json<models::UserLoginRes>> {
    let mut user = models::UserLoginRes {
        id: 0,
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
    let users: Vec<models::DbUser> = sqlx::query_as::<_, models::DbUser>(
        r#"
        SELECT id, email, password_hash
        FROM users
        WHERE email = $1
        "#
    )
    .bind(email)
    .fetch_all(&st.db)
    .await.unwrap();

    let mut user_count = 0;
    let mut user_id = 0;
    let mut db_pass = "".to_string();
    for user in users {
        db_pass = user.password_hash.clone();
        user_id = user.id;
        println!("email: {}", user.email);
        println!("password_hash: {}", db_pass);
        user_count += 1;
    }    
    println!("user_count={}", user_count);
    println!("user_id={}", user_id);
    user.id = user_id; 
    if user_count == 0 {
        println!("error , user_count == 0");
        return Err(AppError::BadRequest(
            "error , user_count == 0",
        ));        
    }
    let pw = password.clone();
    let phc = db_pass.clone();    
    let ok = mod_auth::verify_password(&pw, &db_pass).expect("error , veryfy password");
    println!("password ok? {}", ok);    
    if ok == false {
        return Err(AppError::BadRequest(
            "error , password=NG",
        ));        
    }   
    //user_id

    Ok(Json(
        user,
    ))
}

pub async fn user_create(
    State(st): State<AppState>,
    Json(req): Json<models::UserCreateReq>,
) -> AppResult<Json<models::UserRes>> {
    let mut user = models::UserRes {
        email: "".to_string(),
        password: "".to_string(),
    };   
    println!("#req"); 
    println!("{:?}", req); 
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(&req.email)
        .fetch_one(&st.db)
        .await?;
    if exists {
        return Err(AppError::Conflict("そのユーザー名は既に使われています"));
    }
    let pw = &req.password.clone();
    let phc = mod_auth::hash_password(&pw).expect("error , hash_password");
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

// OTP発行エンドポイント
async fn request_otp(
    State(state): State<AppState>,
    Json(payload): Json<RequestOtpPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // 6桁のOTPを生成
    let otp: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    let expires_at = Utc::now() + Duration::minutes(10);

    // DBに保存 (既存の古いコードは削除)
    sqlx::query("DELETE FROM otp_codes WHERE email = $1")
        .bind(&payload.email)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query(
        "INSERT INTO otp_codes (email, code, expires_at) VALUES ($1, $2, $3)"
    )
    .bind(&payload.email)
    .bind(&otp)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // メール送信
    let email = Message::builder()
        .from("Your App <your-email@gmail.com>".parse().unwrap())
        .to(payload.email.parse().unwrap())
        .subject("Your Login OTP Code")
        .header(ContentType::TEXT_PLAIN)
        .body(format!("Your OTP code is: {} \n It expires in 10 minutes.", otp))
        .unwrap();

    state
        .mailer
        .send(email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send email: {}", e)))?;

    Ok(Json(ApiResponse {
        message: "OTP sent to your email".to_string(),
        token: None,
    }))
}

// OTP検証エンドポイント
async fn verify_otp(
    State(state): State<AppState>,
    Json(payload): Json<VerifyOtpPayload>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // DBから有効なOTPを検索
    let record = sqlx::query_as::<_, (String, chrono::DateTime<Utc>)>(
        "SELECT code, expires_at FROM otp_codes WHERE email = $1 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    //println!("#user_id");
    println!("email={:?}", &payload.email);

    let (stored_code, expires_at) = match record {
        Some(r) => r,
        None => return Err((StatusCode::BAD_REQUEST, "No OTP requested".to_string())),
    };

    // 期限切れチェック
    if Utc::now() > expires_at {
        return Err((StatusCode::BAD_REQUEST, "OTP expired".to_string()));
    }

    // コード一致チェック
    if payload.code != stored_code {
        return Err((StatusCode::UNAUTHORIZED, "Invalid OTP".to_string()));
    }

    // 認証成功：OTPを無効化
    sqlx::query("DELETE FROM otp_codes WHERE email = $1")
        .bind(&payload.email)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // ユーザーが存在すれば取得、なければ作成 (パスワードレスログイン)
    let user_id: (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO passkey_users (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id"
    )
    .bind(&payload.email)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    println!("#user_id");
    println!("{:?}", user_id);

    // 実際のアプリケーションではここでJWTを発行します。
    // ここでは簡易的にUUIDをトークンとして返します。
    let token = uuid::Uuid::new_v4().to_string();

    Ok(Json(ApiResponse {
        message: "Login successful".to_string(),
        token: Some(token),
    }))
}