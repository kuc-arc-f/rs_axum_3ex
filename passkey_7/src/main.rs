mod error;
mod passkey;
mod session;
mod models;
mod mod_auth;

use std::{env, sync::Arc};

use axum::{
    Json,
    Router,
    routing::{get, post},
};
/*
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
*/
use sqlx::postgres::PgPoolOptions;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub webauthn: Arc<Webauthn>,
    pub cookie_secure: bool,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = env::var("DATABASE_URL")?;
    let rp_id = env::var("RP_ID").unwrap_or_else(|_| "localhost".into());
    let rp_origin =
        Url::parse(&env::var("RP_ORIGIN").unwrap_or_else(|_| "http://localhost:3000".into()))?;
    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let cookie_secure = matches!(env::var("COOKIE_SECURE").as_deref(), Ok("true" | "1"));

    // DB 接続 & マイグレーション
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;

    // WebAuthn (Relying Party) 設定
    let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)?
        .rp_name("Passkey Axum Demo")
        .build()?;

    let state = AppState {
        db,
        webauthn: Arc::new(webauthn),
        cookie_secure,
    };
    let app = Router::new()
        .route("/api/signup", post(passkey::user_create))
        .route("/api/register/start", post(passkey::register_start))
        .route("/api/register/finish", post(passkey::register_finish))
        .route("/api/login", post(passkey::user_login))
        .route("/api/login/start", post(passkey::login_start))
        .route("/api/login/finish", post(passkey::login_finish))
        .route("/api/me", get(passkey::me))
        .route("/api/logout", post(passkey::logout))
        .fallback_service(ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!("listening on http://{bind_addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
