use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use webauthn_rs::prelude::WebauthnError;

pub type AppResult<T> = Result<T, AppError>;

/// API が返すエラー。メッセージはクライアントに表示できる内容のみを入れる
#[derive(Debug)]
pub enum AppError {
    BadRequest(&'static str),
    Unauthorized(&'static str),
    NotFound(&'static str),
    Conflict(&'static str),
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m),
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "内部エラーが発生しました",
            ),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error");
        AppError::Internal
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!(error = %e, "json error");
        AppError::Internal
    }
}

impl From<WebauthnError> for AppError {
    fn from(e: WebauthnError) -> Self {
        // 詳細はログのみ。クライアントには一般的なメッセージを返す
        tracing::warn!(error = ?e, "webauthn error");
        AppError::BadRequest("パスキーの検証に失敗しました")
    }
}
