//use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sqlx::FromRow;

/// TODO登録時のリクエストボディ
#[derive(Debug, Deserialize)]
pub struct CreateTodoRequest {
    pub title: String,
}

/// エラーレスポンス用
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct UserRes {
    pub email: String,
    pub password: String,
}
#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct UserLoginRes {
    pub id: i32,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct DbUser {
    pub id: i32,
    pub email: String,
    pub password_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct UserCreateReq {
    pub email: String,
    pub password: String,
}
#[derive(Debug, Deserialize)]
pub struct UserIdReq {
    pub email: String,
}