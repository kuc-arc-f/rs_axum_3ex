//use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Deserialize)]
pub struct RegisterReq {
    pub email: String, 
    pub password: String 
}

#[derive(Debug, Deserialize)]
pub struct LoginReq { 
    pub email: String, 
    pub password: String 
}

#[derive(Debug, Deserialize)]
pub struct SetupReq { 
    pub user_id: i64, 
    pub code: String 
}

#[derive(Debug, Deserialize)]
pub struct UserEmailReq { 
    pub user_id: i64 
}
#[derive(Debug, Deserialize)]
pub struct UserMeReq { 
    pub email: String 
}
