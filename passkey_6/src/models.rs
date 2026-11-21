use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct UserCreateReq {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserRes {
    pub email: String,
    pub password: String,
}

