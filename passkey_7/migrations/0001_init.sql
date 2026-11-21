CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_users_email ON users(email);
-- ユーザー
CREATE TABLE passkey_users (
    id           UUID PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- パスキー（Windows Hello で作成された資格情報の公開鍵など）
CREATE TABLE passkeys (
    id            BIGSERIAL PRIMARY KEY,
    user_id       UUID  NOT NULL REFERENCES passkey_users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    passkey       JSONB NOT NULL,              -- webauthn_rs::Passkey (シリアライズ済み)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX passkeys_user_id_idx ON passkeys (user_id);

-- WebAuthn のチャレンジ状態（登録・認証の途中経過）。1回限りで消費する
CREATE TABLE webauthn_challenges (
    id           UUID PRIMARY KEY,
    kind         TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
    user_id      UUID NOT NULL,
    username     TEXT NOT NULL,
    display_name TEXT,
    state        JSONB NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL
);

-- ログインセッション（Cookie の値は SHA-256 ハッシュのみ保存）
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES passkey_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
