# mail_auth_6

 Version: 0.9.1

 date    : 2026/11/24

 update :

***

Rust Axum , Mail Authrize SQLite Example

* SQLite DB
* Linux
* gmail use , app password 

***
* .env
```
DATABASE_URL=sqlite://app.db
BIND_ADDR=127.0.0.1:3000
# OTP ハッシュ用の秘密文字列 (ランダムな長い値にする)
OTP_PEPPER=change-me-to-a-long-random-string
# HTTPS 運用時は true
COOKIE_SECURE=false
# SMTP (未設定なら OTP はサーバーログに出力 = 開発モード)
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-name
SMTP_PASS=your-pass
SMTP_FROM=App <no-reply@example.com>
```
***
* Test-code

* register
```
curl -X POST localhost:3000/auth/user_register \
 -H 'content-type: application/json' \
 -d '{"email":"a@example.com","password":"password123"}'
```

***
* login
```
curl -X POST localhost:3000/auth/user_login -H 'content-type: application/json' \
 -d '{"email":"a@example.com","password":"password123"}'
```

***
* mail-send
```
curl -X POST localhost:3000/auth/send_code \
 -H 'content-type: application/json' \
 -d '{"email":"a@example.com","password":""}'
```

***
* code-verify
```
curl -X POST localhost:3000/auth/verify-email \
 -H 'content-type: application/json' \
 -d '{"email":"a@example.com","code":"123456"}'
```

***
