# passkey_7

 Version: 0.9.1

 date    : 2026/08/30

 update :

***

Rust Axum , Passkey Authrize PostgreSQL  Example

* PostgreSQL  DB
* windows11 , Windows hello
* Linux
* Rust

***
* .env
```
DATABASE_URL=postgres://root:admin@localhost:5432/mydb
# WebAuthn の RP ID（ドメイン名）と Origin。ローカル開発は localhost のまま
RP_ID=localhost
RP_ORIGIN=http://localhost:3000
BIND_ADDR=127.0.0.1:3000
# HTTPS 運用時は true にする
COOKIE_SECURE=false
RUST_LOG=info,passkey_axum=debug
```

***
* Test-code
* signup

```
curl -X POST http://localhost:3000/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "a1@example.com", "password": "1111"}'
  
```

* login

```
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "a1@example.com", "password": "1111"}'
```

***
