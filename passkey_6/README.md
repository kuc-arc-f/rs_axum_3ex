# passkey_6

 Version: 0.9.1

 date    : 2026/11/22

 update :

***

Rust Axum , Passkey Authrize SQLite Example

* SQLite DB
* windows11 , Windows hello
* node22
* Linux

***
* Test-code
* signup

```
curl -X POST http://localhost:3000/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "1111"}'

```

* login

```
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "1111"}'
```

***
