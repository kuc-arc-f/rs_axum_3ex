# mail_auth_7

 Version: 0.9.1

 date    : 2026/11/25

 update :

***

Rust Axum , Mail Authrize PostgreSQL  Example

* PostgreSQL  DB
* Linux
* Rust

***
* Table: table.sql

***
* .env
```
DATABASE_URL=postgres://root:admin@localhost/mydb
JWT_SECRET=your-super-secret-key-change-me
GMAIL_USER=your-name
GMAIL_APP_PASSWORD=your-pass
```

***
* Test-code
* signup

```
curl -X POST http://localhost:3000/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "a1@example.com", "password": "password123"}'
  
```

* login

```
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email": "a1@example.com", "password": "password123"}'
```
***
* send-mail
```
curl -X POST localhost:3000/auth/request-otp \
 -H 'content-type: application/json' \
 -d '{"email":"a1@example.com"}'
```


***
* code-verify
```
curl -X POST localhost:3000/auth/verify-otp \
 -H 'content-type: application/json' \
 -d '{"email":"a1@example.com","code":"123456"}'
```

***
