// WebAuthn クライアント。サーバーとは base64url 文字列でやり取りし、
// navigator.credentials に渡す直前・受け取った直後に ArrayBuffer と相互変換する。
"use strict";

const $ = (id) => document.getElementById(id);

// ---------- base64url <-> ArrayBuffer ----------
function b64urlToBuffer(str) {
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
  const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---------- API ----------
async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.error ?? `HTTP ${res.status}`);
  return data;
}

// ---------- UI ----------
function setStatus(msg, kind = "") {
  const el = $("status");
  el.textContent = msg;
  el.className = kind;
}

function setBusy(busy) {
  document.querySelectorAll("button").forEach((b) => (b.disabled = busy));
}

function showUser(user) {
  const loggedIn = !!user;
  $("loggedOut").hidden = loggedIn;
  $("loggedIn").hidden = !loggedIn;
  if (user) {
    $("me").textContent = `${user.display_name}（@${user.username}）でログイン中`;
  }
}

// ---------- 登録（Windows Hello で資格情報を作成） ----------
async function register() {
  const username = $("regUsername").value.trim();
  const displayName = $("regDisplayName").value.trim() || username;
  if (!username) return setStatus("ユーザー名を入力してください", "error");

  setBusy(true);
  try {
    setStatus("サーバーにチャレンジを要求中…");
    const { challenge_id, options } = await api("/api/register/start", {
      username,
      display_name: displayName,
    });

    const pk = options.publicKey;
    pk.challenge = b64urlToBuffer(pk.challenge);
    pk.user.id = b64urlToBuffer(pk.user.id);
    if (pk.excludeCredentials) {
      pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
    }

    setStatus("Windows Hello の認証ダイアログで PIN / 顔 / 指紋を入力してください…");
    const cred = await navigator.credentials.create({ publicKey: pk });

    const user = await api("/api/register/finish", {
      challenge_id,
      credential: {
        id: cred.id,
        rawId: bufferToB64url(cred.rawId),
        type: cred.type,
        response: {
          attestationObject: bufferToB64url(cred.response.attestationObject),
          clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
          transports: cred.response.getTransports?.() ?? null,
        },
        extensions: cred.getClientExtensionResults?.() ?? {},
      },
    });
    setStatus(`登録完了：${user.display_name} としてログインしました`, "ok");
    showUser(user);
  } catch (e) {
    setStatus(describeError(e), "error");
  } finally {
    setBusy(false);
  }
}

// ---------- ログイン（Windows Hello で署名） ----------
async function login() {
  const username = $("loginUsername").value.trim();
  if (!username) return setStatus("ユーザー名を入力してください", "error");

  setBusy(true);
  try {
    setStatus("サーバーにチャレンジを要求中…");
    const { challenge_id, options } = await api("/api/login/start", { username });

    const pk = options.publicKey;
    pk.challenge = b64urlToBuffer(pk.challenge);
    if (pk.allowCredentials) {
      pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
    }

    setStatus("Windows Hello の認証ダイアログで本人確認してください…");
    const cred = await navigator.credentials.get({ publicKey: pk });

    const user = await api("/api/login/finish", {
      challenge_id,
      credential: {
        id: cred.id,
        rawId: bufferToB64url(cred.rawId),
        type: cred.type,
        response: {
          authenticatorData: bufferToB64url(cred.response.authenticatorData),
          clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
          signature: bufferToB64url(cred.response.signature),
          userHandle: cred.response.userHandle ? bufferToB64url(cred.response.userHandle) : null,
        },
        extensions: cred.getClientExtensionResults?.() ?? {},
      },
    });
    setStatus("ログインしました", "ok");
    showUser(user);
  } catch (e) {
    setStatus(describeError(e), "error");
  } finally {
    setBusy(false);
  }
}

async function logout() {
  await api("/api/logout", {});
  showUser(null);
  setStatus("ログアウトしました", "ok");
}

// ブラウザの DOMException を日本語のわかりやすいメッセージにする
function describeError(e) {
  if (e?.name === "NotAllowedError") return "認証がキャンセルされたかタイムアウトしました";
  if (e?.name === "InvalidStateError") return "このデバイスには既にパスキーが登録されています";
  return e?.message ?? String(e);
}

// ---------- 初期化 ----------
async function init() {
  if (!window.PublicKeyCredential) {
    $("platform").textContent = "このブラウザはパスキー（WebAuthn）に対応していません";
  } else if (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) {
    $("platform").textContent = "Windows Hello 利用可能";
  } else {
    $("platform").textContent = "この端末では Windows Hello（プラットフォーム認証）が利用できません";
  }

  $("btnRegister").addEventListener("click", register);
  $("btnLogin").addEventListener("click", login);
  $("btnLogout").addEventListener("click", logout);

  try {
    showUser(await api("/api/me"));
  } catch {
    showUser(null);
  }
}

init();
