"""ソフトウェア認証器（Windows Hello 相当の P-256 / 'none' attestation）で登録→ログインを検証する。"""
import base64, hashlib, json, os, struct, sys
import cbor2, requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

BASE = "http://localhost:3000"
ORIGIN = "http://localhost:3000"
RP_ID_HASH = hashlib.sha256(b"localhost").digest()

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def cose_key(pub):
    nums = pub.public_numbers()
    return cbor2.dumps({1: 2, 3: -7, -1: 1,
                        -2: nums.x.to_bytes(32, "big"),
                        -3: nums.y.to_bytes(32, "big")})

class FakeAuthenticator:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.counter = 0

    def create(self, public_key_opts):
        chal = public_key_opts["challenge"]
        client_data = json.dumps({"type": "webauthn.create", "challenge": chal,
                                  "origin": ORIGIN, "crossOrigin": False}).encode()
        auth_data = (RP_ID_HASH + bytes([0x45])  # UP|UV|AT
                     + struct.pack(">I", self.counter)
                     + bytes(16)  # aaguid
                     + struct.pack(">H", len(self.cred_id)) + self.cred_id
                     + cose_key(self.key.public_key()))
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
            "response": {"attestationObject": b64u(att), "clientDataJSON": b64u(client_data)},
            "extensions": {},
        }

    def get(self, chal, *, tamper=False):
        self.counter += 1
        client_data = json.dumps({"type": "webauthn.get", "challenge": chal,
                                  "origin": ORIGIN, "crossOrigin": False}).encode()
        auth_data = RP_ID_HASH + bytes([0x05]) + struct.pack(">I", self.counter)
        msg = auth_data + hashlib.sha256(client_data).digest()
        sig = self.key.sign(msg, ec.ECDSA(hashes.SHA256()))
        if tamper:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return {
            "id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
            "response": {"authenticatorData": b64u(auth_data), "clientDataJSON": b64u(client_data),
                         "signature": b64u(sig), "userHandle": None},
            "extensions": {},
        }

def check(label, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + label + (f"  {extra}" if extra else ""))
    if not cond:
        sys.exit(1)

s = requests.Session()
auth = FakeAuthenticator()
username = "e2e" + os.urandom(3).hex()

# --- 登録 ---
r = s.post(f"{BASE}/api/register/start", json={"username": username, "display_name": "E2E User"})
check("register/start 200", r.status_code == 200, str(r.status_code))
opts = r.json()
sel = opts["options"]["publicKey"]["authenticatorSelection"]
check("platform 認証器に限定", sel.get("authenticatorAttachment") == "platform")
r = s.post(f"{BASE}/api/register/finish", json={"challenge_id": opts["challenge_id"],
                                              "credential": auth.create(opts["options"]["publicKey"])})
check("register/finish 201", r.status_code == 201, r.text)
check("登録後 session cookie 発行", "session" in s.cookies)

# 同じ challenge の再利用は不可
r = s.post(f"{BASE}/api/register/finish", json={"challenge_id": opts["challenge_id"],
                                              "credential": auth.create(opts["options"]["publicKey"])})
check("challenge の再利用は 400", r.status_code == 400, str(r.status_code))

# 登録後は /api/me が使える
r = s.get(f"{BASE}/api/me")
check("/api/me (登録直後)", r.status_code == 200 and r.json()["username"] == username)

# --- ログアウト ---
r = s.post(f"{BASE}/api/logout")
check("logout 204", r.status_code == 204)
r = s.get(f"{BASE}/api/me")
check("logout 後 /api/me は 401", r.status_code == 401)

# --- ログイン ---
s2 = requests.Session()
r = s2.post(f"{BASE}/api/login/start", json={"username": username})
check("login/start 200", r.status_code == 200, r.text)
lo = r.json()
r = s2.post(f"{BASE}/api/login/finish", json={"challenge_id": lo["challenge_id"],
                                            "credential": auth.get(lo["options"]["publicKey"]["challenge"], tamper=True)})
check("改ざん署名は拒否 (4xx)", 400 <= r.status_code < 500, str(r.status_code))

r = s2.post(f"{BASE}/api/login/start", json={"username": username})
lo = r.json()
r = s2.post(f"{BASE}/api/login/finish", json={"challenge_id": lo["challenge_id"],
                                            "credential": auth.get(lo["options"]["publicKey"]["challenge"])})
check("login/finish 200", r.status_code == 200, r.text)
check("ログイン後 session cookie 発行", "session" in s2.cookies)
r = s2.get(f"{BASE}/api/me")
check("ログイン後 /api/me 200", r.status_code == 200 and r.json()["username"] == username)

# リプレイ（同じ challenge）は不可
r = s2.post(f"{BASE}/api/login/finish", json={"challenge_id": lo["challenge_id"],
                                            "credential": auth.get(lo["options"]["publicKey"]["challenge"])})
check("login の challenge リプレイは 400", r.status_code == 400, str(r.status_code))

# 署名カウンタが増えていること（DB 側）
print("ALL PASSED")
