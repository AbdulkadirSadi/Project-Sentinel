"""
Sentinel AI — FastAPI Servisi
==============================
Çalıştır: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
import urllib.request
import urllib.error
from contextlib import asynccontextmanager
from typing import Any, Optional
from pathlib import Path

import asyncpg
from fastapi import FastAPI, HTTPException, Query, UploadFile
from pydantic import BaseModel

from models.static_model import StaticAnalyzer, BinaryAnalyzer
from models.behavioral_model import BehavioralAnalyzer, apply_rules
from models.yara_scanner import YaraScanner

# ── KQL Kural Cache (DB'den yüklenir, memory'de tutulur) ─────────────────────
_custom_rules: list[dict] = []
_rules_loaded_at: float   = 0.0
RULES_TTL = 30.0  # saniye — her 30s'de DB'den yenile

from dotenv import load_dotenv
load_dotenv()

# ── JWT Auth ─────────────────────────────────────────────────────────────────
import hmac
import base64
import struct

JWT_SECRET  = os.getenv("JWT_SECRET", "sentinel-dev-secret-change-in-production")
JWT_EXPIRE  = int(os.getenv("JWT_EXPIRE_HOURS", "24")) * 3600  # saniye
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "")  # agent→server payloşılan token (boşsa bypass)

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def create_jwt(payload: dict) -> str:
    """Minimal HS256 JWT üretici (python-jose bağımlılığı olmadan)."""
    import json as _json
    header  = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload["exp"] = int(time.time()) + JWT_EXPIRE
    body    = _b64url(_json.dumps(payload).encode())
    sig_input = f"{header}.{body}".encode()
    sig     = hmac.new(JWT_SECRET.encode(), sig_input, "sha256").digest()
    return f"{header}.{body}.{_b64url(sig)}"

def verify_jwt(token: str) -> dict | None:
    """JWT doğrula; geçersiz/süresi dolmuşsa None döner."""
    import json as _json
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        sig_input = f"{header}.{body}".encode()
        expected  = hmac.new(JWT_SECRET.encode(), sig_input, "sha256").digest()
        if not hmac.compare_digest(_b64url(expected), sig):
            return None
        payload = _json.loads(_b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def _hash_password(pw: str) -> str:
    """Basit PBKDF2-HMAC-SHA256 hash (bcrypt bağımlılığı yok)."""
    import hashlib
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return base64.b64encode(salt + dk).decode()

def _verify_password(pw: str, stored: str) -> bool:
    import hashlib
    try:
        raw  = base64.b64decode(stored)
        salt, dk = raw[:16], raw[16:]
        chk  = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
        return hmac.compare_digest(chk, dk)
    except Exception:
        return False

async def _get_current_user(request) -> dict | None:
    """Request header'dan JWT çöz. None dönerse auth yok (opsiyonel mod)."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return verify_jwt(auth[7:])
    return None

async def _require_auth(request) -> dict:
    """Zorunlu auth — 401 fırlatır."""
    user = await _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Kimlik doğrulama gerekli.")
    return user

# ── Config ────────────────────────────────────────────────────────────────────

PG_DSN = os.getenv(
    "PG_DSN",
    "postgresql://admin:password123@localhost:5432/xdr_db",
)
SERVER_API = os.getenv("SERVER_API", "http://localhost:8081")
ALERT_THRESHOLD   = float(os.getenv("ALERT_THRESHOLD",   "70"))
ACTION_THRESHOLD  = float(os.getenv("ACTION_THRESHOLD",  "90"))
VT_API_KEY        = os.getenv("VT_API_KEY", "")   # https://www.virustotal.com/gui/my-apikey
VT_MIN_POSITIVES  = int(os.getenv("VT_MIN_POSITIVES", "5"))  # kaç motor zararlı derse alert üret
INTERNAL_SECRET   = os.getenv("INTERNAL_SECRET",  "sentinel-internal-ai-secret-2024")

# ── Globals ───────────────────────────────────────────────────────────────────

static_analyzer     = StaticAnalyzer("models/static_model.pt")
binary_analyzer     = BinaryAnalyzer("models/binary_model.pt")
behavioral_analyzer = BehavioralAnalyzer()
YARA_DIR            = Path(__file__).parent / "yara_rules"
yara_scanner        = YaraScanner(str(YARA_DIR))
pg_pool: asyncpg.Pool | None = None


# ── Startup / Shutdown ────────────────────────────────────────────────────────

# Bilinen zararlı hash'ler (SHA-256) — seed veritabanı
# Bunlar örnek/test hash'leridir; gerçek hash'ler threat intel beslemelerinden alınır
KNOWN_MALWARE_HASHES: dict[str, dict] = {
    # Mimikatz türevleri
    "fc525c9683e8b4d7d232d75b18249e1f21d36d16be7a29ab8d79f08f18a1e08e": {"name": "Mimikatz", "threat_type": "credential_theft", "risk_score": 99},
    "f4dd82b5d0b6c17ed02a65f4d458f5c83c8e6f5f21d9e3f38dd09e4d64c08b4f": {"name": "Mimikatz v2", "threat_type": "credential_theft", "risk_score": 99},
    # Metasploit/Meterpreter
    "3395856ce81f2b7382dee72602f798b642f14d40bad7b5eaa8a8b3d27aae9f09": {"name": "Meterpreter", "threat_type": "rat", "risk_score": 98},
    # WannaCry
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": {"name": "WannaCry Ransomware", "threat_type": "ransomware", "risk_score": 100},
    "b6b3b4b5c5d3b3b4b5c5d3b3b4b5c5d3b3b4b5c5d3b3b4b5c5d3b3b4b5c5d3": {"name": "WannaCry v2", "threat_type": "ransomware", "risk_score": 100},
    # NotPetya
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745": {"name": "NotPetya", "threat_type": "ransomware", "risk_score": 100},
    # EICAR test virüsü (test amaçlı)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {"name": "EICAR Test Virus", "threat_type": "trojan", "risk_score": 100},
    # xmrig cryptominer
    "a5d3c4b2e1f0d3c4b2e1f0d3c4b2e1f0d3c4b2e1f0d3c4b2e1f0d3c4b2e1f0d": {"name": "XMRig Cryptominer", "threat_type": "cryptominer", "risk_score": 92},
    # Cobalt Strike beacon
    "1f3e2d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e": {"name": "Cobalt Strike Beacon", "threat_type": "c2_framework", "risk_score": 99},
}

async def _init_malware_hash_db(pool: asyncpg.Pool) -> None:
    """Malware hash tablosunu oluşturur ve seed hash'leri ekler."""
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS malware_hashes (
            id          SERIAL PRIMARY KEY,
            sha256      VARCHAR(64) UNIQUE NOT NULL,
            name        VARCHAR(255) NOT NULL DEFAULT 'Unknown',
            threat_type VARCHAR(100) NOT NULL DEFAULT 'malware',
            risk_score  FLOAT NOT NULL DEFAULT 90,
            source      VARCHAR(100) NOT NULL DEFAULT 'manual',
            added_at    BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
            notes       TEXT
        )
    """)
    # Seed hash'leri ekle (ON CONFLICT ile tekrar ekleme yapılmaz)
    for sha256, info in KNOWN_MALWARE_HASHES.items():
        await pool.execute(
            """INSERT INTO malware_hashes (sha256, name, threat_type, risk_score, source)
               VALUES ($1, $2, $3, $4, 'builtin')
               ON CONFLICT (sha256) DO NOTHING""",
            sha256, info["name"], info["threat_type"], info["risk_score"]
        )
    count = await pool.fetchval("SELECT COUNT(*) FROM malware_hashes")
    print(f"[+] AI Servis: Malware hash DB hazır — {count} hash kayıtlı.")


async def _init_file_scans_vt_columns(pool: asyncpg.Pool) -> None:
    """file_scans tablosuna VT kolon ekler (varsa atlar)."""
    for col, typ in [
        ("vt_positives", "INT"),
        ("vt_total",     "INT"),
        ("vt_label",     "VARCHAR(200)"),
        ("vt_permalink", "VARCHAR(500)"),
    ]:
        try:
            await pool.execute(
                f"ALTER TABLE file_scans ADD COLUMN IF NOT EXISTS {col} {typ}"
            )
        except Exception:
            pass
    print("[+] AI Servis: file_scans VT kolonları hazır.")


async def _init_file_scans_yara_column(pool: asyncpg.Pool) -> None:
    """file_scans tablosuna YARA sonucu kolonu ekler."""
    try:
        await pool.execute(
            "ALTER TABLE file_scans ADD COLUMN IF NOT EXISTS yara_matches TEXT"
        )
        print("[+] AI Servis: file_scans yara_matches kolonu hazır.")
    except Exception:
        pass


async def vt_lookup_hash(sha256: str) -> dict | None:
    """
    VirusTotal API v3 ile SHA-256 hash sorgular.
    Döndürülen sözlük: found, positives, total, label, permalink
    API key yoksa veya hata alınırsa None döner.
    """
    if not VT_API_KEY:
        return None

    def _fetch() -> dict | None:
        try:
            req = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": VT_API_KEY, "Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            attrs  = data.get("data", {}).get("attributes", {})
            stats  = attrs.get("last_analysis_stats", {})
            label  = (attrs.get("popular_threat_classification") or {}) \
                         .get("suggested_threat_label", "")
            positives = stats.get("malicious", 0)
            total     = sum(stats.values())
            return {
                "found":     True,
                "positives": positives,
                "total":     total,
                "label":     label or "",
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"found": False, "positives": 0, "total": 0,
                        "label": "", "permalink": ""}
            print(f"[VT] HTTP {e.code}: {sha256[:12]}")
            return None
        except Exception as ex:
            print(f"[VT] Hata: {ex}")
            return None

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _fetch)

@asynccontextmanager
async def lifespan(app: FastAPI):
    global pg_pool
    try:
        pg_pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=10)
        print("[+] AI Servis: PostgreSQL bağlantısı kuruldu.")
        # Malware hash DB'yi başlat
        await _init_malware_hash_db(pg_pool)
        await _init_file_scans_vt_columns(pg_pool)
        await _init_file_scans_yara_column(pg_pool)
        # Kayıtlı baseline'ları behavioral_analyzer'a yükle
        await _load_baselines_from_db(pg_pool)
        # Auth: users tablosunu oluştur ve varsayılan admin ekle
        await _init_users_table(pg_pool)
    except Exception as e:
        print(f"[!] AI Servis: Başlangıç hatası: {e}")
    yield
    if pg_pool:
        await pg_pool.close()


async def _init_users_table(pool: asyncpg.Pool) -> None:
    """Kullanıcı tablosunu oluşturur, varsayılan admin varsa atlar."""
    await pool.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            username   VARCHAR(64) UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       VARCHAR(32) DEFAULT 'analyst',
            created_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
            active     BOOLEAN DEFAULT TRUE
        )
    """)
    # Varsayılan admin hesabı — şifresi .env'den alınır, yoksa 'admin123'
    default_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    existing = await pool.fetchval("SELECT id FROM users WHERE username='admin'")
    if not existing:
        hashed = _hash_password(default_pass)
        await pool.execute(
            "INSERT INTO users (username, password, role) VALUES ($1, $2, 'admin')",
            "admin", hashed
        )
        print(f"[+] Auth: Varsayılan admin oluşturuldu (şifre: {default_pass})")
    else:
        print("[+] Auth: Users tablosu hazır.")


from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request

app = FastAPI(title="Sentinel AI Engine", version="1.0.0", lifespan=lifespan)

# CORS: sadece aynı sunucudan gelen frontend isteklerine izin ver
_ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def get_baseline(agent_id: str) -> dict:
    """agent_baseline tablosundan kalibrasyon verisini çeker."""
    if not pg_pool:
        return {}
    row = await pg_pool.fetchrow(
        "SELECT * FROM agent_baseline WHERE agent_id = $1", agent_id
    )
    if not row:
        return {}
    import json
    b = dict(row)
    for k in ("known_processes", "known_ips"):
        if isinstance(b.get(k), str):
            b[k] = json.loads(b[k])
        elif b.get(k) is None:
            b[k] = {}
    return b


async def update_event_score(event_id: int, risk_score: float,
                              threat_type: str, confidence: float,
                              is_anomaly: bool):
    if not pg_pool or not event_id:
        return
    await pg_pool.execute(
        """UPDATE events SET
               risk_score  = $1,
               threat_type = $2,
               confidence  = $3,
               is_anomaly  = $4
           WHERE id = $5""",
        risk_score, threat_type, confidence, is_anomaly, event_id,
    )


async def trigger_action(agent_id: str, threat_type: str,
                          event: dict, risk_score: float):
    """
    Tehdit tipine göre otomatik aksiyon belirler ve
    Go server HTTP API'sine gönderir.
    """
    exe_path   = event.get("exe_path", "") or ""
    pid        = int(event.get("pid", 0) or 0)
    remote_ip  = event.get("remote_ip", "") or ""

    # Karar mantığı:
    # 1. pid > 0  → canlı süreç var, önce kill_process (process event)
    # 2. pid == 0 ve exe_path var → statik analiz, dosyayı karantinaya al
    # 3. remote_ip var → ağ tabanlı, ip engelle
    if pid > 0:
        # Canlı süreç tespiti (process_new, etw_process_start, vb.)
        action = "kill_process"
        params = {"pid": pid}
    elif exe_path:
        # Statik dosya taraması (analyze_static) — pid=0 olarak gönderilir
        action = "quarantine_file"
        params = {"path": exe_path}
    elif remote_ip:
        # Ağ tabanlı tehdit
        net_map = {
            "rat":              ("block_ip",        {"ip": remote_ip}),
            "backdoor":         ("isolate_network", {"ip": remote_ip}),
            "c2_common":        ("block_ip",        {"ip": remote_ip}),
            "c2_beacon":        ("block_ip",        {"ip": remote_ip}),
            "metasploit":       ("block_ip",        {"ip": remote_ip}),
            "lateral_movement": ("isolate_network", {"ip": remote_ip}),
        }
        action, params = net_map.get(threat_type, ("block_ip", {"ip": remote_ip}))
    else:
        print(f"[ACTION] Aksiyon için yeterli parametre yok: {threat_type} | pid={pid} | exe={exe_path} | ip={remote_ip}")
        return

    # Geçersiz param varsa gönderme
    if not any(str(v) for v in params.values()):
        print(f"[ACTION] Geçersiz param, atlandı: {threat_type} | {params}")
        return



    payload = {"agent_id": agent_id, "action": action, "params": params}
    try:
        import httpx, json
        headers = {"X-Internal-Secret": INTERNAL_SECRET}
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(f"{SERVER_API}/api/action", json=payload, headers=headers)
            success = resp.status_code == 200
            print(f"[AUTO-ACTION] {agent_id[:8]} | {action} | score:{risk_score:.0f} | HTTP:{resp.status_code}")
            if resp.status_code != 200:
                print(f"[AUTO-ACTION] YANIT: {resp.text[:200]}")
            if pg_pool:
                await pg_pool.execute(
                    """INSERT INTO action_logs
                       (agent_id, action_type, threat_type, risk_score, params, is_success, message, ts)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                    agent_id, action, threat_type, risk_score, json.dumps(params), success,
                    f"HTTP {resp.status_code}", int(time.time())
                )
    except Exception as e:
        print(f"[!] Aksiyon gönderilemedi ({agent_id[:8]}): {e}")
        if pg_pool:
            import json
            await pg_pool.execute(
                """INSERT INTO action_logs
                   (agent_id, action_type, threat_type, risk_score, params, is_success, message, ts)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                agent_id, action, threat_type, risk_score, json.dumps(params), False,
                str(e), int(time.time())
            )


async def create_alert(
    event_id: int | None, agent_id: str,
    ts: int, risk_score: float,
    threat_type: str, confidence: float,
    pname: str = "", pid: int = 0, rule_name: str = "",
    dedup_window: int = 60,
) -> int | None:
    """Alert oluştur, oluşturulan kaydın id'sini döndür."""
    if not pg_pool:
        return None
    # Dedup: aynı agent + threat_type + pname son dedup_window saniyede var mı?
    if dedup_window > 0:
        cutoff = ts - dedup_window
        existing = await pg_pool.fetchval(
            """SELECT id FROM alerts
               WHERE agent_id=$1 AND threat_type=$2 AND pname=$3 AND ts>$4
               LIMIT 1""",
            agent_id, threat_type, pname, cutoff,
        )
        if existing:
            return int(existing)  # Mevcut alert id'sini döndür
    row = await pg_pool.fetchrow(
        """INSERT INTO alerts
               (event_id, agent_id, ts, risk_score, threat_type, confidence, pname, pid, rule_name)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id""",
        event_id, agent_id, ts, risk_score, threat_type, confidence,
        pname, pid, rule_name,
    )
    alert_id = row["id"] if row else None
    print(f"[!] ALERT #{alert_id} → agent:{agent_id[:8]} | {threat_type} | {pname} | score:{risk_score:.1f}")
    return alert_id



# ── Pydantic Modeller ─────────────────────────────────────────────────────────

class EventRequest(BaseModel):
    event_id: int | None = None
    data:     dict[str, Any]


class StaticRequest(BaseModel):
    agent_id:   str
    exe_b64:    str             # base64 kodlu PE dosyası
    file_name:  str = "unknown.exe"
    categorize: bool = False    # True ise zararlı bulunursa multiclass da çalıştır
    file_path:  str  = ""       # Ajan'dan gelen tam dosya yolu (auto_scan için)
    source:     str  = "manual" # "manual" | "auto_scan"


class CalibrateRequest(BaseModel):
    agent_id: str

class CalibrationStateReq(BaseModel):
    action: str  # 'start', 'stop', 'reset'


class AlertResolveRequest(BaseModel):
    notes: str = ""


# ── Auth Endpoints ────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


@app.post("/auth/login")
async def auth_login(req: LoginRequest):
    """Kullanıcı adı ve şifre ile JWT token al."""
    if not pg_pool:
        raise HTTPException(503, "Veritabanı bağlantısı yok.")
    row = await pg_pool.fetchrow(
        "SELECT id, username, password, role FROM users WHERE username=$1 AND active=TRUE",
        req.username
    )
    if not row or not _verify_password(req.password, row["password"]):
        raise HTTPException(401, "Kullanıcı adı veya şifre hatalı.")
    token = create_jwt({"sub": row["username"], "role": row["role"], "uid": row["id"]})
    return {"access_token": token, "token_type": "bearer",
            "username": row["username"], "role": row["role"]}


@app.get("/auth/me")
async def auth_me(request: Request):
    """Mevcut oturum bilgisi."""
    user = await _require_auth(request)
    return {"username": user["sub"], "role": user["role"]}


@app.get("/auth/users")
async def auth_list_users(request: Request):
    """Kullanıcı listesi — sadece admin."""
    user = await _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Bu işlem için admin yetkisi gerekli.")
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    rows = await pg_pool.fetch("SELECT id, username, role, active, created_at FROM users ORDER BY id")
    return [dict(r) for r in rows]


@app.post("/auth/users")
async def auth_create_user(req: UserCreateRequest, request: Request):
    """Yeni kullanıcı oluştur — sadece admin."""
    user = await _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Bu işlem için admin yetkisi gerekli.")
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    hashed = _hash_password(req.password)
    try:
        await pg_pool.execute(
            "INSERT INTO users (username, password, role) VALUES ($1, $2, $3)",
            req.username, hashed, req.role
        )
    except Exception:
        raise HTTPException(409, "Bu kullanıcı adı zaten mevcut.")
    return {"message": f"'{req.username}' kullanıcısı oluşturuldu."}


@app.delete("/auth/users/{username}")
async def auth_delete_user(username: str, request: Request):
    """Kullanıcı sil — sadece admin (kendini silemez)."""
    user = await _require_auth(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Bu işlem için admin yetkisi gerekli.")
    if username == user["sub"]:
        raise HTTPException(400, "Kendi hesabınızı silemezsiniz.")
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    await pg_pool.execute("UPDATE users SET active=FALSE WHERE username=$1", username)
    return {"message": f"'{username}' devre dışı bırakıldı."}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":          "ok",
        "static_ready":    static_analyzer.is_ready(),
        "pg_connected":    pg_pool is not None,
    }


async def _lookup_parent_pname(agent_id: str, ppid: int) -> str:
    """PPID'ye göre son bilinen parent process adını döndür."""
    if not pg_pool or ppid <= 0:
        return ""
    row = await pg_pool.fetchrow(
        """SELECT raw->>'pname' as pname FROM events
           WHERE agent_id=$1 AND type='process_new'
             AND (raw->>'pid')::int=$2
           ORDER BY ts DESC LIMIT 1""",
        agent_id, ppid,
    )
    return (row["pname"] or "") if row else ""


async def _beacon_check(agent_id: str, remote_ip: str, ts: int) -> bool:
    """Son 10 dakikada aynı agent+IP için ≥3 bağlantı → beacon."""
    if not pg_pool or not remote_ip:
        return False
    cutoff = ts - 600  # 10 dakika
    count = await pg_pool.fetchval(
        """SELECT count(*) FROM events
           WHERE agent_id=$1 AND type='network_new'
             AND raw->>'remote_ip'=$2
             AND ts>=$3""",
        agent_id, remote_ip, cutoff,
    )
    return int(count or 0) >= 3


@app.post("/analyze/event")
async def analyze_event(req: EventRequest):
    """
    Go server her yeni event için bu endpoint'i çağırır.
    Kural motoru + kalibrasyon skoru birleştirilir.
    Eşik aşılırsa alert oluşturulur.
    """
    event     = req.data
    agent_id  = event.get("agent_id", "")
    ts        = int(event.get("ts", time.time()))
    event_id  = req.event_id

    # 1. Parent-child için PPID lookup (process_new ise)
    parent_pname = ""
    if event.get("type") == "process_new":
        ppid = int(event.get("ppid", 0) or 0)
        parent_pname = await _lookup_parent_pname(agent_id, ppid)

    # 2. Kural motoru (parent_pname ile birlikte)
    rule_res  = apply_rules(event, parent_pname=parent_pname)

    # 3. Beacon tespiti (network_new ise)
    if event.get("type") == "network_new":
        remote_ip = event.get("remote_ip", "")
        if await _beacon_check(agent_id, remote_ip, ts):
            if rule_res.score < 78:
                rule_res.score = 78
                rule_res.threat_type = "c2_beacon"
            rule_res.triggered.append(f"beacon:{remote_ip}")

    # 4. Davranışsal anomali (kalibrasyon varsa)
    baseline  = await get_baseline(agent_id)
    beh_score = 0.0
    if baseline.get("calibrated"):
        beh_score = behavioral_analyzer.score_event(agent_id, event, baseline)

    # 5. Birleşik skor
    final_score   = max(float(rule_res.score), beh_score)
    threat_type   = rule_res.threat_type if rule_res.score >= beh_score else "anomaly"
    confidence    = round(final_score / 100.0, 4)
    is_anomaly    = final_score >= ALERT_THRESHOLD

    # 6. DB güncelle
    if event_id:
        await update_event_score(event_id, final_score, threat_type, confidence, is_anomaly)

    # 7. Alert oluştur (RETURNING id ile)
    alert_id = None
    if is_anomaly:
        alert_id = await create_alert(
            event_id, agent_id, ts, final_score, threat_type, confidence,
            pname=str(event.get("pname") or event.get("exe_path") or ""),
            pid=int(event.get("pid") or 0)
        )

    action_taken = "none"

    # 8. Custom KQL kurallarını uygula
    custom_hit = await apply_custom_rules(event)
    if custom_hit:
        c_score = custom_hit["score"]
        c_type  = custom_hit["threat_type"]
        c_pname = str(event.get("pname") or event.get("exe_path") or "")
        c_pid   = int(event.get("pid") or 0)
        if c_score > final_score:
            final_score = c_score
            threat_type = c_type
        if c_score >= ALERT_THRESHOLD:
            c_alert_id = await create_alert(
                event_id, agent_id, ts, c_score, c_type,
                round(c_score/100, 4),
                pname=c_pname, pid=c_pid,
                rule_name=custom_hit["name"],
            )
            if c_alert_id and not alert_id:
                alert_id = c_alert_id
        if c_score >= ACTION_THRESHOLD:
            asyncio.create_task(trigger_action(agent_id, c_type, event, c_score))
            action_taken = "kill_process"

    # 9. Otomatik aksiyon — built-in kural (skor >= ACTION_THRESHOLD)
    if final_score >= ACTION_THRESHOLD and action_taken == "none":
        asyncio.create_task(trigger_action(agent_id, threat_type, event, final_score))
        action_taken = threat_type

    # 10. action_taken'ı doğrudan alert_id ile güncelle (race condition yok)
    if action_taken != "none" and alert_id and pg_pool:
        await pg_pool.execute(
            "UPDATE alerts SET action_taken=$1 WHERE id=$2",
            action_taken, alert_id,
        )

    return {
        "risk_score":   final_score,
        "threat_type":  threat_type,
        "confidence":   confidence,
        "is_anomaly":   is_anomaly,
        "rule_score":   rule_res.score,
        "beh_score":    beh_score,
        "triggered":    rule_res.triggered,
        "parent_pname": parent_pname,
        "auto_action":  action_taken != "none",
        "custom_rule":  custom_hit["name"] if custom_hit else None,
        "action_taken": action_taken,
        "alert_id":     alert_id,
    }


@app.post("/analyze/static")
async def analyze_static(req: StaticRequest):
    """
    PE dosyasını iki aşamalı analiz eder:
      Aşama 1: Binary triage (binary_model.pt) — hızlı benign/malicious kararı
      Aşama 2: Multiclass CNN (static_model.pt) — sadece req.categorize=True ise
    """
    import base64

    # 1) Ham bytes'ları al ve hash'i hesapla
    try:
        raw = base64.b64decode(req.exe_b64)
        file_hash = hashlib.sha256(raw).hexdigest()
        file_size = len(raw)
    except Exception:
        raise HTTPException(400, "Geçersiz base64 verisi.")

    file_name = req.file_name or "unknown.exe"
    ts        = int(time.time())

    # 2a) VT + YARA paralel başlat
    vt_task   = asyncio.create_task(vt_lookup_hash(file_hash)) if VT_API_KEY else None
    yara_task = asyncio.get_event_loop().run_in_executor(
        None, yara_scanner.scan, raw
    ) if yara_scanner.is_ready() else None

    # 2b) Yerel hash veritabanına bak (hızlı yol ~1ms)
    if pg_pool:
        known = await pg_pool.fetchrow(
            "SELECT name, threat_type, risk_score FROM malware_hashes WHERE sha256=$1",
            file_hash
        )
        if known:
            vt   = (await vt_task)   if vt_task   else None
            yara = (await yara_task) if yara_task else []
            import json as _json
            db_result = {
                "threat_type":    known["threat_type"],
                "risk_score":     known["risk_score"],
                "confidence":     1.0,
                "is_malware":     True,
                "verdict":        "malicious",
                "label":          known["name"],
                "method":         "hash_lookup",
                "categorized":    True,
                "vt":             vt,
                "yara_matches":   yara,
            }
            try:
                await pg_pool.execute(
                    """INSERT INTO file_scans
                       (agent_id, file_name, file_hash, file_size,
                        threat_type, risk_score, confidence, is_malware, ts,
                        vt_positives, vt_total, vt_label, vt_permalink, yara_matches)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                       ON CONFLICT DO NOTHING""",
                    req.agent_id, file_name, file_hash, file_size,
                    known["threat_type"], known["risk_score"], 1.0, True, ts,
                    vt.get("positives") if vt else None,
                    vt.get("total")     if vt else None,
                    vt.get("label")     if vt else None,
                    vt.get("permalink") if vt else None,
                    _json.dumps(yara) if yara else None,
                )
            except Exception:
                pass
            print(f"[HASH-HIT] {file_name} | {known['name']} | score:{known['risk_score']}")
            await create_alert(
                event_id=None, agent_id=req.agent_id, ts=ts,
                risk_score=float(known["risk_score"]), threat_type=known["threat_type"],
                confidence=1.0, pname=file_name, pid=0,
                rule_name=f"HashDB:{known['name']}", dedup_window=3600
            )
            # Otomatik karantina — hash eslesmesi, skor >= ACTION_THRESHOLD
            if float(known['risk_score']) >= ACTION_THRESHOLD and req.file_path:
                asyncio.create_task(trigger_action(
                    req.agent_id, known['threat_type'],
                    {'exe_path': req.file_path, 'pid': 0},
                    float(known['risk_score'])
                ))
            return {**db_result, "file_hash": file_hash, "file_size": file_size, "recorded": True}

    # 3) VT + YARA sonucu al
    import json as _json
    vt   = (await vt_task)   if vt_task   else None
    yara = (await yara_task) if yara_task else []

    # 3a) YARA eşleşmesi varsa hızlı sonuç
    if yara:
        top = max(yara, key=lambda x: x["score"])
        yara_score = float(top["score"])
        if yara_score >= 70:
            if pg_pool:
                try:
                    await pg_pool.execute(
                        """INSERT INTO file_scans
                           (agent_id, file_name, file_hash, file_size,
                            threat_type, risk_score, confidence, is_malware, ts,
                            vt_positives, vt_total, vt_label, vt_permalink, yara_matches)
                           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                           ON CONFLICT DO NOTHING""",
                        req.agent_id, file_name, file_hash, file_size,
                        top["rule"], yara_score, 0.9, True, ts,
                        vt.get("positives") if vt else None,
                        vt.get("total")     if vt else None,
                        vt.get("label")     if vt else None,
                        vt.get("permalink") if vt else None,
                        _json.dumps(yara),
                    )
                except Exception:
                    pass
            await create_alert(
                event_id=None, agent_id=req.agent_id, ts=ts,
                risk_score=yara_score, threat_type=top["rule"],
                confidence=0.9, pname=req.file_path or file_name, pid=0,
                rule_name=f"YARA:{top['rule']}", dedup_window=3600,
            )
            print(f"[YARA-HIT] {file_name} | {top['rule']} | score:{yara_score}")
            # Otomatik karantina — YARA eslesmesi
            if yara_score >= ACTION_THRESHOLD and req.file_path:
                asyncio.create_task(trigger_action(
                    req.agent_id, top['rule'],
                    {'exe_path': req.file_path, 'pid': 0},
                    yara_score
                ))
            return {
                "verdict":      "malicious",
                "is_malware":   True,
                "threat_type":  top["rule"],
                "risk_score":   yara_score,
                "confidence":   0.9,
                "method":       "yara",
                "categorized":  True,
                "file_hash":    file_hash,
                "file_size":    file_size,
                "recorded":     True,
                "yara_matches": yara,
                "vt":           vt,
            }

    # 3b) VT eşleşmesi
    if vt and vt.get("found") and vt["positives"] >= VT_MIN_POSITIVES:
        # Skor formülü: 60 (taban) + her tespit eden motor için +3 puan
        # 5 motor  → 60+15 = 75  (alert, aksiyon yok)
        # 10 motor → 60+30 = 90  (alert + otomatik karantina)
        # 14 motor → 60+42 = 100 (maksimum)
        # Ayrıca tespit oranı yüksekse bonus: positives/total > 0.5 → +5
        ratio_bonus = 5.0 if (vt["total"] > 0 and vt["positives"] / vt["total"] > 0.5) else 0.0
        risk = min(100.0, 60.0 + vt["positives"] * 3.0 + ratio_bonus)

        if pg_pool:
            try:
                await pg_pool.execute(
                    """INSERT INTO file_scans
                       (agent_id, file_name, file_hash, file_size,
                        threat_type, risk_score, confidence, is_malware, ts,
                        vt_positives, vt_total, vt_label, vt_permalink, yara_matches)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                       ON CONFLICT DO NOTHING""",
                    req.agent_id, file_name, file_hash, file_size,
                    vt["label"] or "malicious", risk, 0.95, True, ts,
                    vt["positives"], vt["total"], vt["label"], vt["permalink"],
                    _json.dumps(yara) if yara else None,
                )
            except Exception:
                pass
        await create_alert(
            event_id=None, agent_id=req.agent_id, ts=ts,
            risk_score=risk, threat_type=vt["label"] or "malicious",
            confidence=0.95, pname=file_name, pid=0,
            rule_name=f"VirusTotal:{vt['positives']}/{vt['total']}", dedup_window=3600,
        )
        print(f"[VT-HIT] {file_name} | {vt['positives']}/{vt['total']} | {vt['label']}")
        # Otomatik karantina — VirusTotal eslesmesi
        if risk >= ACTION_THRESHOLD and req.file_path:
            asyncio.create_task(trigger_action(
                req.agent_id, vt['label'] or 'malicious',
                {'exe_path': req.file_path, 'pid': 0},
                risk
            ))
        return {
            "verdict":      "malicious",
            "is_malware":   True,
            "threat_type":  vt["label"] or "malicious",
            "risk_score":   risk,
            "confidence":   0.95,
            "method":       "virustotal",
            "categorized":  True,
            "file_hash":    file_hash,
            "file_size":    file_size,
            "recorded":     True,
            "yara_matches": yara,
            "vt":           vt,
        }

    # 4) Binary triage (Aşama 1)
    if not binary_analyzer.is_ready():
        raise HTTPException(503, "Binary model henüz yüklenmedi.")

    binary_result = binary_analyzer.predict_from_base64(req.exe_b64)
    if "error" in binary_result:
        raise HTTPException(422, binary_result["error"])

    # Temiz dosya — hızlı dönüş
    if not binary_result["is_malware"]:
        if pg_pool:
            try:
                await pg_pool.execute(
                    """INSERT INTO file_scans
                       (agent_id, file_name, file_hash, file_size,
                        threat_type, risk_score, confidence, is_malware, ts,
                        vt_positives, vt_total, vt_label, vt_permalink)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                    req.agent_id, file_name, file_hash, file_size,
                    "benign",
                    round((1.0 - binary_result["malware_probability"]) * 100, 2),
                    binary_result["confidence"], False, ts,
                    vt.get("positives") if vt else None,
                    vt.get("total")     if vt else None,
                    vt.get("label")     if vt else None,
                    vt.get("permalink") if vt else None,
                )
            except Exception:
                pass
        return {
            **binary_result,
            "threat_type": "benign",
            "risk_score":  round((1.0 - binary_result["malware_probability"]) * 100, 2),
            "scores":      {"benign": round(1.0 - binary_result["malware_probability"], 4),
                           "malicious": binary_result["malware_probability"]},
            "categorized": False,
            "file_hash":   file_hash,
            "file_size":   file_size,
            "recorded":    True,
            "vt":          vt,
        }

    # 4) Zararlı bulundu
    #    categorize=False ise binary sonucu hemen dönülür, kategorize edilmez
    if not req.categorize:
        if pg_pool:
            try:
                await pg_pool.execute(
                    """INSERT INTO file_scans
                       (agent_id, file_name, file_hash, file_size,
                        threat_type, risk_score, confidence, is_malware, ts,
                        vt_positives, vt_total, vt_label, vt_permalink)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                    req.agent_id, file_name, file_hash, file_size,
                    "malicious",
                    round(binary_result["malware_probability"] * 100, 2),
                    binary_result["confidence"], True, ts,
                    vt.get("positives") if vt else None,
                    vt.get("total")     if vt else None,
                    vt.get("label")     if vt else None,
                    vt.get("permalink") if vt else None,
                )
            except Exception:
                pass
        await create_alert(
            event_id=None, agent_id=req.agent_id, ts=ts,
            risk_score=round(binary_result["malware_probability"] * 100, 2),
            threat_type="malicious",
            confidence=binary_result["confidence"],
            pname=req.file_path or file_name, pid=0,
            rule_name=("AutoScan:BinaryTriage" if req.source == "auto_scan" else "BinaryTriage"),
            dedup_window=3600
        )
        # Otomatik karantina — Binary CNN zararlı tespiti
        _bin_score = round(binary_result['malware_probability'] * 100, 2)
        if _bin_score >= ACTION_THRESHOLD and req.file_path:
            asyncio.create_task(trigger_action(
                req.agent_id, 'malicious',
                {'exe_path': req.file_path, 'pid': 0},
                _bin_score
            ))
        return {
            **binary_result,
            "threat_type":  "malicious",
            "risk_score":   round(binary_result["malware_probability"] * 100, 2),
            "categorized":  False,
            "file_hash":    file_hash,
            "file_size":    file_size,
            "recorded":     True,
            "vt":           vt,
        }

    # 5) categorize=True — multiclass CNN ile detaylı kategori tahmini (Aşama 2)
    if not static_analyzer.is_ready():
        # Multiclass model yoksa binary sonuçla devam et
        return {
            **binary_result,
            "threat_type": "malicious",
            "risk_score":  round(binary_result["malware_probability"] * 100, 2),
            "categorized": False,
            "file_hash":   file_hash,
            "file_size":   file_size,
            "recorded":    True,
            "note":        "Multiclass model yüklü değil.",
        }

    cat_result = static_analyzer.predict_from_base64(req.exe_b64)
    if "error" in cat_result:
        raise HTTPException(422, cat_result["error"])

    is_malware    = cat_result["risk_score"] >= ALERT_THRESHOLD
    final_result  = {
        **cat_result,
        "verdict":        binary_result["verdict"],
        "malware_probability": binary_result["malware_probability"],
        "categorized":    True,
        "method":         "binary_triage+multiclass",
        "file_hash":      file_hash,
        "file_size":      file_size,
        "recorded":       True,
    }

    # 6) DB'ye kaydet
    if pg_pool:
        try:
            await pg_pool.execute(
                """INSERT INTO file_scans
                   (agent_id, file_name, file_hash, file_size,
                    threat_type, risk_score, confidence, is_malware, ts)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)""",
                req.agent_id, file_name, file_hash, file_size,
                cat_result["threat_type"], cat_result["risk_score"],
                cat_result["confidence"], is_malware, ts,
            )
        except Exception:
            pass

    # 7) Zararlıysa hash DB'ye öğrenme döngüsü
    if is_malware and pg_pool:
        try:
            await pg_pool.execute(
                """INSERT INTO malware_hashes (sha256, name, threat_type, risk_score, source, notes)
                   VALUES ($1, $2, $3, $4, 'cnn_detection', $5)
                   ON CONFLICT (sha256) DO NOTHING""",
                file_hash, file_name, cat_result["threat_type"], cat_result["risk_score"],
                f"CNN confidence:{cat_result['confidence']:.2f}"
            )
        except Exception:
            pass
        await create_alert(
            event_id=None, agent_id=req.agent_id, ts=ts,
            risk_score=float(cat_result["risk_score"]), threat_type=cat_result["threat_type"],
            confidence=float(cat_result["confidence"]),
            pname=req.file_path or file_name, pid=0,
            rule_name=("AutoScan:MulticlassCNN" if req.source == "auto_scan" else "BinaryTriage+MulticlassCNN"),
            dedup_window=3600
        )
        # Otomatik karantina — Multiclass CNN zararlı tespiti
        if float(cat_result['risk_score']) >= ACTION_THRESHOLD and req.file_path:
            asyncio.create_task(trigger_action(
                req.agent_id, cat_result['threat_type'],
                {'exe_path': req.file_path, 'pid': 0},
                float(cat_result['risk_score'])
            ))

    return final_result


@app.post("/calibrate/{agent_id}")
async def calibrate(agent_id: str):
    """Belirli bir ajan için Isolation Forest modelini (yeniden) eğitir."""
    baseline = await get_baseline(agent_id)
    if not baseline:
        baseline = {}

    metrics_data = []
    if pg_pool:
        since = int(time.time()) - 3600
        rows = await pg_pool.fetch(
            """SELECT (raw->>'cpu_percent')::float as cpu, 
                      (raw->>'ram_percent')::float as ram
               FROM events 
               WHERE agent_id = $1 AND type = 'metrics' AND ts > $2""",
            agent_id, since
        )
        for r in rows:
            try:
                cpu = r["cpu"] if r["cpu"] is not None else 0.0
                ram = r["ram"] if r["ram"] is not None else 0.0
                metrics_data.append({"cpu_percent": cpu, "ram_percent": ram})
            except Exception:
                continue

    ok = behavioral_analyzer.train_with_data(agent_id, baseline, metrics_data)
    return {"success": ok, "agent_id": agent_id, "data_points_used": len(metrics_data)}

@app.post("/calibrate/{agent_id}/control")
async def control_calibration(agent_id: str, req: CalibrationStateReq):
    """Frontend üzerinden kalibrasyonu manuel başlat/bitir/sıfırla."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    ts = int(time.time())
    if req.action == "start":
        await pg_pool.execute("UPDATE agent_baseline SET calibrated = FALSE, calib_start = $1 WHERE agent_id = $2", ts, agent_id)
        return {"agent_id": agent_id, "status": "learning_started"}
    elif req.action == "stop":
        baseline = await get_baseline(agent_id)
        if not baseline: baseline = {}
        calib_start = baseline.get("calib_start") or (ts - 3600)
        if calib_start == 0: calib_start = ts - 3600
        metrics_data = []
        rows = await pg_pool.fetch("SELECT (raw->>'cpu_percent')::float as cpu, (raw->>'ram_percent')::float as ram FROM events WHERE agent_id = $1 AND type = 'metrics' AND ts >= $2", agent_id, calib_start)
        for r in rows:
            try: metrics_data.append({"cpu_percent": r["cpu"] or 0.0, "ram_percent": r["ram"] or 0.0})
            except Exception: continue
        ok = behavioral_analyzer.train_with_data(agent_id, baseline, metrics_data)
        await pg_pool.execute("UPDATE agent_baseline SET calibrated = TRUE, calib_end = $1 WHERE agent_id = $2", ts, agent_id)
        return {"agent_id": agent_id, "status": "learning_stopped", "model_trained": ok, "data_points": len(metrics_data)}
    elif req.action == "reset":
        await pg_pool.execute("UPDATE agent_baseline SET calibrated = FALSE, calib_start = 0, calib_end = 0, cpu_mean = 0, cpu_std = 0, ram_mean = 0, ram_std = 0, avg_connections = 0, known_processes = '{}'::jsonb, known_ips = '{}'::jsonb WHERE agent_id = $1", agent_id)
        model_path = behavioral_analyzer._path(agent_id)
        if model_path.exists(): model_path.unlink()
        if agent_id in behavioral_analyzer._models: del behavioral_analyzer._models[agent_id]
        return {"agent_id": agent_id, "status": "reset_completed"}
    raise HTTPException(400, "Geçersiz aksiyon")


@app.get("/baseline/{agent_id}")
async def get_baseline_api(agent_id: str):
    b = await get_baseline(agent_id)
    if not b:
        raise HTTPException(404, f"Agent bulunamadı: {agent_id}")
    return b


@app.get("/vt/lookup/{sha256}")
async def vt_lookup_endpoint(sha256: str):
    """Verilen SHA-256 hash'i VirusTotal'da sorgular."""
    if not VT_API_KEY:
        raise HTTPException(503, "VT_API_KEY yapılandırılmamış. Ortam değişkenini ayarlayın.")
    result = await vt_lookup_hash(sha256)
    if result is None:
        raise HTTPException(503, "VirusTotal API'sine ulaşılamadı.")
    return result


@app.post("/yara/reload")
async def yara_reload():
    """YARA kurallarını yeniden yükler (hot-reload, servis yeniden başlatma gerekmez)."""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, yara_scanner.reload)
    return {
        "reloaded":   True,
        "ready":      yara_scanner.is_ready(),
        "rule_count": yara_scanner.rule_count,
    }


@app.get("/yara/rules")
async def list_yara_rules():
    """YARA kural dosyalarındaki kuralların listesini döndürür."""
    import re
    result = []
    for f in sorted(YARA_DIR.glob("*.yar")):
        try:
            content = f.read_text(encoding="utf-8")
            # rule adı ve meta'yı çıkar
            parsed = []
            for m in re.finditer(
                r'rule\s+(\w+)\s*(?:\{[^}]*meta\s*:(.*?)(?:strings:|condition:|(?=rule\s|\Z)))?',
                content, re.DOTALL
            ):
                name = m.group(1)
                meta_block = m.group(2) or ""
                desc_m = re.search(r'description\s*=\s*"([^"]*)"', meta_block)
                sev_m  = re.search(r'severity\s*=\s*"([^"]*)"',  meta_block)
                score_m= re.search(r'score\s*=\s*(\d+)',          meta_block)
                parsed.append({
                    "name":        name,
                    "description": desc_m.group(1)  if desc_m  else "",
                    "severity":    sev_m.group(1)   if sev_m   else "medium",
                    "score":       int(score_m.group(1)) if score_m else 70,
                })
            result.append({
                "file":       f.name,
                "editable":   f.name == "custom_rules.yar",
                "rule_count": len(parsed),
                "rules":      parsed,
                "size":       f.stat().st_size,
            })
        except Exception as e:
            result.append({"file": f.name, "error": str(e), "rules": [], "rule_count": 0})
    return result


class YaraRuleSaveRequest(BaseModel):
    content: str  # Tam .yar dosyası içeriği


@app.post("/yara/rules/save")
async def save_yara_rules(req: YaraRuleSaveRequest):
    """
    Özel YARA kurallarını custom_rules.yar dosyasına kaydeder
    ve ardından tarayıcıyı otomatik yeniden yükler.
    """
    import re
    target = YARA_DIR / "custom_rules.yar"
    try:
        target.write_text(req.content, encoding="utf-8")
    except Exception as e:
        raise HTTPException(500, f"Dosya yazma hatası: {e}")

    # Hot-reload
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, yara_scanner.reload)

    return {
        "saved":      True,
        "file":       str(target),
        "ready":      yara_scanner.is_ready(),
        "rule_count": yara_scanner.rule_count,
    }


@app.post("/yara/rules/upload")
async def upload_yara_file(file: UploadFile):
    """
    Yeni bir .yar/.yara dosyası yükler ve tarayıcıyı yeniden başlatır.
    Yalnızca .yar ve .yara uzantılı dosyalar kabul edilir.
    """
    from pathlib import Path as _Path

    if not file.filename:
        raise HTTPException(400, "Dosya adı boş.")
    ext = _Path(file.filename).suffix.lower()
    if ext not in (".yar", ".yara"):
        raise HTTPException(400, "Yalnızca .yar ve .yara uzantılı dosyalar kabul edilir.")

    content = await file.read()
    try:
        content.decode("utf-8")  # encoding kontrolü
    except Exception:
        raise HTTPException(400, "Dosya UTF-8 formatında olmalıdır.")

    target = YARA_DIR / file.filename
    target.write_bytes(content)

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, yara_scanner.reload)

    return {
        "uploaded":   True,
        "file":       file.filename,
        "size":       len(content),
        "ready":      yara_scanner.is_ready(),
        "rule_count": yara_scanner.rule_count,
    }


class YaraToggleRequest(BaseModel):
    filename: str


@app.post("/yara/rules/toggle")
async def toggle_yara_file(req: YaraToggleRequest):
    """
    Kural dosyasını etkinleştirir / devre dışı bırakır.
    disabled.json'u günceller ve tarayıcıyı yeniden yükler.
    """
    # Sadece var olan dosyaları kabul et
    candidates = list(YARA_DIR.glob("*.yar")) + list(YARA_DIR.glob("*.yara"))
    if not any(f.name == req.filename for f in candidates):
        raise HTTPException(404, f"Kural dosyası bulunamadı: {req.filename}")

    loop   = asyncio.get_event_loop()
    active = await loop.run_in_executor(None, yara_scanner.toggle_file, req.filename)

    return {
        "filename": req.filename,
        "active":   active,
        "ready":    yara_scanner.is_ready(),
        "rule_count": yara_scanner.rule_count,
    }


# /yara/status endpoint'ini genişlet — bireysel kural sayısını da döndür
@app.get("/yara/status")
async def yara_status_extended():
    """YARA tarayıcısının detaylı durumunu döndürür."""
    import re
    from pathlib import Path as _Path

    disabled = yara_scanner.disabled_files()

    total_rules = 0
    for f in YARA_DIR.glob("*.yar"):
        if f.name in disabled:
            continue
        try:
            content = f.read_text(encoding="utf-8")
            total_rules += len(re.findall(r'^\s*rule\s+\w+', content, re.MULTILINE))
        except Exception:
            pass

    return {
        "ready":           yara_scanner.is_ready(),
        "file_count":      yara_scanner.rule_count,   # aktif dosya sayısı
        "rule_count":      total_rules,                # bireysel kural sayısı
        "disabled_files":  list(disabled),
        "vt_enabled":      bool(VT_API_KEY),
        "vt_min_positives": VT_MIN_POSITIVES,
    }


@app.get("/scans")
async def list_scans(limit: int = 100, malware_only: bool = False):
    """Dosya tarama geçmişini döndürür."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    q = "SELECT * FROM file_scans"
    if malware_only:
        q += " WHERE is_malware = TRUE"
    q += f" ORDER BY ts DESC LIMIT {min(limit, 500)}"
    rows = await pg_pool.fetch(q)
    return [dict(r) for r in rows]


@app.get("/alerts")
async def list_alerts(limit: int = 50, unresolved_only: bool = True):
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    q = "SELECT * FROM alerts"
    if unresolved_only:
        q += " WHERE resolved = FALSE"
    q += f" ORDER BY ts DESC LIMIT {min(limit, 200)}"
    rows = await pg_pool.fetch(q)
    return [dict(r) for r in rows]


@app.patch("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, req: AlertResolveRequest):
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    res = await pg_pool.execute(
        "UPDATE alerts SET resolved = TRUE, notes = $1 WHERE id = $2",
        req.notes, alert_id,
    )
    if res == "UPDATE 0":
        raise HTTPException(404, f"Alert bulunamadı: {alert_id}")
    return {"resolved": True, "alert_id": alert_id}


@app.get("/agents")
async def list_agents():
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    rows = await pg_pool.fetch("SELECT * FROM agent_baseline ORDER BY updated_at DESC")
    return [dict(r) for r in rows]


@app.get("/process-tree/{agent_id}/{pid}")
async def get_process_tree(agent_id: str, pid: int):
    """
    Belirli bir PID için soy ağacını döndürür.
    events tablosundan ppid zincirini takip eder.
    """
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")

    tree = []
    current_pid = pid
    visited = set()

    while current_pid > 0 and current_pid not in visited:
        visited.add(current_pid)
        row = await pg_pool.fetchrow(
            """SELECT raw->>'pname' as pname,
                      (raw->>'pid')::int  as pid,
                      (raw->>'ppid')::int as ppid,
                      raw->>'exe_path'    as exe_path,
                      raw->>'username'    as username,
                      raw->>'cmdline'     as cmdline,
                      ts
               FROM events
               WHERE agent_id = $1 AND type = 'process_new'
                 AND (raw->>'pid')::int = $2
               ORDER BY ts DESC LIMIT 1""",
            agent_id, current_pid
        )
        if not row:
            break
        tree.insert(0, dict(row))   # en üste ekle (root önce)
        ppid = row['ppid'] or 0
        if ppid == 0 or ppid == current_pid:
            break
        current_pid = ppid

    return {"pid": pid, "agent_id": agent_id, "tree": tree}


@app.get("/stats/{agent_id}")
async def get_agent_stats(agent_id: str, hours: int = 24):
    """Ajan için son N saatin istatistiklerini döndürür."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    since = int(time.time()) - hours * 3600
    rows = await pg_pool.fetch(
        """SELECT type, COUNT(*) as cnt
           FROM events
           WHERE agent_id = $1 AND ts > $2
           GROUP BY type""",
        agent_id, since
    )
    alert_rows = await pg_pool.fetch(
        """SELECT threat_type, COUNT(*) as cnt
           FROM alerts
           WHERE agent_id = $1 AND ts > $2
           GROUP BY threat_type ORDER BY cnt DESC LIMIT 10""",
        agent_id, since
    )
    return {
        "event_counts": [dict(r) for r in rows],
        "alert_by_type": [dict(r) for r in alert_rows],
    }


@app.get("/metrics/latest")
async def get_latest_metrics():
    """
    Her ajan için en son metrics event'inden cpu/ram çeker.
    Frontend CPU/RAM grafiği için bu endpoint'i kullanır.
    """
    if not pg_pool:
        return []
    rows = await pg_pool.fetch(
        """SELECT DISTINCT ON (agent_id)
               agent_id,
               ts,
               (raw->>'cpu_percent')::float                AS cpu,
               COALESCE((raw->>'ram_used_kb')::bigint,
                        (raw->>'ram_used')::bigint,  0)    AS ram_used,
               COALESCE((raw->>'ram_total_kb')::bigint,
                        (raw->>'ram_total')::bigint, 1)    AS ram_total
           FROM events
           WHERE type = 'metrics'
             AND raw->>'cpu_percent' IS NOT NULL
           ORDER BY agent_id, ts DESC"""
    )
    result = []
    for r in rows:
        ram_total = r["ram_total"] or 1
        ram_pct = round(r["ram_used"] / ram_total * 100, 1) if ram_total > 0 else 0.0
        result.append({
            "agent_id": r["agent_id"],
            "ts":       r["ts"],
            "cpu":      round(r["cpu"] or 0, 1),
            "ram_pct":  ram_pct,
        })
    return result


# ══════════════════════════════════════════════════════════════════════════════
# KQL KURAL MOTORU
# ══════════════════════════════════════════════════════════════════════════════
#
# Desteklenen sözdizimi:
#   process.name = "mimikatz.exe"
#   process.name contains "mimi"
#   process.name matches ".*dump.*"       (regex)
#   network.port = 4444
#   network.remote_ip = "1.2.3.4"
#   event.type = "process_new"
#   process.cmdline contains "powershell" AND process.cmdline contains "-enc"
#   process.name = "cmd.exe" OR process.name = "powershell.exe"
#
# Alan → event JSON anahtarı eşlemesi:
FIELD_MAP = {
    "process.name":      "pname",
    "process.cmdline":   "cmdline",
    "process.exe":       "exe_path",
    "process.pid":       "pid",
    "process.ppid":      "ppid",
    "process.user":      "username",
    "network.port":      "remote_port",
    "network.remote_ip": "remote_ip",
    "network.local_ip":  "local_ip",
    "event.type":        "type",
    "event.agent":       "agent_id",
    "file.path":         "exe_path",
    "cpu.percent":       "cpu_percent",
}


def _get_field(event: dict, field: str) -> str | None:
    key = FIELD_MAP.get(field, field)
    val = event.get(key)
    return str(val).lower() if val is not None else None


def _eval_condition(event: dict, cond: str) -> bool:
    """Tek bir koşulu değerlendirir."""
    cond = cond.strip()

    # contains
    m = re.match(r'([\w.]+)\s+contains\s+"([^"]*)"', cond, re.I)
    if m:
        val = _get_field(event, m.group(1))
        return val is not None and m.group(2).lower() in val

    # matches (regex)
    m = re.match(r'([\w.]+)\s+matches\s+"([^"]*)"', cond, re.I)
    if m:
        val = _get_field(event, m.group(1))
        return val is not None and bool(re.search(m.group(2), val, re.I))

    # = (eşitlik)
    m = re.match(r'([\w.]+)\s*=\s*"([^"]*)"', cond, re.I)
    if m:
        val = _get_field(event, m.group(1))
        return val is not None and val == m.group(2).lower()

    # sayısal =
    m = re.match(r'([\w.]+)\s*=\s*(\d+)', cond, re.I)
    if m:
        val = _get_field(event, m.group(1))
        return val is not None and val == m.group(2)

    # > < sayısal
    m = re.match(r'([\w.]+)\s*([><]=?)\s*(\d+)', cond, re.I)
    if m:
        val = _get_field(event, m.group(1))
        try:
            v = float(val or 0)
            t = float(m.group(3))
            op = m.group(2)
            return (op == ">" and v > t) or (op == ">=" and v >= t) or \
                   (op == "<" and v < t) or (op == "<=" and v <= t)
        except Exception:
            return False

    return False


def evaluate_kql(rule_text: str, event: dict) -> bool:
    """AND / OR destekli KQL kuralını değerlendirir."""
    # OR'a göre böl
    or_parts = re.split(r'\bOR\b', rule_text, flags=re.I)
    for or_part in or_parts:
        # AND'a göre böl
        and_parts = re.split(r'\bAND\b', or_part, flags=re.I)
        if all(_eval_condition(event, c) for c in and_parts):
            return True
    return False


# ── Kural cache yönetimi ──────────────────────────────────────────────────────

async def load_custom_rules() -> list[dict]:
    global _custom_rules, _rules_loaded_at
    now = time.time()
    if now - _rules_loaded_at < RULES_TTL:
        return _custom_rules
    if not pg_pool:
        return []
    rows = await pg_pool.fetch(
        "SELECT id, name, rule_text, threat_type, score FROM detection_rules WHERE enabled = TRUE"
    )
    _custom_rules = [dict(r) for r in rows]
    _rules_loaded_at = now
    return _custom_rules


async def apply_custom_rules(event: dict) -> dict | None:
    """Event'e uyan ilk etkin kuralı döndürür."""
    rules = await load_custom_rules()
    best = None
    for rule in rules:
        try:
            if evaluate_kql(rule["rule_text"], event):
                if best is None or rule["score"] > best["score"]:
                    best = rule
        except Exception:
            pass
    return best


# ── CRUD Endpoint'leri ────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    name:        str
    description: str  = ""
    rule_text:   str
    threat_type: str  = "custom"
    score:       float = 80.0
    enabled:     bool  = True


class RuleUpdate(BaseModel):
    name:        Optional[str]   = None
    description: Optional[str]   = None
    rule_text:   Optional[str]   = None
    threat_type: Optional[str]   = None
    score:       Optional[float] = None
    enabled:     Optional[bool]  = None


@app.get("/rules")
async def list_rules():
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    rows = await pg_pool.fetch("SELECT * FROM detection_rules ORDER BY id DESC")
    return [dict(r) for r in rows]


@app.post("/rules", status_code=201)
async def create_rule(req: RuleCreate):
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    # Sözdizimi kontrolü
    try:
        evaluate_kql(req.rule_text, {})
    except Exception as e:
        raise HTTPException(400, f"Kural sözdizimi hatası: {e}")
    now = int(time.time())
    row = await pg_pool.fetchrow(
        """INSERT INTO detection_rules
               (name, description, rule_text, threat_type, score, enabled, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
           RETURNING *""",
        req.name, req.description, req.rule_text,
        req.threat_type, req.score, req.enabled, now,
    )
    global _rules_loaded_at
    _rules_loaded_at = 0  # cache'i geçersiz kıl
    return dict(row)


@app.patch("/rules/{rule_id}")
async def update_rule(rule_id: int, req: RuleUpdate):
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    row = await pg_pool.fetchrow("SELECT * FROM detection_rules WHERE id=$1", rule_id)
    if not row:
        raise HTTPException(404, f"Kural bulunamadı: {rule_id}")
    updated = dict(row)
    for field in ("name", "description", "rule_text", "threat_type", "score", "enabled"):
        val = getattr(req, field)
        if val is not None:
            updated[field] = val
    updated["updated_at"] = int(time.time())
    await pg_pool.execute(
        """UPDATE detection_rules SET
               name=$1, description=$2, rule_text=$3, threat_type=$4,
               score=$5, enabled=$6, updated_at=$7
           WHERE id=$8""",
        updated["name"], updated["description"], updated["rule_text"],
        updated["threat_type"], updated["score"], updated["enabled"],
        updated["updated_at"], rule_id,
    )
    global _rules_loaded_at
    _rules_loaded_at = 0
    return {**updated, "id": rule_id}


@app.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int):
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    res = await pg_pool.execute("DELETE FROM detection_rules WHERE id=$1", rule_id)
    if res == "DELETE 0":
        raise HTTPException(404, f"Kural bulunamadı: {rule_id}")
    global _rules_loaded_at
    _rules_loaded_at = 0
    return {"deleted": True, "rule_id": rule_id}


@app.post("/rules/{rule_id}/test")
async def test_rule(rule_id: int, event: dict):
    """Bir kuralı verilen event üzerinde test et."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    row = await pg_pool.fetchrow("SELECT * FROM detection_rules WHERE id=$1", rule_id)
    if not row:
        raise HTTPException(404, f"Kural bulunamadı: {rule_id}")
    rule = dict(row)
    matched = evaluate_kql(rule["rule_text"], event)
    return {"matched": matched, "rule": rule["name"], "event_keys": list(event.keys())}


# ── Baseline Persistence ──────────────────────────────────────────────────────

async def _load_baselines_from_db(pool: asyncpg.Pool) -> None:
    """Uygulama başlangıcında DB'deki baseline'ları behavioral_analyzer'a yükler."""
    try:
        rows = await pool.fetch(
            "SELECT agent_id, calibrated FROM agent_baseline WHERE calibrated = TRUE"
        )
        loaded = 0
        for row in rows:
            agent_id = row["agent_id"]
            # BehavioralAnalyzer'ın kendi model dosyasından (.pkl) yükleme
            if behavioral_analyzer.load(agent_id):
                loaded += 1
        if loaded:
            print(f"[+] AI Servis: {loaded} ajan IsolationForest modeli disk'ten yüklendi.")
    except Exception as e:
        print(f"[!] Baseline yükleme hatası (tablolar henüz yok olabilir): {e}")


# ── Threat Intel — Malware Hash Veritabanı ────────────────────────────────────

class HashAddRequest(BaseModel):
    sha256:      str
    name:        str = "Unknown"
    threat_type: str = "malware"
    risk_score:  float = 90.0
    source:      str = "manual"
    notes:       Optional[str] = None


@app.get("/threat-intel/hashes")
async def list_hashes(
    limit: int = Query(200, le=1000),
    source: Optional[str] = None,
    threat_type: Optional[str] = None,
):
    """Bilinen zararlı hash'leri listeler."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    q = "SELECT * FROM malware_hashes"
    filters = []
    params: list[Any] = []
    if source:
        params.append(source)
        filters.append(f"source = ${len(params)}")
    if threat_type:
        params.append(threat_type)
        filters.append(f"threat_type = ${len(params)}")
    if filters:
        q += " WHERE " + " AND ".join(filters)
    q += f" ORDER BY added_at DESC LIMIT {min(limit, 1000)}"
    rows = await pg_pool.fetch(q, *params)
    return [dict(r) for r in rows]


@app.post("/threat-intel/hashes", status_code=201)
async def add_hash(req: HashAddRequest):
    """Yeni bir zararlı hash ekler veya mevcut kaydı günceller."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    sha256 = req.sha256.lower().strip()
    if len(sha256) != 64:
        raise HTTPException(400, "Geçersiz SHA-256 hash (64 hex karakter olmalı).")
    try:
        row = await pg_pool.fetchrow(
            """INSERT INTO malware_hashes (sha256, name, threat_type, risk_score, source, notes)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (sha256) DO UPDATE
                 SET name=EXCLUDED.name, threat_type=EXCLUDED.threat_type,
                     risk_score=EXCLUDED.risk_score, source=EXCLUDED.source,
                     notes=EXCLUDED.notes
               RETURNING *""",
            sha256, req.name, req.threat_type, req.risk_score, req.source, req.notes
        )
        return dict(row)
    except Exception as e:
        raise HTTPException(500, str(e))


@app.delete("/threat-intel/hashes/{sha256}")
async def delete_hash(sha256: str):
    """Bir hash kaydını siler."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    res = await pg_pool.execute(
        "DELETE FROM malware_hashes WHERE sha256=$1", sha256.lower().strip()
    )
    deleted = int(res.split()[-1])
    if not deleted:
        raise HTTPException(404, "Hash bulunamadı.")
    return {"deleted": True, "sha256": sha256}


@app.get("/threat-intel/hashes/lookup/{sha256}")
async def lookup_hash(sha256: str):
    """Tek bir hash'i sorgular."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    row = await pg_pool.fetchrow(
        "SELECT * FROM malware_hashes WHERE sha256=$1", sha256.lower().strip()
    )
    if not row:
        return {"found": False, "sha256": sha256}
    return {"found": True, **dict(row)}


@app.get("/threat-intel/stats")
async def threat_intel_stats():
    """Threat intel DB istatistiklerini döner."""
    if not pg_pool:
        raise HTTPException(503, "DB bağlantısı yok.")
    total = await pg_pool.fetchval("SELECT COUNT(*) FROM malware_hashes")
    by_type = await pg_pool.fetch(
        "SELECT threat_type, COUNT(*) as count FROM malware_hashes GROUP BY threat_type ORDER BY count DESC"
    )
    by_source = await pg_pool.fetch(
        "SELECT source, COUNT(*) as count FROM malware_hashes GROUP BY source ORDER BY count DESC"
    )
    return {
        "total_hashes": total,
        "by_threat_type": [dict(r) for r in by_type],
        "by_source": [dict(r) for r in by_source],
    }


# ══════════════════════════════════════════════════════════════════════════════
# BEATS SUMMARY — Wazuh tarzı modül özeti (Dashboard için)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/beats/summary")
async def beats_summary(hours: int = 24):
    """
    Son N saatin tüm beat istatistiklerini tek sorguda döner.
    Dashboard'daki XDR Beats kartları bu endpoint'i kullanır.
    """
    if not pg_pool:
        # DB yoksa boş ama geçerli yapı dön
        return {
            "process_beat":  {"total": 0, "last_hour": 0, "top_processes": [], "agents": []},
            "network_beat":  {"total": 0, "last_hour": 0, "top_ports": [], "agents": []},
            "file_beat":     {"total": 0, "last_hour": 0, "malware_count": 0, "agents": []},
            "alert_beat":    {"total": 0, "last_hour": 0, "critical": 0, "by_type": []},
            "system_beat":   {"agents": [], "avg_cpu": 0.0, "avg_ram": 0.0},
        }

    since_24h = int(time.time()) - hours * 3600
    since_1h  = int(time.time()) - 3600

    # ── Process Beat ──────────────────────────────────────────────────────────
    proc_total = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM events WHERE type IN ('process_new', 'ebpf_exec', 'etw_process_start') AND ts > $1", since_24h
    ) or 0
    proc_1h = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM events WHERE type IN ('process_new', 'ebpf_exec', 'etw_process_start') AND ts > $1", since_1h
    ) or 0
    proc_top = await pg_pool.fetch(
        """SELECT raw->>'pname' as pname, COUNT(*) as cnt
           FROM events WHERE type IN ('process_new', 'ebpf_exec', 'etw_process_start') AND ts > $1
           GROUP BY pname ORDER BY cnt DESC LIMIT 8""",
        since_24h
    )
    proc_agents = await pg_pool.fetch(
        """SELECT agent_id, COUNT(*) as cnt FROM events
           WHERE type IN ('process_new', 'ebpf_exec', 'etw_process_start') AND ts > $1
           GROUP BY agent_id ORDER BY cnt DESC LIMIT 5""",
        since_24h
    )

    # ── Network Beat ──────────────────────────────────────────────────────────
    net_total = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM events WHERE type='network_new' AND ts > $1", since_24h
    ) or 0
    net_1h = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM events WHERE type='network_new' AND ts > $1", since_1h
    ) or 0
    net_ports = await pg_pool.fetch(
        """SELECT (raw->>'remote_port')::int as port, COUNT(*) as cnt
           FROM events WHERE type='network_new' AND ts > $1
             AND raw->>'remote_port' IS NOT NULL
           GROUP BY port ORDER BY cnt DESC LIMIT 8""",
        since_24h
    )
    net_agents = await pg_pool.fetch(
        """SELECT agent_id, COUNT(*) as cnt FROM events
           WHERE type='network_new' AND ts > $1
           GROUP BY agent_id ORDER BY cnt DESC LIMIT 5""",
        since_24h
    )

    # ── File Integrity Beat ───────────────────────────────────────────────────
    file_total = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM file_scans WHERE ts > $1", since_24h
    ) or 0
    file_1h = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM file_scans WHERE ts > $1", since_1h
    ) or 0
    file_mal = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM file_scans WHERE is_malware=TRUE AND ts > $1", since_24h
    ) or 0
    file_agents = await pg_pool.fetch(
        """SELECT agent_id, COUNT(*) as cnt FROM file_scans
           WHERE ts > $1 GROUP BY agent_id ORDER BY cnt DESC LIMIT 5""",
        since_24h
    )

    # ── Alert Beat ────────────────────────────────────────────────────────────
    alert_total = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE ts > $1", since_24h
    ) or 0
    alert_1h = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE ts > $1", since_1h
    ) or 0
    alert_crit = await pg_pool.fetchval(
        "SELECT COUNT(*) FROM alerts WHERE risk_score >= 90 AND ts > $1", since_24h
    ) or 0
    alert_types = await pg_pool.fetch(
        """SELECT threat_type, COUNT(*) as cnt FROM alerts
           WHERE ts > $1 GROUP BY threat_type ORDER BY cnt DESC LIMIT 8""",
        since_24h
    )

    # ── System Beat ───────────────────────────────────────────────────────────
    sys_rows = await pg_pool.fetch(
        """SELECT DISTINCT ON (agent_id)
               agent_id,
               (raw->>'cpu_percent')::float as cpu,
               COALESCE((raw->>'ram_used_kb')::bigint, 0)  as ram_used,
               COALESCE((raw->>'ram_total_kb')::bigint, 1) as ram_total
           FROM events
           WHERE type='metrics' AND raw->>'cpu_percent' IS NOT NULL
           ORDER BY agent_id, ts DESC"""
    )
    sys_agents = []
    total_cpu = 0.0; total_ram = 0.0
    for r in sys_rows:
        ram_pct = round((r["ram_used"] / max(r["ram_total"], 1)) * 100, 1)
        sys_agents.append({
            "agent_id": r["agent_id"],
            "cpu": round(r["cpu"] or 0, 1),
            "ram_pct": ram_pct,
        })
        total_cpu += r["cpu"] or 0
        total_ram += ram_pct
    n = max(len(sys_agents), 1)

    return {
        "process_beat": {
            "total":         int(proc_total),
            "last_hour":     int(proc_1h),
            "top_processes": [{"name": r["pname"] or "?", "count": int(r["cnt"])} for r in proc_top],
            "agents":        [{"agent_id": r["agent_id"], "count": int(r["cnt"])} for r in proc_agents],
        },
        "network_beat": {
            "total":     int(net_total),
            "last_hour": int(net_1h),
            "top_ports": [{"port": r["port"], "count": int(r["cnt"])} for r in net_ports],
            "agents":    [{"agent_id": r["agent_id"], "count": int(r["cnt"])} for r in net_agents],
        },
        "file_beat": {
            "total":         int(file_total),
            "last_hour":     int(file_1h),
            "malware_count": int(file_mal),
            "agents":        [{"agent_id": r["agent_id"], "count": int(r["cnt"])} for r in file_agents],
        },
        "alert_beat": {
            "total":     int(alert_total),
            "last_hour": int(alert_1h),
            "critical":  int(alert_crit),
            "by_type":   [{"type": r["threat_type"], "count": int(r["cnt"])} for r in alert_types],
        },
        "system_beat": {
            "agents":  sys_agents,
            "avg_cpu": round(total_cpu / n, 1),
            "avg_ram": round(total_ram / n, 1),
        },
    }
