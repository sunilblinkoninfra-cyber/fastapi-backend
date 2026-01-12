from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Dict
from datetime import datetime, timedelta
import uvicorn, jwt, os, json, sqlite3, requests

# ===============================
# CONFIG
# ===============================
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key")
JWT_ALGO = "HS256"
TOKEN_EXPIRE_MINUTES = 60
DB_FILE = "soc_events.db"
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")

# ===============================
# APP
# ===============================
app = FastAPI(
    title="SOC Phishing Platform",
    version="4.2",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# ===============================
# HEALTH (FIX FOR RENDER / BROWSER)
# ===============================
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "SOC Phishing Platform",
        "message": "Backend is running"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

# ===============================
# DATABASE
# ===============================
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS soc_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        subject TEXT,
        verdict TEXT,
        tier TEXT,
        risk_score INTEGER,
        mitre_attack TEXT,
        yara_matches TEXT,
        attachments TEXT,
        source TEXT,
        status TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()

def save_event(event: Dict):
    conn = get_db()
    conn.execute("""
        INSERT INTO soc_events
        (timestamp, subject, verdict, tier, risk_score,
         mitre_attack, yara_matches, attachments, source, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"], event["subject"], event["verdict"],
        event["tier"], event["risk_score"],
        json.dumps(event["mitre_attack"]),
        json.dumps(event["yara_matches"]),
        json.dumps(event["attachments"]),
        event["source"], event["status"]
    ))
    conn.commit()
    conn.close()

def fetch_events():
    conn = get_db()
    rows = conn.execute("SELECT * FROM soc_events ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) | {
        "mitre_attack": json.loads(r["mitre_attack"]),
        "yara_matches": json.loads(r["yara_matches"]),
        "attachments": json.loads(r["attachments"])
    } for r in rows]

def fetch_metrics():
    conn = get_db()
    rows = conn.execute("SELECT tier, COUNT(*) c FROM soc_events GROUP BY tier").fetchall()
    conn.close()
    metrics = {"TOTAL": 0, "HOT": 0, "WARM": 0, "COLD": 0}
    for r in rows:
        metrics[r["tier"]] = r["c"]
        metrics["TOTAL"] += r["c"]
    return metrics

def update_status(event_id, status):
    conn = get_db()
    conn.execute("UPDATE soc_events SET status=? WHERE id=?", (status, event_id))
    conn.commit()
    conn.close()

# ===============================
# AUTH
# ===============================
def create_token():
    return jwt.encode(
        {"exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)},
        JWT_SECRET,
        algorithm=JWT_ALGO
    )

def verify_token(token: str):
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/token")
def token():
    return {"access_token": create_token(), "token_type": "bearer"}

# ===============================
# MODELS
# ===============================
class EmailRequest(BaseModel):
    subject: str
    body: str
    urls: List[str] = []

class StatusUpdate(BaseModel):
    status: str

# ===============================
# SCAN
# ===============================
KEYWORDS = ["urgent", "verify", "password", "login"]

@app.post("/scan")
def scan(email: EmailRequest, bg: BackgroundTasks, token: str = Depends(oauth2_scheme)):
    verify_token(token)
    score = min(sum(20 for k in KEYWORDS if k in (email.subject + email.body).lower()), 100)
    verdict, tier = ("PHISHING", "HOT") if score >= 70 else ("SAFE", "COLD")
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "subject": email.subject,
        "verdict": verdict,
        "tier": tier,
        "risk_score": score,
        "mitre_attack": [],
        "yara_matches": [],
        "attachments": [],
        "source": "json-scan",
        "status": "NEW"
    }
    save_event(event)
    return event

# ===============================
# SOC APIs
# ===============================
@app.get("/soc")
def soc(token: str = Depends(oauth2_scheme)):
    verify_token(token)
    return fetch_events()

@app.get("/soc-metrics")
def metrics(token: str = Depends(oauth2_scheme)):
    verify_token(token)
    return fetch_metrics()

@app.post("/soc/{event_id}/status")
def status(event_id: int, s: StatusUpdate, token: str = Depends(oauth2_scheme)):
    verify_token(token)
    update_status(event_id, s.status)
    return {"ok": True}

# ===============================
# DASHBOARD
# ===============================
@app.get("/soc-dashboard", response_class=HTMLResponse)
def dashboard():
    return """<h2>SOC Dashboard Loaded</h2>"""

# ===============================
# RUN (LOCAL ONLY)
# ===============================
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000)

