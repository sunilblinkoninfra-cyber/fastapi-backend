from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
import jwt
import os

print(">>> RUNNING app.py <<<")

# ===============================
# CONFIG
# ===============================
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key")
JWT_ALGO = "HS256"
TOKEN_EXPIRE_MINUTES = 60

# ===============================
# APP (LET FASTAPI HANDLE DOCS)
# ===============================
app = FastAPI(
    title="SOC Phishing Platform",
    version="4.2"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# ===============================
# HEALTH
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

# ===============================
# SCAN
# ===============================
KEYWORDS = ["urgent", "verify", "password", "login"]

@app.post("/scan")
def scan(email: EmailRequest, token: str = Depends(oauth2_scheme)):
    verify_token(token)
    score = min(sum(20 for k in KEYWORDS if k in (email.subject + email.body).lower()), 100)
    verdict = "PHISHING" if score >= 70 else "SAFE"
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "subject": email.subject,
        "verdict": verdict,
        "risk_score": score
    }
