from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from datetime import datetime, timedelta
import jwt
import os

print(">>> RUNNING app.py <<<")

JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key")
JWT_ALGO = "HS256"
TOKEN_EXPIRE_MINUTES = 60

# 👇 MOVE DOCS TO NON-RESERVED PATHS
app = FastAPI(
    title="SOC Phishing Platform",
    version="4.2",
    docs_url="/swagger",
    openapi_url="/swagger.json"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "SOC Phishing Platform",
        "message": "Backend is running"
    }

@app.post("/token")
def token():
    payload = {
        "exp": datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    }
    return {
        "access_token": jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO),
        "token_type": "bearer"
    }

class EmailRequest(BaseModel):
    subject: str
    body: str
    urls: List[str] = []

@app.post("/scan")
def scan(email: EmailRequest, token: str = Depends(oauth2_scheme)):
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    score = 20 if "password" in (email.subject + email.body).lower() else 0
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "verdict": "PHISHING" if score else "SAFE",
        "score": score
    }
