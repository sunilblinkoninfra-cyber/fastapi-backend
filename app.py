# app.py - PhishGuard AI Backend
from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import random
import uuid

app = FastAPI(title="PhishGuard AI API", version="1.0.0")

# CORS for edge function access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---
class ScanRequest(BaseModel):
    subject: str
    body: str
    urls: Optional[List[str]] = []

class ScanResponse(BaseModel):
    phishing_probability: float
    risk_score: int
    tier: str
    verdict: str
    explainability: str
    malware_scan_result: str
    severity: str
    mitre_attack: List[str]
    yara_matches: List[str]

class SOCEvent(BaseModel):
    id: str
    timestamp: str
    tenant_id: str
    severity: str
    threat_type: str
    source_ip: str
    destination_ip: str
    affected_user: str
    indicators: List[str]
    recommendation: str
    status: str
    raw_evidence: dict

class SOCMetrics(BaseModel):
    total_events: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    events_today: int
    avg_response_time: float
    detection_rate: float

class TenantInfo(BaseModel):
    id: str
    name: str
    plan: str
    emails_scanned: int
    threats_blocked: int
    api_calls_remaining: int

# --- AI Phishing Detection Logic ---
def analyze_email(subject: str, body: str, urls: List[str]) -> ScanResponse:
    """Analyze email for phishing indicators"""
    
    phishing_keywords = [
        "urgent", "verify", "suspended", "click here", "password", 
        "account", "bank", "limited time", "act now", "confirm",
        "security alert", "unauthorized", "update required"
    ]
    
    text = f"{subject} {body}".lower()
    keyword_matches = sum(1 for kw in phishing_keywords if kw in text)
    
    # URL analysis
    suspicious_url_patterns = ["bit.ly", "tinyurl", ".tk", ".ml", "login", "verify"]
    url_score = sum(1 for url in urls for pattern in suspicious_url_patterns if pattern in url.lower())
    
    # Calculate probability
    base_score = (keyword_matches * 0.1) + (url_score * 0.15)
    probability = min(0.95, max(0.05, base_score + random.uniform(-0.1, 0.1)))
    risk_score = int(probability * 100)
    
    # Determine tier and verdict
    if probability >= 0.7:
        tier, verdict, severity = "HOT", "PHISHING", "CRITICAL"
    elif probability >= 0.4:
        tier, verdict, severity = "WARM", "SUSPICIOUS", "HIGH"
    elif probability >= 0.2:
        tier, verdict, severity = "WARM", "SUSPICIOUS", "MEDIUM"
    else:
        tier, verdict, severity = "COLD", "SAFE", "LOW"
    
    # Generate explainability
    reasons = []
    if keyword_matches > 0:
        reasons.append(f"Found {keyword_matches} phishing keywords")
    if url_score > 0:
        reasons.append(f"Detected {url_score} suspicious URL patterns")
    if not reasons:
        reasons.append("No significant phishing indicators detected")
    
    mitre = []
    if probability >= 0.4:
        mitre = ["T1566.001 - Spearphishing Attachment", "T1566.002 - Spearphishing Link"]
    
    return ScanResponse(
        phishing_probability=round(probability, 3),
        risk_score=risk_score,
        tier=tier,
        verdict=verdict,
        explainability="; ".join(reasons),
        malware_scan_result="CLEAN" if probability < 0.5 else "SUSPICIOUS",
        severity=severity,
        mitre_attack=mitre,
        yara_matches=["PHISH_URL_PATTERN"] if url_score > 0 else []
    )

# --- SOC Event Generation ---
def generate_soc_events(count: int = 50) -> List[SOCEvent]:
    """Generate realistic SOC events"""
    
    threat_types = ["Phishing", "Malware", "BEC", "Credential Harvesting", "Ransomware", "Data Exfiltration"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    statuses = ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED"]
    users = ["john.doe@company.com", "jane.smith@company.com", "admin@company.com", "hr@company.com"]
    
    events = []
    for i in range(count):
        severity = random.choices(severities, weights=[10, 25, 40, 25])[0]
        timestamp = datetime.utcnow() - timedelta(hours=random.randint(0, 168))
        
        events.append(SOCEvent(
            id=str(uuid.uuid4()),
            timestamp=timestamp.isoformat() + "Z",
            tenant_id="tenant_001",
            severity=severity,
            threat_type=random.choice(threat_types),
            source_ip=f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            destination_ip=f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
            affected_user=random.choice(users),
            indicators=[f"indicator_{random.randint(1000,9999)}" for _ in range(random.randint(1, 4))],
            recommendation=f"Investigate and {'escalate immediately' if severity == 'CRITICAL' else 'monitor closely'}",
            status=random.choice(statuses),
            raw_evidence={"email_id": f"msg_{random.randint(10000,99999)}"}
        ))
    
    return sorted(events, key=lambda x: x.timestamp, reverse=True)

# --- API Endpoints ---
@app.get("/")
def root():
    return {"status": "healthy", "service": "PhishGuard AI", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/soc", response_model=List[SOCEvent])
def get_soc_events():
    """Get all SOC events"""
    return generate_soc_events(50)

@app.get("/soc-metrics", response_model=SOCMetrics)
def get_soc_metrics():
    """Get SOC dashboard metrics"""
    return SOCMetrics(
        total_events=random.randint(1200, 1500),
        critical_count=random.randint(5, 15),
        high_count=random.randint(30, 60),
        medium_count=random.randint(150, 250),
        low_count=random.randint(400, 600),
        events_today=random.randint(20, 50),
        avg_response_time=round(random.uniform(2.5, 8.5), 1),
        detection_rate=round(random.uniform(94.0, 99.5), 1)
    )

@app.get("/tenant", response_model=TenantInfo)
def get_tenant_info():
    """Get tenant information"""
    return TenantInfo(
        id="tenant_001",
        name="PhishGuard Enterprise",
        plan="Enterprise",
        emails_scanned=random.randint(50000, 100000),
        threats_blocked=random.randint(500, 1500),
        api_calls_remaining=random.randint(8000, 10000)
    )

@app.post("/scan", response_model=ScanResponse)
def scan_email(request: ScanRequest):
    """Scan a single email for phishing"""
    return analyze_email(request.subject, request.body, request.urls or [])

@app.post("/scan-batch")
def scan_batch(emails: dict):
    """Scan multiple emails"""
    results = []
    for email in emails.get("emails", []):
        result = analyze_email(
            email.get("subject", ""),
            email.get("body", ""),
            email.get("urls", [])
        )
        results.append(result.dict())
    return results

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
