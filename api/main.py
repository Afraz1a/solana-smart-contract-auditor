# api/main.py
# Run: uvicorn api.main:app --reload --port 8000

import os, sys, hashlib, time
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ml.scanner import get_scanner

app = FastAPI(title="Solana Auditor API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

SCANS       = {}
LEADERBOARD = []
FEEDBACK    = []
scanner     = get_scanner()


class ScanRequest(BaseModel):
    source_code:  str
    program_name: Optional[str] = "My Contract"
    public:       bool = True

class FeedbackRequest(BaseModel):
    scan_id:    str
    vuln_type:  str
    reason:     str


@app.get("/")
def root():
    return {"status": "running", "docs": "/docs"}


@app.get("/health")
def health():
    return {
        "status":      "ok",
        "total_scans": len(SCANS),
        "leaderboard": len(LEADERBOARD),
        "feedback":    len(FEEDBACK),
    }


@app.post("/scan")
def scan(req: ScanRequest):
    if not req.source_code.strip():
        raise HTTPException(400, "source_code is empty")

    scan_id = hashlib.md5(
        (req.source_code + str(time.time())).encode()
    ).hexdigest()[:10]

    result = scanner.scan(req.source_code, req.program_name)

    record = {
        "scan_id":       scan_id,
        "program_name":  req.program_name,
        "scanned_at":    datetime.now(timezone.utc).isoformat(),
        **result,
    }
    SCANS[scan_id] = record

    if req.public:
        LEADERBOARD.append({
            "scan_id":       scan_id,
            "program_name":  req.program_name,
            "risk_score":    result["risk_score"],
            "is_vulnerable": result["is_vulnerable"],
            "vuln_type":     result["vuln_type"],
            "scanned_at":    record["scanned_at"],
        })

    return record


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in SCANS:
        raise HTTPException(404, "Scan not found")
    return SCANS[scan_id]


@app.get("/leaderboard")
def leaderboard(limit: int = 20):
    sorted_lb = sorted(LEADERBOARD, key=lambda x: x["risk_score"], reverse=True)
    return {"total": len(sorted_lb), "entries": sorted_lb[:limit]}


@app.post("/feedback")
def feedback(req: FeedbackRequest):
    if req.scan_id not in SCANS:
        raise HTTPException(404, "Scan not found")
    item = {
        "id":           len(FEEDBACK) + 1,
        "scan_id":      req.scan_id,
        "vuln_type":    req.vuln_type,
        "reason":       req.reason,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    FEEDBACK.append(item)
    return {"message": "Feedback received, thank you!", "id": item["id"]}
