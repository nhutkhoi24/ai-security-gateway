import json
import os
import re
from datetime import datetime, timezone

import psycopg
import redis
from fastapi import FastAPI
from pydantic import BaseModel
from prometheus_client import Counter, CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dlp_user:change_me@postgres:5432/dlp_db")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

app = FastAPI(title="DLP Inspection Worker", version="0.2.0")
SCANS = Counter("dlp_scans_total", "DLP scans", ["result"])

PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone_vn": re.compile(r"(?<!\d)(?:\+84|0)(?:3|5|7|8|9)\d{8}(?!\d)"),
    "card_candidate": re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
}

REPLACEMENTS = {
    "email": "[EMAIL]",
    "phone_vn": "[PHONE_NUMBER]",
    "card_candidate": "[CARD_NUMBER]",
}

class InspectRequest(BaseModel):
    text: str

def mask(text: str):
    findings = []
    masked = text
    for name, pattern in PATTERNS.items():
        matches = list(pattern.finditer(masked))
        if matches:
            findings.append({"type": name, "count": len(matches)})
            masked = pattern.sub(REPLACEMENTS[name], masked)
    return masked, findings

def store_event(original: str, masked: str, findings: list):
    # Store metadata + masked content only. Do not persist the original sensitive text.
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS inspection_events (
                        id BIGSERIAL PRIMARY KEY,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        findings JSONB NOT NULL,
                        original_length INTEGER NOT NULL,
                        masked_text TEXT NOT NULL
                    )
                    """
                )
                cur.execute(
                    "INSERT INTO inspection_events(findings, original_length, masked_text) VALUES (%s, %s, %s)",
                    (json.dumps(findings), len(original), masked),
                )
            conn.commit()
    except Exception:
        pass

    try:
        client = redis.from_url(REDIS_URL, socket_connect_timeout=2, decode_responses=True)
        client.setex(
            "dlp:last_scan",
            300,
            json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "findings": findings}),
        )
    except Exception:
        pass

@app.get("/health")
def health():
    return {"status": "ok", "service": "inspection-worker"}

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/inspect")
def inspect(payload: InspectRequest):
    masked, findings = mask(payload.text)
    result = "sensitive" if findings else "clean"
    SCANS.labels(result).inc()
    store_event(payload.text, masked, findings)
    return {"result": result, "findings": findings, "masked_text": masked}
