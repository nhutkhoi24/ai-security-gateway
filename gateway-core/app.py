import os
import time
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

DLP_WORKER_URL = os.getenv("DLP_WORKER_URL", "http://10.10.10.20:8001").rstrip("/")
AI_PROVIDER = os.getenv("AI_PROVIDER", "disabled")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_BASE_URL = os.getenv("AI_BASE_URL", "").rstrip("/")
AI_MODEL = os.getenv("AI_MODEL", "")

app = FastAPI(title="AI Security Gateway Core", version="0.2.0")
REQUESTS = Counter("gateway_requests_total", "Gateway HTTP requests", ["endpoint", "status"])
LATENCY = Histogram("gateway_request_duration_seconds", "Gateway request latency", ["endpoint"])

class InspectRequest(BaseModel):
    text: str

class ChatRequest(BaseModel):
    text: str

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "gateway-core",
        "dlp_worker_url": DLP_WORKER_URL,
        "ai_provider": AI_PROVIDER,
    }

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

async def inspect_text(text: str):
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(f"{DLP_WORKER_URL}/inspect", json={"text": text})
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"DLP worker unavailable: {exc}") from exc

@app.post("/api/inspect")
async def inspect(payload: InspectRequest):
    started = time.perf_counter()
    try:
        result = await inspect_text(payload.text)
        REQUESTS.labels("inspect", "200").inc()
        return result
    except HTTPException:
        REQUESTS.labels("inspect", "502").inc()
        raise
    finally:
        LATENCY.labels("inspect").observe(time.perf_counter() - started)

@app.post("/api/chat")
async def chat(payload: ChatRequest):
    """Demo pipeline: DLP first, then an optional generic OpenAI-compatible provider.

    Keep AI_PROVIDER=disabled until an approved provider, base URL, model and API key
    are configured on VM02. The API key is never sent to VM03.
    """
    started = time.perf_counter()
    try:
        inspection = await inspect_text(payload.text)
        masked_text = inspection.get("masked_text", payload.text)

        if AI_PROVIDER == "disabled":
            REQUESTS.labels("chat", "200").inc()
            return {
                "status": "ai_disabled",
                "inspection": inspection,
                "text_sent_to_ai": masked_text,
            }

        if AI_PROVIDER != "openai_compatible":
            raise HTTPException(status_code=501, detail="Unsupported AI_PROVIDER")
        if not (AI_API_KEY and AI_BASE_URL and AI_MODEL):
            raise HTTPException(status_code=500, detail="AI provider configuration is incomplete")

        headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
        body = {
            "model": AI_MODEL,
            "messages": [{"role": "user", "content": masked_text}],
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(f"{AI_BASE_URL}/chat/completions", headers=headers, json=body)
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"AI provider returned HTTP {response.status_code}")

        REQUESTS.labels("chat", "200").inc()
        return {"inspection": inspection, "ai_response": response.json()}
    except HTTPException as exc:
        REQUESTS.labels("chat", str(exc.status_code)).inc()
        raise
    finally:
        LATENCY.labels("chat").observe(time.perf_counter() - started)
