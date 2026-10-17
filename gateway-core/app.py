import os
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

DLP_WORKER_URL = os.getenv("DLP_WORKER_URL", "http://10.10.10.20:8001").rstrip("/")
AI_PROVIDER = os.getenv("AI_PROVIDER", "disabled")
AI_API_KEY = os.getenv("AI_API_KEY", "")
AI_BASE_URL = os.getenv("AI_BASE_URL", "").rstrip("/")
AI_MODEL = os.getenv("AI_MODEL", "")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

app = FastAPI(title="AI Security Gateway Core", version="0.3.0")
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


async def inspect_file(filename: str, content_type: str, data: bytes):
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(180.0, connect=10.0)) as client:
            response = await client.post(
                f"{DLP_WORKER_URL}/inspect/file",
                files={"file": (filename, data, content_type)},
            )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        # Do not continue to the AI provider when the DLP worker rejects the file.
        raise HTTPException(
            status_code=502,
            detail=f"DLP worker rejected the file with HTTP {exc.response.status_code}",
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"DLP worker unavailable: {exc}") from exc


async def send_to_ai(masked_text: str):
    if AI_PROVIDER == "disabled":
        return None
    if AI_PROVIDER != "openai_compatible":
        raise HTTPException(status_code=501, detail="Unsupported AI_PROVIDER")
    if not (AI_API_KEY and AI_BASE_URL and AI_MODEL):
        raise HTTPException(status_code=500, detail="AI provider configuration is incomplete")

    headers = {"Authorization": f"Bearer {AI_API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": AI_MODEL,
        "reasoning_effort": "low",
        "messages": [
            {
                "role": "user",
                "content": "Tóm tắt tài liệu sau. Chỉ sử dụng nội dung đã qua DLP:\n\n" + masked_text,
            }
        ],
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(180.0, connect=10.0)) as client:
            response = await client.post(
                f"{AI_BASE_URL}/chat/completions", headers=headers, json=body
            )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=502,
                detail=f"AI provider returned HTTP {response.status_code}",
            )
        return response.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"AI provider unavailable ({type(exc).__name__}): {exc!r}") from exc


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
    """Inspect text first; only the masked text can reach the AI provider."""
    started = time.perf_counter()
    try:
        inspection = await inspect_text(payload.text)
        masked_text = inspection.get("masked_text")
        if not isinstance(masked_text, str):
            raise HTTPException(status_code=502, detail="DLP worker returned no masked text")

        ai_response = await send_to_ai(masked_text)
        REQUESTS.labels("chat", "200").inc()
        if ai_response is None:
            return {
                "status": "ai_disabled",
                "inspection": inspection,
                "text_sent_to_ai": masked_text,
            }
        return {"inspection": inspection, "ai_response": ai_response}
    except HTTPException as exc:
        REQUESTS.labels("chat", str(exc.status_code)).inc()
        raise
    finally:
        LATENCY.labels("chat").observe(time.perf_counter() - started)


@app.post("/api/chat/file")
async def chat_file(file: UploadFile = File(...)):
    """Inspect an uploaded file, then send only its masked text to Gemini."""
    started = time.perf_counter()
    status = "500"
    try:
        filename = Path(file.filename or "upload").name
        content_type = file.content_type or "application/octet-stream"
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        await file.close()
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File exceeds the 10 MiB limit")

        inspection = await inspect_file(filename, content_type, data)
        result = inspection.get("result")
        if result not in {"clean", "sensitive"}:
            # Fail closed for scanned PDFs, empty files, and unknown worker results.
            raise HTTPException(
                status_code=422,
                detail=f"File was not cleared by DLP (result={result!r}); it was not sent to AI",
            )
        masked_text = inspection.get("masked_text")
        if not isinstance(masked_text, str) or not masked_text.strip():
            raise HTTPException(status_code=422, detail="DLP returned no usable sanitized text")

        ai_response = await send_to_ai(masked_text)
        status = "200"
        REQUESTS.labels("chat_file", status).inc()
        if ai_response is None:
            return {
                "status": "ai_disabled",
                "filename": filename,
                "inspection": inspection,
                "text_sent_to_ai": masked_text,
            }
        return {
            "status": "completed",
            "filename": filename,
            "inspection": inspection,
            # Included as demo evidence: this is the exact text put in the AI request.
            "text_sent_to_ai": masked_text,
            "ai_response": ai_response,
        }
    except HTTPException as exc:
        status = str(exc.status_code)
        REQUESTS.labels("chat_file", status).inc()
        raise
    finally:
        LATENCY.labels("chat_file").observe(time.perf_counter() - started)