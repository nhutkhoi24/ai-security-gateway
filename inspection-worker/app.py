import json
import os
import re
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import psycopg
import pymupdf
import redis
from docx import Document
from openpyxl import load_workbook
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel
from prometheus_client import Counter, CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://dlp_user:change_me@postgres:5432/dlp_db",
)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

app = FastAPI(title="DLP Inspection Worker", version="0.3.0")
SCANS = Counter("dlp_scans_total", "DLP scans", ["result"])
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
SUPPORTED_FILE_TYPES = {".txt", ".pdf", ".docx", ".xlsx"}

# CCCD requires nearby context to reduce false positives from unrelated
# 12-digit values. Keep it before card_candidate so it is classified as CCCD.
PATTERNS = {
    "cccd": re.compile(
        r"\b(?:CCCD|căn\s*cước(?:\s+công\s+dân)?|số\s+định\s+danh)\b"
        r"[^\d]{0,24}?(?P<number>(?:\d[\s-]?){11}\d)(?!\d)",
        re.IGNORECASE,
    ),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone_vn": re.compile(r"(?<!\d)(?:\+84|0)(?:3|5|7|8|9)\d{8}(?!\d)"),
    "card_candidate": re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
}

REPLACEMENTS = {
    "cccd": "[CCCD]",
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
        if not matches:
            continue

        findings.append({"type": name, "count": len(matches)})
        if name == "cccd":
            # Preserve the label/context and replace only the ID number.
            masked = pattern.sub(
                lambda match: match.group(0).replace(
                    match.group("number"), REPLACEMENTS[name]
                ),
                masked,
            )
        else:
            masked = pattern.sub(REPLACEMENTS[name], masked)
    return masked, findings


def extract_file_text(extension: str, data: bytes) -> str:
    if extension == ".txt":
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return data.decode("cp1258", errors="replace")

    if extension == ".pdf":
        with pymupdf.open(stream=data, filetype="pdf") as pdf:
            if pdf.needs_pass:
                raise ValueError("Encrypted PDF is not supported")
            return "\n".join(page.get_text("text") for page in pdf)

    if extension == ".docx":
        document = Document(BytesIO(data))
        parts = [paragraph.text for paragraph in document.paragraphs]
        for table in document.tables:
            for row in table.rows:
                parts.append("\t".join(cell.text for cell in row.cells))
        for section in document.sections:
            parts.extend(paragraph.text for paragraph in section.header.paragraphs)
            parts.extend(paragraph.text for paragraph in section.footer.paragraphs)
        return "\n".join(part for part in parts if part)

    if extension == ".xlsx":
        workbook = load_workbook(BytesIO(data), read_only=True, data_only=True)
        try:
            parts = []
            for worksheet in workbook.worksheets:
                for row in worksheet.iter_rows(values_only=True):
                    values = [str(value) for value in row if value is not None]
                    if values:
                        parts.append("\t".join(values))
            return "\n".join(parts)
        finally:
            workbook.close()

    raise ValueError("Unsupported file type")


def store_event(original: str, masked: str, findings: list):
    # Store metadata and masked content only. Never persist original sensitive text.
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
                    "INSERT INTO inspection_events"
                    "(findings, original_length, masked_text) VALUES (%s, %s, %s)",
                    (json.dumps(findings), len(original), masked),
                )
            conn.commit()
    except Exception:
        pass

    try:
        client = redis.from_url(
            REDIS_URL,
            socket_connect_timeout=2,
            decode_responses=True,
        )
        client.setex(
            "dlp:last_scan",
            300,
            json.dumps(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "findings": findings,
                }
            ),
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


@app.post("/inspect/file")
async def inspect_file(file: UploadFile = File(...)):
    filename = Path(file.filename or "upload").name
    extension = Path(filename).suffix.lower()
    if extension not in SUPPORTED_FILE_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Supported file types are .txt, .pdf, and .docx",
        )

    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 10 MiB limit")

    try:
        extracted = extract_file_text(extension, data)
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Could not parse {extension} file",
        ) from exc
    finally:
        await file.close()

    if not extracted.strip():
        # An image-only/scanned PDF is not safe to label clean without OCR.
        result = "needs_ocr" if extension == ".pdf" else "empty"
        SCANS.labels(result).inc()
        store_event(extracted, extracted, [])
        return {
            "filename": filename,
            "file_type": extension[1:],
            "result": result,
            "findings": [],
            "masked_text": "",
            "extracted_chars": 0,
        }

    masked, findings = mask(extracted)
    result = "sensitive" if findings else "clean"
    SCANS.labels(result).inc()
    store_event(extracted, masked, findings)
    return {
        "filename": filename,
        "file_type": extension[1:],
        "result": result,
        "findings": findings,
        "masked_text": masked,
        "extracted_chars": len(extracted),
    }