"""phi-shield HTTP API — deploy as microservice for EMS1R integration.

Endpoints:
    POST /scan     — scan text, return entities + risk + action
    POST /redact   — redact PHI from text (optional preset)
    GET  /health   — service health check
    GET  /patterns — list all active patterns

Run:
    pip install uvicorn fastapi
    uvicorn server:app --host 0.0.0.0 --port 8900

Author: Amado Alvarez Sueiras
"""

import time
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

from phi_shield.scanner import FastPHIScanner

app = FastAPI(
    title="phi-shield",
    version="0.2.0",
    description="Fast PHI/PII scanner for healthcare LLM pipelines",
)

scanner = FastPHIScanner()


class ScanRequest(BaseModel):
    text: str


class RedactRequest(BaseModel):
    text: str
    preset: Optional[str] = None  # ems, billing, radiology, dialysis, or null for all


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "healthy": scanner.healthy,
        "pattern_count": scanner.pattern_count,
    }


@app.get("/patterns")
def patterns() -> dict:
    return {
        "count": scanner.pattern_count,
        "patterns": list(scanner._patterns.keys()),
    }


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    t0 = time.monotonic()
    result = scanner.scan(req.text)
    result["latency_ms"] = round((time.monotonic() - t0) * 1000, 3)
    return result


@app.post("/redact")
def redact(req: RedactRequest) -> dict:
    t0 = time.monotonic()
    presets = {
        "ems": scanner.redact_ems,
        "billing": scanner.redact_billing,
        "radiology": scanner.redact_radiology,
        "dialysis": scanner.redact_dialysis,
    }
    fn = presets.get(req.preset, scanner.redact) if req.preset else scanner.redact
    clean = fn(req.text)
    return {
        "original_length": len(req.text),
        "redacted_length": len(clean),
        "redacted_text": clean,
        "preset": req.preset or "all",
        "latency_ms": round((time.monotonic() - t0) * 1000, 3),
    }
