"""HTTP wrapper around the scanner so a Lovable (or any) frontend can call it.

Run locally:
    pip install -e '.[server]'
    uvicorn lovable_audit.server:app --reload

POST /scan
    { "url": "https://example.com" }
    -> streams JSON progress (text/event-stream) with check results
    -> final event is the full report markdown

GET /healthz -> "ok"
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from datetime import date

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .report import render_markdown
from .scanner import scan

app = FastAPI(title="lovable-audit", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # intended for local dev + Lovable preview
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str = Field(..., description="Full URL including scheme")


def _normalize(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan")
async def scan_endpoint(req: ScanRequest) -> StreamingResponse:
    url = _normalize(req.url)

    queue: asyncio.Queue = asyncio.Queue()

    def on_progress(cr):
        queue.put_nowait(
            {
                "type": "check",
                "name": cr.name,
                "skipped": cr.skipped,
                "skip_reason": cr.skip_reason,
                "error": cr.error,
                "findings": [asdict(f) for f in cr.findings],
            }
        )

    async def run_scan():
        try:
            result = await scan(url, on_progress=on_progress)
            queue.put_nowait(
                {
                    "type": "report",
                    "url": result.url,
                    "date": date.today().isoformat(),
                    "counts": {
                        sev: result.count(sev)  # type: ignore[arg-type]
                        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                    },
                    "markdown": render_markdown(result),
                }
            )
        except Exception as e:
            queue.put_nowait({"type": "error", "message": f"{type(e).__name__}: {e}"})
        finally:
            queue.put_nowait(None)

    async def event_stream():
        task = asyncio.create_task(run_scan())
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(event_stream(), media_type="text/event-stream")
