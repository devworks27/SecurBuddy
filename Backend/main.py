"""SecurBuddy - AI-powered security assistant backend.

Pipeline for a pasted log, email, or note:
  1. deterministic signature detection (no network, no keys required)
  2. IOC extraction, then live reputation enrichment (AbuseIPDB / VirusTotal)
  3. a plain-English explanation plus copy-paste remediation commands
  4. an optional streaming chat copilot grounded in that same analysis
"""

import json
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from groq import AsyncGroq
from pydantic import BaseModel, Field

from config import DATASET_PATH, MAX_INPUT_CHARS, SYSTEM_PROMPT, settings
from dataset import Dataset
from detector import Detector, IOCExtractor
from intel import ReputationService
from remediation import RemediationBuilder

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("securbuddy")


# --------------------------------------------------------------- schemas


class ChatMessage(BaseModel):
    """A single message in the conversation."""

    role: Literal["user", "assistant", "system"]
    content: str


class ChatRequest(BaseModel):
    """Incoming request for a streamed chat completion."""

    history: list[ChatMessage] = Field(default_factory=list)
    user_message: str
    system_prompt: str | None = None
    analysis_context: str | None = None


class AnalyzeRequest(BaseModel):
    """Analyze either pasted content or a named case from the golden dataset."""

    raw_content: str = ""
    dataset_id: str | None = None


# --------------------------------------------------------------- services


class ChatbotService:
    """Streaming chat completions backed by Groq."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.client: AsyncGroq | None = AsyncGroq(api_key=api_key) if api_key else None

    async def generate_chat_stream(
        self,
        history: list[ChatMessage],
        new_msg: ChatMessage,
        system_prompt: str | None = None,
        analysis_context: str | None = None,
    ) -> AsyncGenerator[str, None]:
        """Yield SSE `data:` frames of token text, then a terminator."""
        system = system_prompt or SYSTEM_PROMPT
        if analysis_context:
            system = f"{system}\n\nVerified analysis of the user's current submission:\n{analysis_context}"

        messages: list[dict[str, str]] = [{"role": "system", "content": system}]
        messages.extend(m.model_dump() for m in history[-12:])
        messages.append(new_msg.model_dump())

        if not self.client:
            yield "data: " + json.dumps(
                {"error": "GROQ_API_KEY is not configured on the server, so the copilot is offline."}
            ) + "\n\n"
            yield "data: [DONE]\n\n"
            return

        try:
            stream = await self.client.chat.completions.create(
                model=settings.model,
                messages=messages,
                stream=True,
                temperature=0.4,
            )
            async for chunk in stream:
                token = chunk.choices[0].delta.content
                if token:
                    yield "data: " + json.dumps({"text": token}) + "\n\n"
        except Exception:
            logger.exception("Chat stream failed")
            yield "data: " + json.dumps({"error": "The AI service could not be reached."}) + "\n\n"

        yield "data: [DONE]\n\n"


def build_context_packet(
    analysis: dict[str, Any],
    reputation: dict[str, Any],
    remediation: dict[str, Any],
    similar: tuple[dict[str, Any], float] | None = None,
) -> str:
    """Compact JSON the model reads as ground truth, so it cannot invent IOCs."""
    packet: dict[str, Any] = {
        "detections": [
            {"threat": m["label"], "severity": m["severity"], "occurrences": m["matches_found"]}
            for m in analysis.get("matches", [])
        ],
        "indicators_of_compromise": {
            "ips": reputation.get("iocs", {}).get("ips", []),
            "urls": reputation.get("iocs", {}).get("urls", []),
            "emails": reputation.get("iocs", {}).get("emails", []),
            "bitcoin_wallets": reputation.get("iocs", {}).get("wallets", []),
            "domains": reputation.get("iocs", {}).get("domains", []),
        },
        "live_reputation": {
            "ip_reports": reputation.get("ip_reports", []),
            "url_reports": reputation.get("url_reports", []),
        },
        "recommended_block": remediation.get("primary"),
    }
    if similar:
        case, score = similar
        packet["closest_dataset_case"] = {
            "id": case.get("id"),
            "type": case.get("type"),
            "known_label": case.get("description"),
            "similarity": score,
        }
    return json.dumps(packet, indent=2, default=str)[:6000]


# ------------------------------------------------------------------ state

chatbot_service = ChatbotService(settings.groq_api_key)
dataset = Dataset(DATASET_PATH)
detector = Detector()
ioc_extractor = IOCExtractor()
remediation_builder = RemediationBuilder()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Own the lifetime of the shared async HTTP client."""
    app.state.reputation = ReputationService()
    try:
        yield
    finally:
        await app.state.reputation.aclose()


app = FastAPI(
    title="SecurBuddy Security API",
    version="2.0.0",
    description="Paste a log, email, or note; get IOC extraction, live reputation, "
    "a plain-English explanation, and copy-paste remediation commands.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



def get_reputation(request: Request) -> ReputationService:
    return request.app.state.reputation


# ------------------------------------------------------------------ routes


@app.get("/")
async def root() -> dict[str, str]:
    """Explain where the browser UI and API documentation are located."""
    return {
        "service": "SecurBuddy",
        "message": "SecurBuddy API is running securely in the cloud.",
        "status": "online",
    }


@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Liveness probe reporting which live integrations are configured."""
    return {
        "status": "ok",
        "service": "securbuddy",
        "version": app.version,
        "model": settings.model,
        "dataset_cases": len(dataset),
        "integrations": {
            "groq": bool(settings.groq_api_key),
            "abuseipdb": bool(settings.abuseipdb_api_key),
            "virustotal": bool(settings.virustotal_api_key),
        },
    }


@app.get("/api/dataset")
async def get_dataset() -> dict[str, Any]:
    """List every labelled case in the golden dataset, raw text included."""
    return {
        "status": "success",
        "count": len(dataset),
        "cases": [dataset.public_case(c) for c in dataset.cases],
    }


@app.post("/api/dataset/reload")
async def reload_dataset() -> dict[str, Any]:
    """Re-read the dataset from disk without restarting the server."""
    dataset.reload()
    return {"status": "success", "count": len(dataset)}


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest, request: Request) -> dict[str, Any]:
    """Analyze pasted content: detect, enrich, explain, and build commands."""
    raw = (payload.raw_content or "").strip()

    if payload.dataset_id:
        case = dataset.get(payload.dataset_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"Unknown dataset case '{payload.dataset_id}'.")
        raw = str(case.get("raw_input", "")).strip()

    if not raw:
        return {
            "status": "empty",
            "verdict": "clean",
            "verdict_label": "Nothing to analyze",
            "message": "Paste a log, an email, or a suspicious message first.",
            "analysis": {"matches": [], "top_severity": "info", "match_count": 0, "signal_count": 0},
            "iocs": {"ips": [], "urls": [], "emails": [], "wallets": [], "domains": []},
            "reputation": {"ip_reports": [], "url_reports": [], "skipped_ips": [], "skipped_urls": []},
            "remediation": {
                "primary": None,
                "variants": [],
                "note": "Nothing to block: there was no content.",
            },
            "dataset_match": None,
            "stats": {"input_chars": 0, "truncated": False},
        }

    truncated = len(raw) > MAX_INPUT_CHARS
    text = raw[:MAX_INPUT_CHARS]

    analysis = detector.analyze(text)
    iocs = ioc_extractor.extract(text)
    reputation = await get_reputation(request).enrich(iocs)
    reputation["iocs"] = iocs
    remediation = remediation_builder.build(analysis, iocs, reputation)
    similar = dataset.find_similar(text)

    return {
        "status": "success",
        "verdict": analysis["verdict"],
        "verdict_label": analysis["verdict_label"],
        "message": _headline(analysis, iocs, truncated),
        "analysis": {
            "verdict": analysis["verdict"],
            "verdict_label": analysis["verdict_label"],
            "top_severity": analysis["top_severity"],
            "match_count": analysis["match_count"],
            "signal_count": analysis["signal_count"],
            "matches": analysis["matches"],
        },
        "iocs": iocs,
        "reputation": reputation,
        "remediation": remediation,
        "dataset_match": (
            {
                "id": similar[0].get("id"),
                "type": similar[0].get("type"),
                "description": similar[0].get("description"),
                "similarity": similar[1],
            }
            if similar
            else None
        ),
        "stats": {"input_chars": len(raw), "truncated": truncated},
    }


@app.post("/api/chat/stream")
async def chat_stream(payload: ChatRequest) -> StreamingResponse:
    """Stream an assistant response as Server-Sent Events."""
    return StreamingResponse(
        chatbot_service.generate_chat_stream(
            payload.history,
            ChatMessage(role="user", content=payload.user_message),
            payload.system_prompt,
            payload.analysis_context,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _headline(analysis: dict[str, Any], iocs: dict[str, list[str]], truncated: bool) -> str:
    """One-sentence summary for the UI banner."""
    matches = analysis.get("matches", [])
    if not matches:
        return "No attack patterns matched this content."
    top = matches[0]
    parts = [f"{top['matches_found']}x {top['label']}"]
    if len(matches) > 1:
        parts.append(f"{len(matches) - 1} other pattern(s)")
    ioc_total = len(iocs["ips"]) + len(iocs["urls"])
    if ioc_total:
        parts.append(f"{ioc_total} indicator(s) extracted")
    if truncated:
        parts.append("input truncated for safety")
    return " - ".join(parts) + "."


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)