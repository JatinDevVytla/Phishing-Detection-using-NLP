from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from model import PhishingModel

app = FastAPI(title="Phishing Detector API")

# Allow Chrome extension to call the API (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Load model once at startup — stays in memory for all requests
model = PhishingModel()


class EmailRequest(BaseModel):
    subject: str = ""
    body: str
    sender: str = ""
    urls: List[str] = []


# ── Health check — popup.js pings this to show green/red dot ─────────────────
@app.get("/health")
async def health():
    return {"status": "ok"}


# ── Main analysis endpoint ────────────────────────────────────────────────────
@app.post("/analyze")
async def analyze_email(email: EmailRequest):
    full_text = f"{email.subject} {email.body}".strip()

    result = model.predict(
        text=full_text,
        sender=email.sender,
        urls=email.urls
    )

    return {
        "label":      result["label"],       # "PHISHING" or "LEGIT"
        "confidence": result["confidence"],  # 0.0 – 1.0
        "reasons":    result["reasons"]      # list of human-readable strings
    }
