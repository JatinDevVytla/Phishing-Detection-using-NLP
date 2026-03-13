from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from model import PhishingModel

app = FastAPI()

# Allow extension to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_methods=["POST"],
    allow_headers=["*"],
)

model = PhishingModel()

class EmailRequest(BaseModel):
    subject: str
    body: str
    sender: str
    urls: List[str] = []

@app.post("/analyze")
async def analyze_email(email: EmailRequest):
    full_text = f"{email.subject} {email.body}"

    # Run NLP pipeline
    result = model.predict(
        text=full_text,
        sender=email.sender,
        urls=email.urls
    )

    return {
        "label":      result["label"],        # "PHISHING" or "LEGIT"
        "confidence": result["confidence"],   # 0.0 - 1.0
        "reasons":    result["reasons"]       # ["Urgency language", "Spoofed domain"]
    }