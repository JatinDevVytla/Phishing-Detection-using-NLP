from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re
from preprocessor import preprocess, urgency_score, get_manipulation_flags, get_spoofing_flags
from url_analyzer import get_url_flags

MODEL_PATH = "./trained_model"

# ── Trusted domains — skip model for these ────────────────────────
TRUSTED_SENDER_DOMAINS = {
    "google.com", "gmail.com", "accounts.google.com",
    "amazon.com", "amazon.in", "amazonses.com",
    "paypal.com", "apple.com", "microsoft.com",
    "linkedin.com", "twitter.com", "facebook.com",
    "netflix.com", "github.com", "youtube.com",
    "stackoverflow.com", "dropbox.com",
    # Add your university/college domain here:
    # "youruniversity.edu",
}

def extract_sender_domain(sender_email: str) -> str:
    """Extract domain from email address."""
    if "@" in sender_email:
        return sender_email.strip().lower().split("@")[-1]
    return ""

def is_trusted_sender(sender_email: str) -> bool:
    """Return True if sender domain is in our whitelist."""
    domain = extract_sender_domain(sender_email)
    # Check exact match and subdomain match
    # e.g. "mail.google.com" should match "google.com"
    for trusted in TRUSTED_SENDER_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


class PhishingModel:
    def __init__(self):
        print(f"Loading tokenizer and model from {MODEL_PATH}...")
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
        self.model.eval()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        print(f"Model loaded on {self.device}")

    def predict(self, text: str, sender: str, urls: list) -> dict:

        # ── Step 1: Trusted sender bypass ────────────────────────────
        if is_trusted_sender(sender):
            return {
                "label":      "LEGIT",
                "confidence": 0.99,
                "reasons":    []
            }

        # ── Step 2: Preprocess ────────────────────────────────────────
        cleaned = preprocess(text)

        # ── Step 3: DistilBERT classification ────────────────────────
        inputs = self.tokenizer(
            cleaned,
            return_tensors="pt",
            truncation=True,
            max_length=256,
            padding=True
        )
        inputs.pop("token_type_ids", None)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self.model(**inputs).logits

        probs      = torch.softmax(logits, dim=1)[0]
        confidence = probs[1].item()

        # ── Step 4: Raised threshold + urgency gate ───────────────────
        # Only flag as phishing if model is very confident AND
        # there are actual urgency signals present
        urgency = urgency_score(text)
        has_urgency = any(
            score > 0
            for key, score in urgency.items()
            if key != "overall"
        )

        # Require BOTH high confidence AND some urgency signal
        # This prevents the model from flagging plain emails
        if confidence > 0.85 and has_urgency:
            label = "PHISHING"
        elif confidence > 0.95:
            # Very high confidence even without urgency signals
            label = "PHISHING"
        else:
            label = "LEGIT"

        # ── Step 5: Build reasons ─────────────────────────────────────
        reasons = []

        if has_urgency:
            reasons.extend(get_manipulation_flags(text))

        reasons.extend(get_spoofing_flags(text, sender))

        if urls:
            reasons.extend(get_url_flags(urls))

        return {
            "label":      label,
            "confidence": round(confidence, 4),
            "reasons":    reasons
        }
