from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from preprocessor import preprocess, urgency_score, get_manipulation_flags, get_spoofing_flags
from url_analyzer import get_url_flags

MODEL_PATH = "./trained_model"

class PhishingModel:
    def __init__(self):
        print(f"Loading tokenizer and model from {MODEL_PATH}...")

        # Load both tokenizer and model from local trained_model folder
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
        self.model.eval()

        # Use GPU if available, otherwise CPU
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

        print(f"Model loaded on {self.device}")

    def predict(self, text: str, sender: str, urls: list) -> dict:

        # ── Step 1: Preprocess ────────────────────────────────────────────────
        cleaned = preprocess(text)

        # ── Step 2: DistilBERT classification ────────────────────────────────
        inputs = self.tokenizer(
            cleaned,
            return_tensors="pt",
            truncation=True,
            max_length=256,
            padding=True
        )

        # DistilBERT does NOT use token_type_ids — remove if tokenizer added it
        inputs.pop("token_type_ids", None)

        # Move to same device as model
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self.model(**inputs).logits

        probs      = torch.softmax(logits, dim=1)[0]
        confidence = probs[1].item()
        label      = "PHISHING" if confidence > 0.5 else "LEGIT"

        # ── Step 3: Build human-readable reasons ─────────────────────────────
        reasons = []

        # urgency_score() returns a dict of per-category scores.
        # Flag if ANY category has at least one hit (score > 0),
        # not just if the overall average clears a threshold.
        urgency = urgency_score(text)
        has_urgency = any(
            score > 0
            for key, score in urgency.items()
            if key != "overall"
        )
        if has_urgency:
            reasons.extend(get_manipulation_flags(text))

        # Brand spoofing via NER
        reasons.extend(get_spoofing_flags(text, sender))

        # URL risk
        if urls:
            reasons.extend(get_url_flags(urls))

        return {
            "label":      label,
            "confidence": round(confidence, 4),
            "reasons":    reasons
        }
