from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from preprocessor import preprocess, urgency_score, check_brand_spoofing
from url_analyzer import extract_url_features

class PhishingModel:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
        self.model = AutoModelForSequenceClassification.from_pretrained(
            "./trained_model"  # your fine-tuned model
        )
        self.model.eval()

    def predict(self, text, sender, urls):
        # 1. Preprocess
        cleaned = preprocess(text)

        # 2. BERT prediction
        inputs = self.tokenizer(
            cleaned, return_tensors="pt",
            truncation=True, max_length=512
        )
        with torch.no_grad():
            logits = self.model(**inputs).logits

        confidence = torch.softmax(logits, dim=1)[0][1].item()
        label = "PHISHING" if confidence > 0.5 else "LEGIT"

        # 3. Build human-readable reasons
        reasons = []
        if urgency_score(text) > 0.3:
            reasons.append("⚠️ Urgency/fear language detected")

        spoofing = check_brand_spoofing(text, sender)
        if spoofing:
            reasons.append(f"🎭 Impersonates {spoofing[0]['brand']}")

        for url in urls:
            url_risk = extract_url_features(url)
            if url_risk["risk_score"] > 5:
                reasons.append(f"🔗 Suspicious URL: {url[:40]}...")

        return {
            "label": label,
            "confidence": confidence,
            "reasons": reasons
        }
