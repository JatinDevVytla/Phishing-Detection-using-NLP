"""
preprocessor.py
────────────────────────────────────────────────
Full NLP preprocessing pipeline for phishing detection.
Includes: text cleaning, tokenization, urgency scoring,
NER-based brand spoofing detection, and feature extraction.
"""

import re
import nltk
import spacy
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

# ── Download required NLTK data ──────────────────────────────────────────────
nltk.download("punkt",      quiet=True)
nltk.download("stopwords",  quiet=True)
nltk.download("wordnet",    quiet=True)

# ── Load spaCy model ──────────────────────────────────────────────────────────
# Run: python -m spacy download en_core_web_sm
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    import subprocess
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    nlp = spacy.load("en_core_web_sm")

# ── Constants ─────────────────────────────────────────────────────────────────

TRUSTED_DOMAINS = {
    "paypal":    "paypal.com",
    "apple":     "apple.com",
    "amazon":    "amazon.com",
    "google":    "google.com",
    "microsoft": "microsoft.com",
    "netflix":   "netflix.com",
    "facebook":  "facebook.com",
    "instagram": "instagram.com",
    "twitter":   "twitter.com",
    "bank":      None,           # generic — always flag
    "irs":       "irs.gov",
    "fedex":     "fedex.com",
    "ups":       "ups.com",
    "dhl":       "dhl.com",
}

URGENCY_SIGNALS = {
    "threat": [
        "suspended", "compromised", "unauthorized", "blocked",
        "expired", "locked", "breach", "violation", "disabled",
        "terminated", "restricted", "flagged"
    ],
    "action": [
        "verify", "confirm", "click", "update", "validate",
        "login", "sign in", "submit", "provide", "enter",
        "complete", "respond"
    ],
    "time_pressure": [
        "immediately", "urgent", "24 hours", "now", "today only",
        "limited time", "expires", "deadline", "as soon as possible",
        "right away", "don't delay", "act fast", "last chance"
    ],
    "reward": [
        "winner", "prize", "free", "congratulations", "selected",
        "lucky", "reward", "bonus", "gift", "claim", "won"
    ],
    "fear": [
        "warning", "alert", "suspicious activity", "fraud",
        "identity theft", "hacked", "malware", "virus",
        "attention required", "security notice"
    ],
}

# Stopwords to keep because they carry meaning in phishing context
KEEP_WORDS = {"no", "not", "never", "urgent", "free", "win", "won", "now"}


# ── Text Cleaning ─────────────────────────────────────────────────────────────

def clean_html(text: str) -> str:
    """Remove HTML tags from text."""
    return re.sub(r"<[^>]+>", " ", text)


def replace_urls(text: str) -> str:
    """Replace URLs with URLTOKEN to preserve signal without noise."""
    return re.sub(r"http\S+|www\S+", " URLTOKEN ", text)


def replace_emails(text: str) -> str:
    """Replace email addresses with EMAILTOKEN."""
    return re.sub(r"\S+@\S+\.\S+", " EMAILTOKEN ", text)


def replace_phone_numbers(text: str) -> str:
    """Replace phone numbers with PHONETOKEN."""
    return re.sub(r"\b(\+?\d[\d\s\-().]{7,}\d)\b", " PHONETOKEN ", text)


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def remove_special_chars(text: str) -> str:
    """Keep letters, spaces, and meaningful punctuation."""
    return re.sub(r"[^a-zA-Z\s]", " ", text)


# ── Core Preprocess Function ──────────────────────────────────────────────────

def preprocess(text: str, lemmatize: bool = True) -> str:
    """
    Full preprocessing pipeline.

    Steps:
        1. Clean HTML
        2. Replace URLs, emails, phone numbers with tokens
        3. Lowercase
        4. Remove special characters
        5. Tokenize
        6. Remove stopwords (keeping phishing-relevant ones)
        7. Lemmatize

    Args:
        text:      Raw email or SMS text
        lemmatize: Whether to apply lemmatization (default True)

    Returns:
        Cleaned string ready for vectorization or BERT
    """
    # Step 1–4: Structural cleaning
    text = clean_html(text)
    text = replace_urls(text)
    text = replace_emails(text)
    text = replace_phone_numbers(text)
    text = text.lower()
    text = remove_special_chars(text)
    text = normalize_whitespace(text)

    # Step 5: Tokenize
    tokens = nltk.word_tokenize(text)

    # Step 6: Remove stopwords (but keep phishing-relevant ones)
    stop_words = set(stopwords.words("english")) - KEEP_WORDS
    tokens = [t for t in tokens if t not in stop_words and len(t) > 1]

    # Step 7: Lemmatize
    if lemmatize:
        lemmatizer = WordNetLemmatizer()
        tokens = [lemmatizer.lemmatize(t) for t in tokens]

    return " ".join(tokens)


# ── Urgency Scoring ───────────────────────────────────────────────────────────

def urgency_score(text: str) -> dict:
    """
    Compute urgency/manipulation scores across 5 categories.

    Returns:
        Dict with per-category scores (0–1) and overall score.

    Example:
        >>> urgency_score("URGENT: Your account has been suspended. Verify NOW!")
        {'threat': 0.25, 'action': 0.125, 'time_pressure': 0.25,
         'reward': 0.0, 'fear': 0.0, 'overall': 0.125}
    """
    text_lower = text.lower()
    scores = {}

    for category, signals in URGENCY_SIGNALS.items():
        hits = sum(1 for s in signals if s in text_lower)
        scores[category] = round(hits / len(signals), 4)

    scores["overall"] = round(sum(scores.values()) / len(scores), 4)
    return scores


def get_manipulation_flags(text: str) -> list:
    """
    Return human-readable list of manipulation tactics found.

    Returns:
        List of flag strings, e.g. ["⚠️ Threat language", "⏰ Time pressure"]
    """
    scores = urgency_score(text)
    flags = []

    category_labels = {
        "threat":        "⚠️ Threat/suspension language",
        "action":        "🖱️ Forced action language",
        "time_pressure": "⏰ Time pressure tactics",
        "reward":        "🎁 Reward/prize bait",
        "fear":          "😨 Fear/security alert language",
    }

    for category, label in category_labels.items():
        if scores.get(category, 0) > 0:
            flags.append(label)

    return flags


# ── NER: Brand Spoofing Detection ─────────────────────────────────────────────

def check_brand_spoofing(text: str, sender_email: str = "") -> list:
    """
    Use spaCy NER to detect brand impersonation.

    Checks if a known brand is mentioned in the text but the
    sender's email domain doesn't match the official domain.

    Args:
        text:         Email body text
        sender_email: Sender's email address (e.g. "support@paypa1.com")

    Returns:
        List of spoofing findings, empty if none detected.

    Example:
        >>> check_brand_spoofing("Your Apple ID is locked", "no-reply@apple-secure.net")
        [{'brand': 'Apple', 'official_domain': 'apple.com',
          'sender_domain': 'apple-secure.net', 'risk': 'BRAND_SPOOFING'}]
    """
    doc = nlp(text)
    findings = []

    # Extract sender domain
    sender_domain = ""
    if "@" in sender_email:
        sender_domain = sender_email.split("@")[-1].lower()

    # Check named entities
    for ent in doc.ents:
        if ent.label_ == "ORG":
            brand_key = ent.text.lower().strip()

            # Check against known brand list
            for brand_name, official_domain in TRUSTED_DOMAINS.items():
                if brand_name in brand_key or brand_key in brand_name:
                    if official_domain is None:
                        # Generic brand (like "bank") — always suspicious
                        findings.append({
                            "brand":           ent.text,
                            "official_domain": "unknown",
                            "sender_domain":   sender_domain,
                            "risk":            "GENERIC_BRAND_IMPERSONATION",
                        })
                    elif sender_domain and official_domain not in sender_domain:
                        findings.append({
                            "brand":           ent.text,
                            "official_domain": official_domain,
                            "sender_domain":   sender_domain,
                            "risk":            "BRAND_SPOOFING",
                        })

    return findings


def get_spoofing_flags(text: str, sender_email: str = "") -> list:
    """
    Human-readable spoofing flags.

    Returns:
        List of strings like ["🎭 Impersonates PayPal (sent from paypa1.com)"]
    """
    findings = check_brand_spoofing(text, sender_email)
    flags = []
    for f in findings:
        flags.append(
            f"🎭 Impersonates {f['brand']} "
            f"(official: {f['official_domain']}, "
            f"sender: {f['sender_domain'] or 'unknown'})"
        )
    return flags


# ── Combined Feature Extraction ───────────────────────────────────────────────

def extract_text_features(text: str, sender_email: str = "") -> dict:
    """
    Extract all NLP-based features from an email/SMS in one call.

    Returns a flat dict of features ready for ML model input or
    for generating human-readable explanations.

    Args:
        text:         Raw email or SMS body
        sender_email: Sender's email address

    Returns:
        Dict of features including cleaned text, urgency scores,
        spoofing findings, and overall risk flags.
    """
    cleaned = preprocess(text)
    urgency  = urgency_score(text)
    spoofing = check_brand_spoofing(text, sender_email)
    manip_flags  = get_manipulation_flags(text)
    spoof_flags  = get_spoofing_flags(text, sender_email)

    return {
        # Cleaned text for BERT/TF-IDF
        "cleaned_text":       cleaned,

        # Urgency scores (0–1 each)
        "urgency_threat":     urgency["threat"],
        "urgency_action":     urgency["action"],
        "urgency_time":       urgency["time_pressure"],
        "urgency_reward":     urgency["reward"],
        "urgency_fear":       urgency["fear"],
        "urgency_overall":    urgency["overall"],

        # Structural text features
        "text_length":        len(text),
        "caps_ratio":         sum(1 for c in text if c.isupper()) / max(len(text), 1),
        "exclamation_count":  text.count("!"),
        "has_url":            bool(re.search(r"http\S+|www\S+", text)),
        "url_count":          len(re.findall(r"http\S+|www\S+", text)),

        # NER spoofing
        "brand_spoofing_count": len(spoofing),
        "spoofing_details":     spoofing,

        # Human-readable flags (for UI display)
        "risk_flags":         manip_flags + spoof_flags,
    }


# ── Quick Test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sample_email = """
    Dear Customer,

    URGENT NOTICE: Your PayPal account has been SUSPENDED due to suspicious activity!
    
    You must verify your identity IMMEDIATELY or your account will be permanently closed.
    Click the link below within 24 hours:
    
    http://paypal-secure-verify.xyz/login
    
    Failure to act will result in permanent account termination.
    
    PayPal Security Team
    support@paypa1-secure.com
    """

    sender = "support@paypa1-secure.com"

    print("=" * 60)
    print("PHISHING DETECTOR — PREPROCESSOR TEST")
    print("=" * 60)

    features = extract_text_features(sample_email, sender)

    print(f"\n📝 Cleaned text:\n{features['cleaned_text']}\n")
    print(f"⚡ Urgency overall score: {features['urgency_overall']}")
    print(f"🔠 Caps ratio: {features['caps_ratio']:.2%}")
    print(f"🔗 URL count: {features['url_count']}")
    print(f"🎭 Brand spoofing count: {features['brand_spoofing_count']}")

    print("\n🚩 Risk Flags:")
    for flag in features["risk_flags"]:
        print(f"   {flag}")

    print("\n✅ Spoofing Details:")
    for s in features["spoofing_details"]:
        print(f"   Brand: {s['brand']}, Official: {s['official_domain']}, Got: {s['sender_domain']}")
