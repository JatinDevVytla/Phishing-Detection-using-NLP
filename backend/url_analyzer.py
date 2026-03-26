"""
url_analyzer.py
────────────────────────────────────────────────────────────────
URL feature extraction and risk scoring for phishing detection.

Features extracted:
  - Structural signals  (length, subdomains, special chars)
  - Trust signals       (HTTPS, known shorteners, suspicious TLDs)
  - Brand spoofing      (lookalike domains, brand in subdomain)
  - Redirect signals    (double slashes, redirect params)
  - Entropy             (randomness score — phishing domains are random)

Main functions:
  extract_url_features(url)   → dict of features + risk score 0–10
  analyze_urls(url_list)      → list of results, sorted by risk
  get_url_flags(url_list)     → human-readable risk strings for UI
"""

import re
import math
import string
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False


# ── Constants ─────────────────────────────────────────────────────────────────

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "short.io", "rebrand.ly", "cutt.ly", "is.gd",
    "shorte.st", "adf.ly", "linktr.ee", "tiny.cc", "bl.ink",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".click", ".download", ".loan", ".win", ".racing",
    ".date", ".trade", ".review", ".stream", ".gdn",
    ".men", ".work", ".party", ".accountant", ".science",
}

TRUSTED_BRANDS = [
    "paypal", "apple", "amazon", "google", "microsoft",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "dropbox", "icloud", "outlook", "office365", "ebay",
    "fedex", "ups", "dhl", "usps", "irs", "bankofamerica",
    "chase", "wellsfargo", "citibank", "hsbc",
]

# Official domains for the above brands
OFFICIAL_DOMAINS = {
    "paypal": "paypal.com",     "apple": "apple.com",
    "amazon": "amazon.com",     "google": "google.com",
    "microsoft": "microsoft.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com",
    "twitter": "twitter.com",   "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",   "icloud": "icloud.com",
    "outlook": "outlook.com",   "ebay": "ebay.com",
}

SUSPICIOUS_KEYWORDS_IN_URL = [
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "banking", "password", "credential",
    "support", "helpdesk", "recover", "suspend", "unlock",
    "validate", "authenticate", "access", "portal", "alert",
]

REDIRECT_PARAMS = ["redirect", "url", "next", "goto", "return", "dest", "forward"]


# ── Entropy Calculation ───────────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy → random-looking string → likely generated/phishing domain.

    Legitimate: 'paypal.com'       → ~2.7
    Phishing:   'xk92mzpq4r.xyz'  → ~3.4+
    """
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


# ── Domain Parsing ────────────────────────────────────────────────────────────

def parse_domain(url: str) -> Dict[str, str]:
    """
    Extract domain components from a URL.

    Returns:
        {subdomain, domain, suffix, registered_domain, full_netloc}
    """
    parsed = urlparse(url if url.startswith("http") else "http://" + url)

    if HAS_TLDEXTRACT:
        ext = tldextract.extract(url)
        return {
            "subdomain":         ext.subdomain,
            "domain":            ext.domain,
            "suffix":            ext.suffix,
            "registered_domain": ext.registered_domain,
            "full_netloc":       parsed.netloc,
        }
    else:
        # Fallback without tldextract
        netloc = parsed.netloc
        parts  = netloc.split(".")
        return {
            "subdomain":         ".".join(parts[:-2]) if len(parts) > 2 else "",
            "domain":            parts[-2] if len(parts) >= 2 else netloc,
            "suffix":            parts[-1] if len(parts) >= 1 else "",
            "registered_domain": ".".join(parts[-2:]) if len(parts) >= 2 else netloc,
            "full_netloc":       netloc,
        }


# ── Individual Feature Extractors ─────────────────────────────────────────────

def check_ip_address(netloc: str) -> bool:
    """True if domain is a raw IP address (e.g. http://192.168.1.1/login)."""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", netloc))


def check_brand_in_subdomain(subdomain: str, domain: str) -> List[str]:
    """
    Detect brand names used in subdomains to fake legitimacy.
    e.g. paypal.secure-login.com → subdomain='paypal', domain='secure-login'
    """
    hits = []
    text = (subdomain + "." + domain).lower()
    for brand in TRUSTED_BRANDS:
        if brand in text:
            # Check if the registered domain is NOT the official one
            official = OFFICIAL_DOMAINS.get(brand, "")
            if official and official not in (domain + "."):
                hits.append(brand)
    return hits


def check_lookalike_domain(domain: str) -> List[str]:
    """
    Detect homograph / typosquatting domains.
    e.g. 'paypa1', 'g00gle', 'arnazon', 'micosoft'
    """
    hits = []
    # Common substitution patterns
    substitutions = {
        "0": "o", "1": "i", "1": "l", "3": "e",
        "4": "a", "5": "s", "vv": "w", "rn": "m",
    }

    domain_lower = domain.lower()
    for brand in TRUSTED_BRANDS:
        if brand == domain_lower:
            continue  # exact match = fine

        # Normalize domain using substitution table
        normalized = domain_lower
        for fake, real in substitutions.items():
            normalized = normalized.replace(fake, real)

        if normalized == brand:
            hits.append(f"{domain} → {brand}")
            continue

        # Edit distance check (simple 1-char diff)
        if len(domain_lower) == len(brand):
            diffs = sum(a != b for a, b in zip(domain_lower, brand))
            if diffs == 1:
                hits.append(f"{domain} ≈ {brand}")

    return hits


def count_suspicious_keywords(url: str) -> List[str]:
    """Find phishing keywords in URL path/params."""
    url_lower = url.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS_IN_URL if kw in url_lower]


def check_redirect_params(url: str) -> List[str]:
    """Detect open redirect parameters in query string."""
    try:
        params = parse_qs(urlparse(url).query)
        return [p for p in REDIRECT_PARAMS if p in params]
    except Exception:
        return []


def check_data_uri(url: str) -> bool:
    """Detect data: URI phishing trick."""
    return url.strip().startswith("data:")


def check_punycode(netloc: str) -> bool:
    """Detect IDN/punycode domains used for homograph attacks (xn--)."""
    return "xn--" in netloc.lower()


# ── Main Feature Extractor ────────────────────────────────────────────────────

def extract_url_features(url: str) -> Dict:
    """
    Extract all features from a single URL and compute a risk score.

    Args:
        url: Full URL string

    Returns:
        Dict containing:
          - All boolean/numeric features
          - risk_score   (int 0–10)
          - risk_level   ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')
          - risk_reasons (list of human-readable strings)
    """
    if not url:
        return {"risk_score": 0, "risk_level": "LOW", "risk_reasons": []}

    # Normalize
    url = unquote(url.strip())
    if not url.startswith(("http://", "https://", "data:")):
        url = "http://" + url

    parsed   = urlparse(url)
    netloc   = parsed.netloc.lower()
    path     = parsed.path.lower()
    dom      = parse_domain(url)
    domain   = dom["domain"].lower()
    subdomain = dom["subdomain"].lower()
    suffix   = "." + dom["suffix"].lower() if dom["suffix"] else ""

    # ── Feature extraction ────────────────────────────────────────────────────
    features = {}

    # Structural
    features["url_length"]          = len(url)
    features["domain_length"]       = len(netloc)
    features["num_subdomains"]      = netloc.count(".")
    features["num_path_segments"]   = len([s for s in path.split("/") if s])
    features["num_query_params"]    = len(parse_qs(parsed.query))
    features["has_port"]            = bool(parsed.port and parsed.port not in (80, 443))
    features["has_fragment"]        = bool(parsed.fragment)

    # Special characters
    features["has_at_symbol"]       = "@" in url
    features["has_double_slash"]    = url.count("//") > 1
    features["has_hyphen_domain"]   = "-" in netloc
    features["hyphen_count"]        = netloc.count("-")
    features["digit_count_domain"]  = sum(c.isdigit() for c in netloc)
    features["special_char_count"]  = sum(c in "%?=&+" for c in url)

    # Trust signals
    features["has_https"]           = parsed.scheme == "https"
    features["is_url_shortener"]    = any(s in netloc for s in URL_SHORTENERS)
    features["has_suspicious_tld"]  = any(netloc.endswith(t) for t in SUSPICIOUS_TLDS)
    features["has_ip_address"]      = check_ip_address(netloc)
    features["has_data_uri"]        = check_data_uri(url)
    features["has_punycode"]        = check_punycode(netloc)

    # Brand / spoofing
    brand_subdomain_hits            = check_brand_in_subdomain(subdomain, domain)
    lookalike_hits                  = check_lookalike_domain(domain)
    features["brand_in_subdomain"]  = bool(brand_subdomain_hits)
    features["is_lookalike_domain"] = bool(lookalike_hits)
    features["spoofed_brands"]      = brand_subdomain_hits + lookalike_hits

    # Suspicious content
    kw_hits                         = count_suspicious_keywords(url)
    redirect_hits                   = check_redirect_params(url)
    features["suspicious_keywords"] = kw_hits
    features["has_redirect_param"]  = bool(redirect_hits)
    features["redirect_params"]     = redirect_hits

    # Entropy
    features["domain_entropy"]      = round(shannon_entropy(domain), 3)
    features["path_entropy"]        = round(shannon_entropy(path), 3)

    # ── Risk Scoring ──────────────────────────────────────────────────────────
    score = 0
    reasons = []

    if features["has_ip_address"]:
        score += 4
        reasons.append(f"🔢 Raw IP address used instead of domain name")

    if features["has_data_uri"]:
        score += 4
        reasons.append("📄 Data URI — commonly used to fake login pages")

    if features["is_lookalike_domain"]:
        score += 4
        for hit in lookalike_hits:
            reasons.append(f"🎭 Lookalike domain detected: {hit}")

    if features["brand_in_subdomain"]:
        score += 3
        for b in brand_subdomain_hits:
            reasons.append(f"🏷️ Brand '{b}' used in subdomain to fake legitimacy")

    if features["is_url_shortener"]:
        score += 2
        reasons.append(f"🔗 URL shortener hides real destination ({netloc})")

    if features["has_suspicious_tld"]:
        score += 2
        reasons.append(f"🌐 Suspicious TLD: {suffix}")

    if features["has_at_symbol"]:
        score += 2
        reasons.append("@ symbol in URL redirects to a different host")

    if features["has_double_slash"]:
        score += 2
        reasons.append("⧸⧸ Double slash redirect detected in URL")

    if features["has_punycode"]:
        score += 3
        reasons.append("🔡 Punycode / IDN domain — possible homograph attack")

    if features["has_redirect_param"]:
        score += 2
        reasons.append(f"↪️ Open redirect parameter: {', '.join(redirect_hits)}")

    if features["domain_entropy"] > 3.5:
        score += 2
        reasons.append(f"🎲 High domain entropy ({features['domain_entropy']}) — looks auto-generated")

    if features["url_length"] > 100:
        score += 1
        reasons.append(f"📏 Unusually long URL ({features['url_length']} chars)")

    if features["num_subdomains"] > 3:
        score += 1
        reasons.append(f"🪜 Many subdomains ({features['num_subdomains']}) used to hide real domain")

    if len(kw_hits) >= 2:
        score += 1
        reasons.append(f"🔑 Phishing keywords in URL: {', '.join(kw_hits[:3])}")

    if features["digit_count_domain"] > 3:
        score += 1
        reasons.append(f"🔢 Many digits in domain name ({features['digit_count_domain']})")

    if not features["has_https"]:
        score += 1
        reasons.append("🔓 No HTTPS — connection is not encrypted")

    # Cap at 10
    score = min(score, 10)

    # Risk level
    if score >= 7:
        risk_level = "CRITICAL"
    elif score >= 5:
        risk_level = "HIGH"
    elif score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        **features,
        "url":         url,
        "risk_score":  score,
        "risk_level":  risk_level,
        "risk_reasons": reasons,
    }


# ── Analyze Multiple URLs ─────────────────────────────────────────────────────

def analyze_urls(url_list: List[str]) -> List[Dict]:
    """
    Analyze a list of URLs and return results sorted by risk (highest first).

    Args:
        url_list: List of URL strings

    Returns:
        List of feature dicts, sorted by risk_score descending
    """
    results = [extract_url_features(url) for url in url_list if url.strip()]
    return sorted(results, key=lambda x: x["risk_score"], reverse=True)


def get_url_flags(url_list: List[str]) -> List[str]:
    """
    Get a flat list of human-readable risk flags from all URLs combined.
    Used by model.py to pass reasons to the popup UI.

    Args:
        url_list: List of URL strings

    Returns:
        Deduplicated list of risk reason strings
    """
    if not url_list:
        return []

    results = analyze_urls(url_list)
    flags = []
    seen  = set()

    for r in results:
        if r["risk_score"] > 3:
            for reason in r["risk_reasons"]:
                if reason not in seen:
                    flags.append(reason)
                    seen.add(reason)

    return flags


def get_max_url_risk(url_list: List[str]) -> int:
    """Return the highest risk_score across all URLs in the list."""
    if not url_list:
        return 0
    return max(r["risk_score"] for r in analyze_urls(url_list))


# ── Quick Test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        # High risk
        "http://192.168.1.1/paypal/login",
        "http://paypal.secure-verify.xyz/confirm?redirect=http://evil.com",
        "https://paypa1.com/account/suspended",
        "http://bit.ly/3xKp9mZ",
        "https://xn--pple-43d.com/id/login",      # punycode apple

        # Medium risk
        "http://login-microsoft-support.com/verify",
        "https://amazon-account-update.com/signin",

        # Low risk
        "https://google.com/search?q=phishing",
        "https://github.com/user/repo",
    ]

    print("=" * 65)
    print("URL ANALYZER — TEST RESULTS")
    print("=" * 65)

    for url in test_urls:
        result = extract_url_features(url)
        print(f"\n🔗 {url[:60]}")
        print(f"   Risk: {result['risk_score']}/10  [{result['risk_level']}]")
        for reason in result["risk_reasons"]:
            print(f"   {reason}")
