import re
from utils.risk_engine import finalize_result

# High-risk scam keywords
HIGH_RISK_KEYWORDS = [
    "otp", "atm pin", "cvv", "pin", "bank account blocked",
    "account blocked", "suspended", "verify now", "urgent action",
    "claim prize", "lottery winner", "refund now", "share otp",
    "send otp", "update kyc", "click below", "login now"
]

# Medium-risk suspicious words
MEDIUM_RISK_KEYWORDS = [
    "urgent", "verify", "claim", "reward", "winner", "lottery",
    "kyc", "refund", "limited time", "immediately", "congratulations",
    "bank", "account", "payment failed", "offer", "free gift"
]

# Trusted domains (reduce risk)
TRUSTED_DOMAINS = [
    "google.com", "amazon.in", "amazon.com", "flipkart.com",
    "paytm.com", "phonepe.com", "icicibank.com", "sbi.co.in",
    "hdfcbank.com", "axisbank.com"
]


def extract_urls(text):
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(url_pattern, text, flags=re.IGNORECASE)


def is_trusted_url(url):
    url = url.lower()
    return any(domain in url for domain in TRUSTED_DOMAINS)


def analyze_sms(text):
    text_lower = text.lower()
    risk = 0
    reasons = []

    # =========================
    # 1. High-risk keywords
    # =========================
    high_matches = []
    for kw in HIGH_RISK_KEYWORDS:
        if kw in text_lower:
            high_matches.append(kw)

    if high_matches:
        risk += min(len(high_matches) * 18, 45)
        reasons.append(f"High-risk scam indicators found: {', '.join(high_matches[:4])}")

    # =========================
    # 2. Medium-risk keywords
    # =========================
    medium_matches = []
    for kw in MEDIUM_RISK_KEYWORDS:
        if kw in text_lower:
            medium_matches.append(kw)

    if medium_matches:
        risk += min(len(medium_matches) * 7, 25)
        reasons.append(f"Suspicious words found: {', '.join(medium_matches[:5])}")

    # =========================
    # 3. URLs inside SMS
    # =========================
    urls = extract_urls(text)
    if urls:
        reasons.append(f"{len(urls)} link(s) found in SMS")

        for url in urls[:2]:
            url_lower = url.lower()

            if url_lower.startswith("http://"):
                risk += 18
                reasons.append(f"Insecure HTTP link detected: {url}")

            if any(x in url_lower for x in [".xyz", ".tk", ".ml", ".cf", ".gq"]):
                risk += 22
                reasons.append(f"Suspicious domain extension in link: {url}")

            suspicious_terms = ["verify", "login", "secure", "update", "reward", "gift", "refund", "claim"]
            matched_terms = [t for t in suspicious_terms if t in url_lower]
            if matched_terms:
                risk += min(len(matched_terms) * 6, 18)
                reasons.append(f"Suspicious link keywords found: {', '.join(matched_terms)}")

            if is_trusted_url(url):
                risk -= 15
                reasons.append(f"Trusted domain detected: {url}")

    # =========================
    # 4. Urgency + financial request combo
    # =========================
    urgency_words = ["urgent", "immediately", "now", "today", "asap"]
    financial_words = ["bank", "account", "otp", "pin", "cvv", "payment", "refund", "upi"]

    if any(u in text_lower for u in urgency_words) and any(f in text_lower for f in financial_words):
        risk += 20
        reasons.append("Urgency combined with financial/account-related request")

    # =========================
    # 5. Message length sanity
    # =========================
    if len(text.strip()) < 15:
        risk -= 5

    # Clamp
    risk = max(0, min(100, risk))

    if not reasons:
        reasons.append("No major suspicious indicators found.")

    return finalize_result(risk, reasons)