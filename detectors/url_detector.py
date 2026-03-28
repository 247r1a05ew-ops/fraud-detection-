from urllib.parse import urlparse
from utils.risk_engine import finalize_result

TRUSTED_DOMAINS = [
    "google.com", "amazon.in", "amazon.com", "flipkart.com",
    "paytm.com", "phonepe.com", "icicibank.com", "sbi.co.in",
    "hdfcbank.com", "axisbank.com", "youtube.com", "github.com"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "reward", "gift",
    "refund", "claim", "free", "winner", "lottery", "bonus"
]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".cf", ".gq"]


def analyze_url(url):
    url = url.strip()
    url_lower = url.lower()
    risk = 0
    reasons = []

    # Add protocol if missing
    if not url_lower.startswith(("http://", "https://")):
        url_lower = "http://" + url_lower
        reasons.append("No protocol provided, treated as HTTP for analysis")

    parsed = urlparse(url_lower)
    domain = parsed.netloc.lower()

    # Remove www.
    if domain.startswith("www."):
        domain = domain[4:]

    # =========================
    # 1. Trusted domain check first
    # =========================
    if any(td == domain or domain.endswith("." + td) for td in TRUSTED_DOMAINS):
        risk -= 25
        reasons.append(f"Trusted domain detected: {domain}")

    # =========================
    # 2. HTTP only
    # =========================
    if url_lower.startswith("http://"):
        risk += 18
        reasons.append("Insecure HTTP link detected")

    # =========================
    # 3. Suspicious TLD
    # =========================
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        risk += 30
        reasons.append("Suspicious domain extension detected")

    # =========================
    # 4. Suspicious keywords
    # =========================
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_keywords:
        risk += min(len(matched_keywords) * 8, 24)
        reasons.append(f"Suspicious URL keywords found: {', '.join(matched_keywords[:4])}")

    # =========================
    # 5. Too many hyphens
    # =========================
    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        risk += 15
        reasons.append("Domain contains multiple hyphens (common in fake sites)")

    # =========================
    # 6. Too long domain
    # =========================
    if len(domain) > 30:
        risk += 10
        reasons.append("Long domain name detected")

    # =========================
    # 7. IP address URL
    # =========================
    domain_parts = domain.split(".")
    if len(domain_parts) == 4 and all(part.isdigit() for part in domain_parts):
        risk += 35
        reasons.append("IP address used instead of domain")

    # =========================
    # 8. @ symbol
    # =========================
    if "@" in url_lower:
        risk += 25
        reasons.append("@ symbol detected in URL (possible masking attack)")

    # Clamp
    risk = max(0, min(100, risk))

    if not reasons:
        reasons.append("No major suspicious indicators found.")

    return finalize_result(risk, reasons)