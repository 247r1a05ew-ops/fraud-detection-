import re
import cv2
import pytesseract
from PIL import Image
from pyzbar.pyzbar import decode
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
from detectors.sms_detector import analyze_sms
from detectors.url_detector import analyze_url
from detectors.qr_detector import analyze_qr
from utils.risk_engine import finalize_result


def extract_text_basic(image_path):
    """
    Basic OCR using pytesseract
    """
    try:
        text = pytesseract.image_to_string(Image.open(image_path))
        return text.strip()
    except:
        return ""


def extract_text_advanced(image_path):
    """
    Try multiple OCR methods for better screenshot reading
    """
    texts = []

    try:
        # 1. Original
        img_pil = Image.open(image_path)
        t1 = pytesseract.image_to_string(img_pil).strip()
        if t1:
            texts.append(t1)
    except:
        pass

    try:
        # 2. OpenCV grayscale
        img = cv2.imread(image_path)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        t2 = pytesseract.image_to_string(gray).strip()
        if t2:
            texts.append(t2)
    except:
        pass

    try:
        # 3. Threshold
        img = cv2.imread(image_path)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)
        t3 = pytesseract.image_to_string(thresh).strip()
        if t3:
            texts.append(t3)
    except:
        pass

    try:
        # 4. Enlarged grayscale
        img = cv2.imread(image_path)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        enlarged = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        t4 = pytesseract.image_to_string(enlarged).strip()
        if t4:
            texts.append(t4)
    except:
        pass

    if not texts:
        return ""

    # return longest extracted text
    texts = sorted(texts, key=len, reverse=True)
    return texts[0]


def extract_urls(text):
    """
    Find URLs inside OCR text
    """
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(url_pattern, text, flags=re.IGNORECASE)


def detect_qr_from_image(image_path):
    """
    Direct QR detection from image before OCR
    """
    try:
        img = Image.open(image_path)
        decoded = decode(img)
        if decoded:
            return decoded[0].data.decode("utf-8", errors="ignore").strip()
    except:
        pass
    return None


def analyze_image(image_path):
    reasons = []
    total_risk = 0

    # =========================
    # STEP 1: Check QR inside image
    # =========================
    qr_data = detect_qr_from_image(image_path)
    if qr_data:
        reasons.append("📷 QR code found inside image")
        qr_result = analyze_qr(image_path)
        total_risk += qr_result["risk"]
        reasons.append(f"🔍 QR analysis result: {qr_result['status']} ({qr_result['risk']}%)")
        for r in qr_result["reasons"][:6]:
            reasons.append(f"• {r}")

    # =========================
    # STEP 2: OCR text extraction
    # =========================
    text = extract_text_advanced(image_path)

    if not text:
        # IMPORTANT CHANGE: don't mark Safe directly
        return {
            "status": "Suspicious",
            "risk": max(25, total_risk),
            "reasons": reasons + [
                "⚠ No readable text detected in image.",
                "This may be a screenshot, logo, payment proof, QR-only image, or low-quality image.",
                "OCR could not clearly extract content, so it should not be marked fully safe.",
                "Try a clearer image for better detection."
            ]
        }

    # Short preview only
    preview = text[:180].replace("\n", " ")
    reasons.append("📝 Readable text detected in image")
    reasons.append(f"📄 Extracted text preview: {preview}...")

    # =========================
    # STEP 3: Analyze extracted text as SMS-like scam text
    # =========================
    sms_result = analyze_sms(text)
    total_risk += sms_result["risk"]
    reasons.append(f"📨 Text scam analysis: {sms_result['status']} ({sms_result['risk']}%)")
    for r in sms_result["reasons"][:6]:
        reasons.append(f"• {r}")

    # =========================
    # STEP 4: Detect URLs in text and analyze them
    # =========================
    urls = extract_urls(text)
    if urls:
        reasons.append(f"🌐 {len(urls)} URL(s) found in image text")

        # Analyze max 2 URLs to avoid too much noise
        for url in urls[:2]:
            if not url.startswith("http"):
                url = "http://" + url

            url_result = analyze_url(url)
            total_risk += int(url_result["risk"] * 0.7)  # weighted, not full duplicate risk
            reasons.append(f"🔗 URL analysis: {url_result['status']} ({url_result['risk']}%)")
            for r in url_result["reasons"][:4]:
                reasons.append(f"• {r}")

    # cap risk
    if total_risk > 100:
        total_risk = 100

    return finalize_result(total_risk, reasons)