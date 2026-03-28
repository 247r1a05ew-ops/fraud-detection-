# qr_utils.py
# Utility file for decoding and analyzing QR code images

from PIL import Image, ImageEnhance, ImageFilter
from pyzbar.pyzbar import decode
import cv2
import numpy as np

try:
    # When imported as a module from app.py
    from detectors.url_detector import analyze_url
    from detectors.sms_detector import analyze_sms
    from utils.risk_engine import finalize_result
except ImportError:
    # Fallback for relative imports
    from .url_detector import analyze_url
    from .sms_detector import analyze_sms
    from ..utils.risk_engine import finalize_result


def decode_qr_with_pyzbar(image_path):
    """
    Decode QR using pyzbar (good for many standard QR images)
    """
    try:
        img = Image.open(image_path)
        decoded_objects = decode(img)

        if decoded_objects:
            return decoded_objects[0].data.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass

    return None


def decode_qr_with_opencv(image):
    """
    Decode QR using OpenCV QRCodeDetector
    Accepts image matrix (numpy array)
    """
    try:
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(image)

        if data:
            return data.strip()
    except Exception:
        pass

    return None


def generate_preprocessed_versions(image_path):
    """
    Generate multiple preprocessed image versions to improve QR detection.
    This increases the chance of scanning difficult QR screenshots.
    """
    versions = []

    try:
        img = cv2.imread(image_path)

        if img is None:
            return versions

        # 1. Original
        versions.append(img)

        # 2. Grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        versions.append(gray)

        # 3. Binary threshold
        _, thresh = cv2.threshold(gray, 120, 255, cv2.THRESH_BINARY)
        versions.append(thresh)

        # 4. Adaptive threshold
        adaptive = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
        )
        versions.append(adaptive)

        # 5. Enlarged grayscale
        enlarged = cv2.resize(gray, None, fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC)
        versions.append(enlarged)

        # 6. Enlarged threshold
        enlarged_thresh = cv2.resize(thresh, None, fx=2.5, fy=2.5, interpolation=cv2.INTER_CUBIC)
        versions.append(enlarged_thresh)

        # 7. Inverted grayscale
        inverted = cv2.bitwise_not(gray)
        versions.append(inverted)

        # 8. Denoised
        denoised = cv2.fastNlMeansDenoising(gray, None, 30, 7, 21)
        versions.append(denoised)

        # 9. Sharpened
        kernel = np.array([[0, -1, 0],
                           [-1, 5, -1],
                           [0, -1, 0]])
        sharpened = cv2.filter2D(gray, -1, kernel)
        versions.append(sharpened)

    except Exception:
        pass

    return versions


def preprocess_and_decode(image_path):
    """
    Try decoding QR code using multiple image preprocessing methods.
    """
    versions = generate_preprocessed_versions(image_path)

    for version in versions:
        data = decode_qr_with_opencv(version)
        if data:
            return data

    # Try pyzbar as fallback on original image
    data = decode_qr_with_pyzbar(image_path)
    if data:
        return data

    return None


def analyze_qr(image_path):
    """
    Analyze QR code content and classify it as Safe / Suspicious / Fraud.
    """
    reasons = []
    risk = 0

    # Step 1: Decode QR
    qr_data = preprocess_and_decode(image_path)

    # If not decoded
    if not qr_data:
        return {
            "status": "Unknown",
            "risk": 0,
            "reasons": [
                "⚠ QR code could not be decoded clearly.",
                "Please upload a clearer, uncropped, high-resolution QR image.",
                "Possible reasons: blur, low contrast, partial screenshot, dark mode, too much background."
            ]
        }

    reasons.append("📷 QR code detected successfully")

    short_preview = qr_data if len(qr_data) <= 120 else qr_data[:120] + "..."
    reasons.append(f"📦 QR contains: {short_preview}")

    qr_lower = qr_data.lower()

    # --------------------------------------------------
    # 1) UPI QR Detection (common in India)
    # --------------------------------------------------
    if qr_lower.startswith("upi://pay"):
        reasons.append("💳 UPI payment QR detected")
        risk += 5  # small base risk because payment requests should always be verified

        suspicious_words = [
            "urgent", "verify", "refund", "reward", "claim", "kyc",
            "blocked", "suspended", "legal", "court", "fine", "penalty",
            "otp", "bank", "update"
        ]

        found_suspicious = False
        for word in suspicious_words:
            if word in qr_lower:
                risk += 10
                found_suspicious = True
                reasons.append(f"⚠ Suspicious term inside UPI QR: {word}")

        if "legal" in qr_lower or "court" in qr_lower or "penalty" in qr_lower:
            risk += 15
            reasons.append("⚠ Legal-pressure style content found in UPI QR")

        if not found_suspicious and risk <= 10:
            return {
                "status": "Safe",
                "risk": risk,
                "reasons": reasons + [
                    "ℹ Normal UPI payment QR detected.",
                    "Always verify the receiver name and UPI ID before making payment."
                ]
            }

    # --------------------------------------------------
    # 2) URL QR Detection
    # --------------------------------------------------
    elif qr_data.startswith("http://") or qr_data.startswith("https://"):
        url_result = analyze_url(qr_data)

        # Use weighted contribution instead of full risk addition
        risk += int(url_result["risk"] * 0.9)

        reasons.append(f"🌐 QR URL analysis: {url_result['status']} ({url_result['risk']}%)")
        for r in url_result["reasons"][:6]:
            reasons.append(f"• {r}")

    # --------------------------------------------------
    # 3) Domain-like QR (example: google.com)
    # --------------------------------------------------
    elif "." in qr_data and " " not in qr_data and not qr_lower.startswith("upi://"):
        possible_url = "http://" + qr_data
        url_result = analyze_url(possible_url)

        risk += int(url_result["risk"] * 0.8)

        reasons.append(f"🌐 QR URL-like content analysis: {url_result['status']} ({url_result['risk']}%)")
        for r in url_result["reasons"][:6]:
            reasons.append(f"• {r}")

    # --------------------------------------------------
    # 4) Text QR Detection
    # --------------------------------------------------
    else:
        sms_result = analyze_sms(qr_data)

        risk += int(sms_result["risk"] * 0.85)

        reasons.append(f"📝 QR text analysis: {sms_result['status']} ({sms_result['risk']}%)")
        for r in sms_result["reasons"][:6]:
            reasons.append(f"• {r}")

    # Final classification
    return finalize_result(risk, reasons)