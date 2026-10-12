import io
import re
from pathlib import Path

try:
    from PIL import Image, UnidentifiedImageError
except ImportError:  # pragma: no cover
    Image = None
    UnidentifiedImageError = Exception

SUSPICIOUS_FILENAME_KEYWORDS = [
    "login",
    "verify",
    "security",
    "password",
    "bank",
    "account",
    "urgent",
    "invoice",
    "confirm",
    "update",
    "reset",
    "pay",
]


def _extract_keywords(filename):
    if not filename:
        return []
    lowered = re.sub(r"[^a-z0-9]+", " ", filename.lower())
    tokens = lowered.split()
    hits = [token for token in tokens if token in SUSPICIOUS_FILENAME_KEYWORDS]
    return sorted(set(hits))


def analyze_screenshot(file_bytes, filename=""):
    if not file_bytes:
        return {
            "file_name": filename,
            "is_suspicious": False,
            "risk_level": "low",
            "reasons": ["No screenshot content was provided."],
            "width": None,
            "height": None,
            "size_bytes": 0,
            "suspicious_keywords": [],
            "file_type": "unknown",
        }

    size_bytes = len(file_bytes)
    file_type = "unknown"
    width = None
    height = None
    suspicious_keywords = _extract_keywords(filename)
    reasons = []

    suffix = Path(filename).suffix.lower() if filename else ""
    if suffix in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}:
        file_type = suffix.lstrip(".")

    if Image is not None:
        try:
            with Image.open(io.BytesIO(file_bytes)) as image:
                width, height = image.size
                if image.format:
                    file_type = image.format.lower()
        except (UnidentifiedImageError, OSError, ValueError):
            width = None
            height = None

    if size_bytes > 5 * 1024 * 1024:
        reasons.append("Large screenshot file size")

    if width and height:
        if max(width, height) > 5000 or min(width, height) < 150:
            reasons.append("Unusual screenshot dimensions")

    if suspicious_keywords:
        reasons.append("Screenshot filename suggests a login or verification flow")

    if not reasons:
        risk_level = "low"
        is_suspicious = False
    else:
        risk_level = "high" if len(reasons) >= 2 else "medium"
        is_suspicious = True

    return {
        "file_name": filename or "unknown screenshot",
        "is_suspicious": is_suspicious,
        "risk_level": risk_level,
        "reasons": reasons or ["No strong screenshot-based phishing indicators were detected."],
        "width": width,
        "height": height,
        "size_bytes": size_bytes,
        "suspicious_keywords": suspicious_keywords,
        "file_type": file_type,
        "summary": {
            "suspicious_keywords": suspicious_keywords,
            "width": width,
            "height": height,
            "size_bytes": size_bytes,
        },
    }
