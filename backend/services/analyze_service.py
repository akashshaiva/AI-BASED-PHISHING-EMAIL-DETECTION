import sys
from functools import lru_cache
from pathlib import Path

import joblib

from services.header_analyzer import analyze_email_headers
from services.risk_analyzer import analyze_risk
from services.screenshot_analyzer import analyze_screenshot
from services.url_analyzer import analyze_url_features

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.preprocess import clean_text

MODEL_NAME = "Logistic Regression"


@lru_cache(maxsize=1)
def get_model_assets():
    model_dir = PROJECT_ROOT / "ml" / "models"
    vectorizer_path = model_dir / "tfidf_vectorizer.joblib"
    model_path = model_dir / "logistic_regression.joblib"

    if not vectorizer_path.exists() or not model_path.exists():
        raise FileNotFoundError(
            "Trained ML model files not found. Please train the model before using /api/analyze."
        )

    vectorizer = joblib.load(vectorizer_path)
    model = joblib.load(model_path)
    return vectorizer, model


def _clean_string(value, field_name):
    if value is None:
        raise ValueError(f"{field_name} is required.")

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")

    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty.")

    return cleaned


def analyze_email(data):
    sender = _clean_string(data.get("sender"), "sender")
    subject = _clean_string(data.get("subject"), "subject")
    body = _clean_string(data.get("body"), "body")

    combined_text = f"{subject} {body}".strip()
    processed_text = clean_text(combined_text)

    vectorizer, model = get_model_assets()
    features = vectorizer.transform([processed_text])
    prediction = int(model.predict(features)[0])

    confidence = 0.0
    probabilities = None
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)[0]
        confidence = float(max(probabilities))

    url_analysis = analyze_url_features(combined_text)
    header_data = data.get("headers") if isinstance(data, dict) else None
    header_analysis = analyze_email_headers(header_data) if header_data is not None else analyze_email_headers({})

    screenshot_analysis = data.get("screenshot_analysis") if isinstance(data, dict) else None
    if screenshot_analysis is None and isinstance(data, dict) and data.get("screenshot") is not None:
        screenshot_analysis = analyze_screenshot(data["screenshot"].read(), getattr(data["screenshot"], "filename", ""))

    risk_summary = analyze_risk(
        prediction=prediction,
        confidence=confidence,
        url_analysis=url_analysis,
        header_analysis=header_analysis,
        text=combined_text,
        screenshot_analysis=screenshot_analysis,
    )

    result = {
        "prediction": risk_summary["prediction"],
        "confidence": confidence,
        "model_name": MODEL_NAME,
        "risk_level": risk_summary["risk_level"],
        "url_analysis": url_analysis,
        "header_analysis": header_analysis,
        "reasons": risk_summary["reasons"],
        "recommendation": risk_summary["recommendation"],
    }

    if screenshot_analysis is not None:
        result["screenshot_analysis"] = screenshot_analysis

    if probabilities is not None:
        result["probabilities"] = {
            "legitimate": float(probabilities[0]),
            "phishing": float(probabilities[1]),
        }

    return result
