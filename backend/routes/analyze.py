from flask import Blueprint, jsonify, request

from database import save_scan_record
from services.analyze_service import analyze_email

analyze_bp = Blueprint("analyze_bp", __name__)


def _build_reasons(result):
    reasons = []
    url_analysis = result.get("url_analysis", {}) or {}
    summary = url_analysis.get("summary", {}) or {}

    suspicious_keywords = summary.get("suspicious_keywords") or []
    if suspicious_keywords:
        reasons.extend([f"Suspicious keyword: {keyword}" for keyword in suspicious_keywords])

    if isinstance(url_analysis.get("count"), int) and url_analysis["count"] > 0:
        reasons.append(f"{url_analysis['count']} URL(s) found")

    if result.get("prediction") == 1:
        reasons.append("Model classified the email as phishing")

    if not reasons:
        reasons.append("No major suspicious indicators detected")

    return reasons


@analyze_bp.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)

    if data is None:
        return jsonify({"error": "Request body must be valid JSON."}), 400

    try:
        result = analyze_email(data)
        sender = str(data.get("sender") or "unknown").strip() or "unknown"
        subject = str(data.get("subject") or "No subject").strip() or "No subject"
        url_analysis = result.get("url_analysis", {}) or {}
        url_count = int(url_analysis.get("count") or 0)
        reasons = _build_reasons(result)

        saved_record = save_scan_record(
            sender=sender,
            subject=subject,
            prediction=result.get("prediction", 0),
            confidence=result.get("confidence", 0.0),
            risk_level=result.get("risk_level", "low"),
            url_count=url_count,
            reasons=reasons,
        )
        if saved_record is None:
            result["warning"] = "Analysis completed, but scan history could not be saved because the database is unavailable."
    except ValueError:
        return jsonify({"error": "Invalid input", "message": "Please check the sender, subject, and email body."}), 400
    except Exception:
        return jsonify({"error": "Internal server error", "message": "The analysis service could not complete the request."}), 500

    return jsonify(result), 200
