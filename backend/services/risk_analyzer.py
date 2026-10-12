import re


URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "action required",
    "final notice",
    "limited time",
    "verify now",
    "expires soon",
    "suspended",
    "secure your account",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "login",
    "verify account",
    "reset password",
    "update credentials",
    "bank account",
    "security alert",
    "confirm identity",
]

WARNING_KEYWORDS = [
    "click here",
    "claim reward",
    "urgent action",
    "winner",
    "invoice",
    "payment required",
    "tax refund",
]


def _contains_any(text, keywords):
    if not text:
        return []
    lowered = text.lower()
    found = []
    for keyword in keywords:
        if keyword in lowered:
            found.append(keyword)
    return found


def _build_recommendation(reasons):
    if not reasons:
        return "Review the message carefully and verify the sender through a trusted channel."

    if any("Credential-related request detected" in r for r in reasons):
        return "Do not click or enter credentials. Contact the organization directly using a trusted channel."

    if any("Suspicious URL detected" in r for r in reasons):
        return "Avoid opening the link and verify the request through official contact methods."

    if any("Sender/Reply-To mismatch" in r for r in reasons):
        return "Treat this message as suspicious and verify the sender independently before responding."

    if any("Authentication warning" in r for r in reasons):
        return "Check the email headers and verify authentication records before trusting the message."

    return "Exercise caution and verify the request through an official source before taking action."


def analyze_risk(prediction, confidence, url_analysis=None, header_analysis=None, text=None, screenshot_analysis=None):
    url_analysis = url_analysis or {}
    header_analysis = header_analysis or {}
    screenshot_analysis = screenshot_analysis or {}
    text = text or ""

    reasons = []
    if prediction == 1:
        reasons.append("ML model classified the message as phishing")

    if confidence is not None:
        if confidence >= 0.75:
            reasons.append("High model confidence in phishing classification")
        elif confidence >= 0.6:
            reasons.append("Moderate model confidence in phishing classification")

    url_summary = (url_analysis or {}).get("summary") or {}
    if isinstance(url_analysis, dict) and int(url_analysis.get("count") or 0) > 0:
        reasons.append("Suspicious URL detected")

    if url_summary.get("suspicious_keywords"):
        reasons.append("Suspicious URL keywords detected")

    if isinstance(header_analysis, dict):
        indicators = header_analysis.get("indicators") or []
        if any(item.get("type") == "from_reply_to_mismatch" for item in indicators):
            reasons.append("Sender/Reply-To mismatch")
        if any(item.get("type") == "return_path_mismatch" for item in indicators):
            reasons.append("Return-Path mismatch")
        if any(item.get("type") == "authentication_results_present" for item in indicators):
            auth_results = header_analysis.get("auth_results") or {}
            if auth_results:
                for key, value in auth_results.items():
                    if isinstance(value, dict) and value.get("status") in {"fail", "softfail", "not_found"}:
                        reasons.append("Authentication warning")
                        break

    if isinstance(screenshot_analysis, dict):
        if screenshot_analysis.get("is_suspicious"):
            reasons.append("Suspicious screenshot detected")
        if screenshot_analysis.get("suspicious_keywords"):
            reasons.append("Screenshot contains login or verification wording")

    detected_urgent = _contains_any(text, URGENT_KEYWORDS)
    if detected_urgent:
        reasons.append("Urgent language detected")

    detected_credentials = _contains_any(text, CREDENTIAL_KEYWORDS)
    if detected_credentials:
        reasons.append("Credential-related request detected")

    warning_hits = _contains_any(text, WARNING_KEYWORDS)
    if warning_hits:
        reasons.append("Urgency or scam language detected")

    unique_reasons = []
    seen = set()
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            unique_reasons.append(reason)

    if prediction == 1 and not reasons:
        reasons = ["ML model classified the message as phishing"]

    if prediction == 0 and not reasons:
        reasons = ["No strong phishing indicators were detected during analysis"]

    if prediction == 1:
        if confidence is not None and confidence >= 0.7:
            risk_level = "high"
        elif confidence is not None and confidence >= 0.55:
            risk_level = "medium"
        else:
            risk_level = "medium"
    else:
        risk_level = "low"

    if prediction == 1 and len(unique_reasons) >= 3:
        risk_level = "high"

    if isinstance(screenshot_analysis, dict) and screenshot_analysis.get("risk_level") in {"medium", "high"}:
        if risk_level == "low":
            risk_level = screenshot_analysis["risk_level"]
        elif screenshot_analysis["risk_level"] == "high":
            risk_level = "high"

    recommendation = _build_recommendation(unique_reasons)

    return {
        "prediction": int(prediction),
        "confidence": float(confidence) if confidence is not None else 0.0,
        "risk_level": risk_level,
        "reasons": unique_reasons,
        "recommendation": recommendation,
    }
