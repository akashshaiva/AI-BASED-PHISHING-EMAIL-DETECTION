from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from database import save_scan_record
from services.analyze_service import analyze_email
from services.email_parser import parse_eml
from services.screenshot_analyzer import analyze_screenshot

upload_bp = Blueprint("upload_bp", __name__)


def _build_reasons(result):
    reasons = []
    url_analysis = result.get("url_analysis", {}) or {}
    summary = url_analysis.get("summary", {}) or {}
    screenshot_analysis = result.get("screenshot_analysis", {}) or {}

    suspicious_keywords = summary.get("suspicious_keywords") or []
    if suspicious_keywords:
        reasons.extend([f"Suspicious keyword: {keyword}" for keyword in suspicious_keywords])

    if isinstance(url_analysis.get("count"), int) and url_analysis["count"] > 0:
        reasons.append(f"{url_analysis['count']} URL(s) found")

    if isinstance(screenshot_analysis, dict):
        if screenshot_analysis.get("is_suspicious"):
            reasons.append("Suspicious screenshot detected")
        if screenshot_analysis.get("suspicious_keywords"):
            reasons.extend([f"Screenshot keyword: {keyword}" for keyword in screenshot_analysis["suspicious_keywords"]])

    if result.get("prediction") == 1:
        reasons.append("Model classified the email as phishing")

    if not reasons:
        reasons.append("No major suspicious indicators detected")

    return reasons


@upload_bp.route("/api/upload", methods=["POST"])
def upload_email():
    if "file" not in request.files and "screenshot" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    email_file = request.files.get("file")
    screenshot_file = request.files.get("screenshot")

    screenshot_analysis = None
    if screenshot_file and screenshot_file.filename:
        screenshot_name = secure_filename(screenshot_file.filename or "")
        if not screenshot_name:
            return jsonify({"error": "Screenshot file could not be processed."}), 400
        image_extension = "." + screenshot_name.rsplit(".", 1)[-1].lower() if "." in screenshot_name else ""
        if image_extension.lower() not in {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}:
            return jsonify({"error": "Only image screenshot files are allowed for the screenshot input."}), 400
        screenshot_data = screenshot_file.read()
        if not screenshot_data:
            return jsonify({"error": "Uploaded screenshot is empty."}), 400
        screenshot_analysis = analyze_screenshot(screenshot_data, screenshot_name)

    if email_file is None:
        return jsonify({"error": "No email file was uploaded."}), 400

    if email_file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    allowed_extensions = current_app.config.get("ALLOWED_EXTENSIONS", {".eml"})
    filename = secure_filename(email_file.filename or "")
    suffix = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if not filename or suffix.lower() not in {ext.lower() for ext in allowed_extensions}:
        return jsonify({"error": "Only .eml files are allowed."}), 400

    email_file.stream.seek(0, 2)
    file_size = email_file.stream.tell()
    email_file.stream.seek(0)

    if file_size <= 0:
        return jsonify({"error": "Uploaded file is empty."}), 400

    max_upload_size = current_app.config.get("MAX_CONTENT_LENGTH", 5 * 1024 * 1024)
    if file_size > max_upload_size:
        return jsonify({"error": f"File is too large. Maximum allowed size is {max_upload_size / (1024 * 1024):.0f}MB."}), 400

    content = email_file.read()

    try:
        parsed_email = parse_eml(content)
    except Exception:
        return jsonify({"error": "Failed to parse the .eml file.", "message": "The uploaded file is not a valid .eml message."}), 400

    sender = parsed_email.get("From") or "unknown"
    subject = parsed_email.get("Subject") or "No subject"
    body = parsed_email.get("body") or ""

    if not body.strip():
        return jsonify({"error": "The uploaded .eml file does not contain readable email body text."}), 400

    try:
        analysis_payload = {"sender": sender, "subject": subject, "body": body, "headers": parsed_email}
        if screenshot_analysis is not None:
            analysis_payload["screenshot_analysis"] = screenshot_analysis
        analysis = analyze_email(analysis_payload)
        url_analysis = analysis.get("url_analysis", {}) or {}
        reasons = _build_reasons(analysis)

        saved_record = save_scan_record(
            sender=sender,
            subject=subject,
            prediction=analysis.get("prediction", 0),
            confidence=analysis.get("confidence", 0.0),
            risk_level=analysis.get("risk_level", "low"),
            url_count=int(url_analysis.get("count") or 0),
            reasons=reasons,
        )
        if saved_record is None:
            analysis["warning"] = "Email was analyzed successfully, but the database is currently unavailable so history was not saved."
    except Exception:
        return jsonify({"error": "Failed to analyze uploaded email.", "message": "The uploaded message could not be analyzed at this time."}), 500

    response_payload = {
        "message": "Email parsed and analyzed successfully.",
        "email": {
            "from": parsed_email.get("From"),
            "to": parsed_email.get("To"),
            "subject": parsed_email.get("Subject"),
            "reply_to": parsed_email.get("Reply-To"),
            "return_path": parsed_email.get("Return-Path"),
            "authentication_results": parsed_email.get("Authentication-Results"),
            "body": body,
            "html_body": parsed_email.get("html_body"),
            "urls": parsed_email.get("urls", []),
        },
        "analysis": analysis,
    }
    if screenshot_analysis is not None:
        response_payload["screenshot_analysis"] = screenshot_analysis

    return jsonify(response_payload)
