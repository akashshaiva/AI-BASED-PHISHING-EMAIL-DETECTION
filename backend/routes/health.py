from flask import Blueprint, jsonify

health_bp = Blueprint("health_bp", __name__)


@health_bp.route("/api/health", methods=["GET"])
def health_check():
    return jsonify(
        {
            "status": "ok",
            "service": "AI-Based Phishing Email Detection System",
            "mode": "development",
        }
    )
