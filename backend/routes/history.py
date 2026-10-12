from flask import Blueprint, jsonify

from database import get_dashboard_stats, get_recent_scan_history

history_bp = Blueprint("history_bp", __name__)


@history_bp.route("/api/history", methods=["GET"])
def get_history():
    history = get_recent_scan_history(limit=50)
    return jsonify(history), 200


@history_bp.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    stats = get_dashboard_stats()
    return jsonify(stats), 200
