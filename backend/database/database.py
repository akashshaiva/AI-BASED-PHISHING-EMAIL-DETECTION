import json
import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.getenv("DATABASE_PATH", os.path.join(BASE_DIR, "data", "phishguard.db"))

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _normalize_reasons(reasons):
    if reasons is None:
        return "[]"
    if isinstance(reasons, str):
        return reasons
    return json.dumps(reasons, ensure_ascii=False)


def init_db():
    try:
        connection = get_db_connection()
    except sqlite3.Error:
        return False

    try:
        existing_columns = connection.execute("PRAGMA table_info(scan_history)").fetchall()

        if not existing_columns:
            connection.execute(
                """
                CREATE TABLE scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    prediction INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    url_count INTEGER NOT NULL DEFAULT 0,
                    reasons TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        else:
            column_names = {row[1] for row in existing_columns}
            has_required_fields = (
                "sender" in column_names
                and "subject" in column_names
                and "prediction" in column_names
                and "confidence" in column_names
                and "risk_level" in column_names
                and "url_count" in column_names
                and "reasons" in column_names
                and "created_at" in column_names
            )

            if not has_required_fields:
                connection.execute("ALTER TABLE scan_history ADD COLUMN url_count INTEGER NOT NULL DEFAULT 0")
                connection.execute("ALTER TABLE scan_history ADD COLUMN reasons TEXT NOT NULL DEFAULT '[]'")
                connection.execute(
                    "ALTER TABLE scan_history ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
                )

            prediction_types = {
                row[1]: row[2]
                for row in existing_columns
                if row[1] == "prediction"
            }
            if prediction_types.get("prediction", "").upper() != "INTEGER":
                connection.execute("ALTER TABLE scan_history RENAME TO scan_history_legacy")
                connection.execute(
                    """
                    CREATE TABLE scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        prediction INTEGER NOT NULL,
                        confidence REAL NOT NULL,
                        risk_level TEXT NOT NULL,
                        url_count INTEGER NOT NULL DEFAULT 0,
                        reasons TEXT NOT NULL DEFAULT '[]',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
                connection.execute(
                    """
                    INSERT INTO scan_history (id, sender, subject, prediction, confidence, risk_level, url_count, reasons, created_at)
                    SELECT
                        id,
                        sender,
                        subject,
                        CAST(prediction AS INTEGER),
                        CAST(confidence AS REAL),
                        risk_level,
                        COALESCE(CAST(url_count AS INTEGER), 0),
                        COALESCE(reasons, '[]'),
                        COALESCE(created_at, CURRENT_TIMESTAMP)
                    FROM scan_history_legacy
                    """
                )
                connection.execute("DROP TABLE scan_history_legacy")

        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_history_created_at ON scan_history(created_at DESC)"
        )
        connection.commit()
        return True
    except sqlite3.Error:
        return False
    finally:
        connection.close()


def save_scan_record(sender, subject, prediction, confidence, risk_level, url_count=0, reasons=None):
    sender_value = str(sender or "unknown").strip() or "unknown"
    subject_value = str(subject or "No subject").strip() or "No subject"
    prediction_value = int(prediction)
    confidence_value = float(confidence)
    risk_value = str(risk_level or "low").strip().lower() or "low"
    url_count_value = int(url_count or 0)
    reasons_value = _normalize_reasons(reasons)

    try:
        connection = get_db_connection()
    except sqlite3.Error:
        return None

    try:
        cursor = connection.execute(
            """
            INSERT INTO scan_history (sender, subject, prediction, confidence, risk_level, url_count, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (sender_value, subject_value, prediction_value, confidence_value, risk_value, url_count_value, reasons_value),
        )
        connection.commit()
        return cursor.lastrowid
    except sqlite3.Error:
        return None
    finally:
        connection.close()


def get_recent_scan_history(limit=20):
    try:
        connection = get_db_connection()
    except sqlite3.Error:
        return []

    try:
        rows = connection.execute(
            """
            SELECT id, sender, subject, prediction, confidence, risk_level, url_count, reasons, created_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

        history = []
        for row in rows:
            reasons = row["reasons"]
            try:
                parsed_reasons = json.loads(reasons) if reasons else []
            except (TypeError, json.JSONDecodeError):
                parsed_reasons = [reasons] if reasons else []

            history.append(
                {
                    "id": row["id"],
                    "sender": row["sender"],
                    "subject": row["subject"],
                    "prediction": row["prediction"],
                    "confidence": row["confidence"],
                    "risk_level": row["risk_level"],
                    "url_count": row["url_count"],
                    "reasons": parsed_reasons,
                    "created_at": row["created_at"],
                }
            )
        return history
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def get_dashboard_stats():
    try:
        connection = get_db_connection()
    except sqlite3.Error:
        return {
            "total_scans": 0,
            "phishing_count": 0,
            "legitimate_count": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
        }

    try:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                SUM(CASE WHEN prediction = 1 THEN 1 ELSE 0 END) AS phishing_count,
                SUM(CASE WHEN prediction = 0 THEN 1 ELSE 0 END) AS legitimate_count,
                SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) AS high_risk_count,
                SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) AS medium_risk_count,
                SUM(CASE WHEN risk_level = 'low' THEN 1 ELSE 0 END) AS low_risk_count
            FROM scan_history
            """
        ).fetchone()

        return {
            "total_scans": int(row["total_scans"] or 0),
            "phishing_count": int(row["phishing_count"] or 0),
            "legitimate_count": int(row["legitimate_count"] or 0),
            "high_risk_count": int(row["high_risk_count"] or 0),
            "medium_risk_count": int(row["medium_risk_count"] or 0),
            "low_risk_count": int(row["low_risk_count"] or 0),
        }
    except sqlite3.Error:
        return {
            "total_scans": 0,
            "phishing_count": 0,
            "legitimate_count": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
        }
    finally:
        connection.close()
