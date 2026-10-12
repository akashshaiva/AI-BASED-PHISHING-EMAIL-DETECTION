"""Backward-compatible database helpers.

The active implementation lives in backend/database/database.py and is re-exported here
for compatibility with older imports.
"""

from .database import (
    get_dashboard_stats,
    get_db_connection,
    get_recent_scan_history,
    init_db,
    save_scan_record,
)

__all__ = [
    "get_db_connection",
    "init_db",
    "save_scan_record",
    "get_recent_scan_history",
    "get_dashboard_stats",
]
