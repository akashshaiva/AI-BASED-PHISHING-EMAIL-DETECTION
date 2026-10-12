# Backend structure for AI-Based Phishing Email Detection System

This directory contains the Python Flask backend skeleton for the project. It is intentionally limited to structure and responsibilities so the frontend remains untouched until the next stage.

Important notes:
- No fake ML prediction logic is included.
- No external URL scanning is performed.
- The backend is designed to support future email analysis, .eml parsing,
  risk assessment, and dashboard/history APIs.

Planned modules:
- app/config.py: application configuration
- app/database.py: SQLite setup and query helpers
- app/routes/*: REST API endpoints
- app/services/*: parsing, extraction, modeling, and risk logic
- run.py: app startup entry point
