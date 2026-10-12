import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent


class Config:
    DEBUG = False
    TESTING = False
    JSON_SORT_KEYS = False

    SECRET_KEY = os.getenv("SECRET_KEY") or "change-me-in-production"
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "5000"))

    BASE_DIR = str(PROJECT_ROOT)
    STATIC_FOLDER = str(PROJECT_ROOT / "static")
    TEMPLATE_FOLDER = str(PROJECT_ROOT)
    MODEL_DIR = str(PROJECT_ROOT / "ml" / "models")

    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BACKEND_DIR / "data" / "phishguard.db"))
    DATABASE_URL = os.getenv("DATABASE_URL")

    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_SIZE", str(5 * 1024 * 1024)))
    ALLOWED_EXTENSIONS = {".eml"}
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(BACKEND_DIR / "uploads"))

    ALLOWED_ORIGINS = [
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000").split(",")
        if origin.strip()
    ]

    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() in {"1", "true", "yes"}
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    PREFERRED_URL_SCHEME = os.getenv("PREFERRED_URL_SCHEME", "https")


class DevelopmentConfig(Config):
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes"}
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


def get_config():
    env_name = os.getenv("FLASK_ENV", "production").lower()
    if env_name == "development":
        return DevelopmentConfig
    return ProductionConfig
