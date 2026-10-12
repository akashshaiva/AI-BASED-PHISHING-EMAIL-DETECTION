"""API route package."""

from .analyze import analyze_bp
from .health import health_bp

__all__ = ["analyze_bp", "health_bp"]
