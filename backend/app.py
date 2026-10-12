import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, send_from_directory
from flask_cors import CORS

load_dotenv()

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from config import get_config
from database import init_db
from routes.analyze import analyze_bp
from routes.health import health_bp
from routes.history import history_bp
from routes.upload import upload_bp


PROJECT_ROOT = BACKEND_DIR.parent


def create_app(config_class=None):
    config_class = config_class or get_config()
    app = Flask(__name__, template_folder=str(PROJECT_ROOT), static_folder=str(PROJECT_ROOT / "static"))
    app.config.from_object(config_class)

    app.config.setdefault("MAX_CONTENT_LENGTH", int(os.getenv("MAX_UPLOAD_SIZE", str(5 * 1024 * 1024))))
    app.config.setdefault("STATIC_FOLDER", str(PROJECT_ROOT / "static"))
    app.config.setdefault("TEMPLATE_FOLDER", str(PROJECT_ROOT))

    allowed_origins = app.config.get("ALLOWED_ORIGINS", [])
    CORS(app, resources={r"/api/*": {"origins": allowed_origins}}, supports_credentials=False)

    app.register_blueprint(health_bp)
    app.register_blueprint(analyze_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(history_bp)

    @app.route("/")
    def index_page():
        return send_from_directory(app.template_folder, "index.html")

    @app.route("/<path:page_name>")
    def serve_page(page_name):
        if page_name.startswith("api/"):
            return {"error": "Not found", "message": "The requested endpoint does not exist."}, 404

        if page_name.endswith(".html"):
            base_dir = os.path.abspath(app.template_folder)
            target_path = os.path.abspath(os.path.join(base_dir, page_name))
            if os.path.commonpath([base_dir, target_path]) == base_dir and os.path.isfile(target_path):
                return send_from_directory(app.template_folder, page_name)

        return {"error": "Not found", "message": "The requested endpoint does not exist."}, 404

    init_db()

    @app.errorhandler(400)
    def handle_bad_request(error):
        return {"error": "Bad request", "message": "The request could not be processed."}, 400

    @app.errorhandler(404)
    def handle_not_found(error):
        return {"error": "Not found", "message": "The requested endpoint does not exist."}, 404

    @app.errorhandler(500)
    def handle_internal_error(error):
        return {"error": "Internal server error", "message": "Something went wrong on the server."}, 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
        use_reloader=False,
    )
