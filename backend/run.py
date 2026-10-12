"""Production entry point for the Flask backend."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

APP_FILE = ROOT / "app.py"

spec = importlib.util.spec_from_file_location("phishguard_app_file", APP_FILE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

app = module.create_app()

if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
        use_reloader=False,
    )
