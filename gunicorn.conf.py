wsgi_app = "run:app"
bind = "0.0.0.0:8000"
workers = 2
threads = 2
worker_class = "sync"
timeout = 120
keepalive = 5
accesslog = "-"
errorlog = "-"

def when_ready(server):
    server.log.info("PhishGuard production server is ready")
