from app import app
from werkzeug.middleware.proxy_fix import ProxyFix

# Wrap the app with ProxyFix middleware
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# This is the entry point for Vercel
app = app 