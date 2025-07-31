#!/usr/bin/env python3
"""Simple runner for local ZAP Security Scanner"""

import os
import sys

# Set basic environment
os.environ.setdefault('DATABASE_URL', 'sqlite:///scanner.db')
os.environ.setdefault('SESSION_SECRET', 'local-dev-key')

try:
    from app import app
    print("Starting ZAP Security Scanner...")
    print("Open: http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
except ImportError:
    print("Missing dependencies. Install with:")
    print("pip install flask flask-sqlalchemy python-owasp-zap-v2.4 reportlab beautifulsoup4 psutil requests")