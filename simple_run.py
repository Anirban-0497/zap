#!/usr/bin/env python3
"""
Simplified Flask app runner for local development
This ensures database is created and app runs with proper configuration
"""

import os
import sys
from pathlib import Path

# Set up environment
os.environ.setdefault('SESSION_SECRET', 'local-dev-key-12345')
os.environ.setdefault('DATABASE_URL', 'sqlite:///zap_scanner.db')

def setup_directories():
    """Create required directories"""
    Path('./instance').mkdir(exist_ok=True)
    Path('./reports').mkdir(exist_ok=True)
    print("Created required directories")

def setup_database():
    """Initialize database"""
    try:
        from app import app, db
        with app.app_context():
            db.create_all()
            print("Database initialized successfully")
            return True
    except Exception as e:
        print(f"Database setup failed: {e}")
        return False

def run_app():
    """Run the Flask application"""
    try:
        from app import app
        print("Starting Flask app on http://localhost:8080")
        print("ZAP API Key: 72cnks1ojc5359jc7e4g0pt650")
        print("Make sure ZAP is running on port 8080")
        app.run(host='0.0.0.0', port=8080, debug=True)
    except Exception as e:
        print(f"Failed to start app: {e}")

if __name__ == "__main__":
    print("ZAP Security Scanner - Local Setup")
    print("=" * 40)
    
    setup_directories()
    
    if setup_database():
        run_app()
    else:
        print("Database setup failed. Cannot start application.")