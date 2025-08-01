#!/usr/bin/env python3
"""
Simple version of main.py with minimal error handling
Use this if main.py has issues
"""
import os

# Set up database - try PostgreSQL first, fallback to SQLite
try:
    # Import PostgreSQL config
    from urllib.parse import quote_plus
    
    POSTGRES_CONFIG = {
        'host': 'localhost',
        'port': '8081',
        'database': 'zap_scanner',
        'username': 'postgres',
        'password': 'Arindam@0497'
    }
    
    # URL-encode password to handle @ symbol
    encoded_password = quote_plus(POSTGRES_CONFIG['password'])
    DATABASE_URL = f"postgresql://{POSTGRES_CONFIG['username']}:{encoded_password}@{POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}/{POSTGRES_CONFIG['database']}"
    
    os.environ['DATABASE_URL'] = DATABASE_URL
    print(f"Attempting PostgreSQL connection: {POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}")
    
except Exception as e:
    print(f"PostgreSQL config failed: {e}")
    # Fallback to SQLite
    os.makedirs('instance', exist_ok=True)
    os.environ['DATABASE_URL'] = 'sqlite:///instance/zap_scanner.db'
    print("Using SQLite database")

# Import and run the app
if __name__ == '__main__':
    try:
        from app import app
        print("✓ Flask app imported successfully")
        print("Starting ZAP Security Scanner on http://localhost:8080")
        print("Make sure ZAP is running on port 8080 (as shown in your screenshot)")
        app.run(host='0.0.0.0', port=8080, debug=True)
    except Exception as e:
        print(f"Error starting app: {e}")
        print("Try installing required packages:")
        print("pip install flask flask-sqlalchemy psycopg2-binary python-owasp-zap-v2.4")