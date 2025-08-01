import os
import sys

# For Replit: Use PostgreSQL if available, otherwise SQLite
if 'DATABASE_URL' not in os.environ:
    # Create instance directory for SQLite
    os.makedirs('instance', exist_ok=True) 
    os.environ['DATABASE_URL'] = 'sqlite:///instance/zap_scanner.db'
    print("Using SQLite database for Replit environment")

# Import app and initialize
from app import app
print("✓ Flask app initialized successfully")

if __name__ == '__main__':
    if app is None:
        print("✗ App failed to initialize")
        sys.exit(1)
    
    print("Starting ZAP Security Scanner on http://localhost:8080")
    print("Make sure ZAP is running on port 8080 (as shown in your screenshot)")
    app.run(host='0.0.0.0', port=8080, debug=True)
