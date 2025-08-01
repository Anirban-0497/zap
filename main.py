import os
# Import local configuration if it exists
try:
    import local_config
    print("Using local PostgreSQL configuration")
except ImportError:
    print("No local_config.py found, using default SQLite")
    # Fallback to SQLite if no PostgreSQL config
    if 'DATABASE_URL' not in os.environ:
        os.environ['DATABASE_URL'] = 'sqlite:///instance/zap_scanner.db'

from app import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
