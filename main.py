import os
import sys

# Import local configuration if it exists
try:
    import local_config
    print("Using local PostgreSQL configuration")
    print(f"Database: {local_config.POSTGRES_CONFIG['host']}:{local_config.POSTGRES_CONFIG['port']}")
except ImportError:
    print("No local_config.py found, using default SQLite")
    # Fallback to SQLite if no PostgreSQL config
    if 'DATABASE_URL' not in os.environ:
        os.environ['DATABASE_URL'] = 'sqlite:///instance/zap_scanner.db'

# Test database connection before starting app
try:
    from app import app
    with app.app_context():
        from app import db
        # Try to connect to database - use modern SQLAlchemy syntax
        with db.engine.connect() as conn:
            conn.execute(db.text('SELECT 1'))
        print("✓ Database connection successful")
except Exception as e:
    print(f"✗ Database connection failed: {e}")
    print("Falling back to SQLite...")
    # Create instance directory for SQLite
    os.makedirs('instance', exist_ok=True)
    os.environ['DATABASE_URL'] = 'sqlite:///instance/zap_scanner.db'
    print("✓ SQLite fallback configured")

if __name__ == '__main__':
    print(f"Starting ZAP Security Scanner on http://localhost:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)
