#!/usr/bin/env python3
"""
Local runner for ZAP Security Scanner
This script starts the Flask application for local development
"""

import os
import sys
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def setup_environment():
    """Setup environment variables from .env file if it exists"""
    env_file = current_dir / '.env'
    if env_file.exists():
        print("Loading configuration from .env file...")
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()
    
    # Set default values if not in environment
    if 'DATABASE_URL' not in os.environ:
        os.environ['DATABASE_URL'] = 'sqlite:///./instance/scanner.db'
    
    if 'SESSION_SECRET' not in os.environ:
        os.environ['SESSION_SECRET'] = 'dev-secret-key-change-in-production'
    
    if 'FLASK_ENV' not in os.environ:
        os.environ['FLASK_ENV'] = 'development'

def main():
    """Main function to start the application"""
    print("🔧 ZAP Security Scanner - Starting Local Server")
    print("=" * 50)
    
    # Setup environment
    setup_environment()
    
    # Create instance directory if it doesn't exist
    instance_dir = current_dir / 'instance'
    instance_dir.mkdir(exist_ok=True)
    
    reports_dir = current_dir / 'reports'
    reports_dir.mkdir(exist_ok=True)
    
    try:
        # Import and run the Flask app
        from app import app
        
        print("✅ Application loaded successfully")
        print("🌐 Starting server at http://localhost:5000")
        print("📊 Admin interface available at http://localhost:5000")
        print("🛑 Press Ctrl+C to stop the server")
        print("-" * 50)
        
        # Run the Flask development server
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=True
        )
        
    except ImportError as e:
        print(f"❌ Failed to import application: {e}")
        print("💡 Make sure all dependencies are installed:")
        print("   pip install flask flask-sqlalchemy python-owasp-zap-v2.4 reportlab beautifulsoup4 psutil requests")
        return False
    
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)