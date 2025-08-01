#!/usr/bin/env python3
"""
Windows-specific runner for ZAP Security Scanner
Handles SQLite database path issues on Windows
"""
import os
import sys
from pathlib import Path

def setup_windows_database():
    """Setup SQLite database with proper Windows paths"""
    # Get the current directory where the script is located
    current_dir = Path(__file__).parent.absolute()
    instance_dir = current_dir / 'instance'
    
    # Create instance directory if it doesn't exist
    instance_dir.mkdir(exist_ok=True)
    
    # Set database path with proper Windows path format
    db_path = instance_dir / 'zap_scanner.db'
    database_url = f'sqlite:///{db_path}'
    
    # Set environment variable
    os.environ['DATABASE_URL'] = database_url
    
    print(f"Windows Environment Setup:")
    print(f"Current Directory: {current_dir}")
    print(f"Instance Directory: {instance_dir}")
    print(f"Database Path: {db_path}")
    print(f"Database URL: {database_url}")
    
    return str(db_path)

if __name__ == '__main__':
    print("=" * 60)
    print("ZAP Security Scanner - Windows Edition")
    print("=" * 60)
    
    # Setup database for Windows
    db_path = setup_windows_database()
    
    try:
        # Test if we can create/access the database file
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute('CREATE TABLE IF NOT EXISTS test (id INTEGER)')
        conn.close()
        print("✓ Database file access test successful")
        
        # Import and run the Flask app
        from app import app
        print("✓ Flask app imported successfully")
        
        print("\n" + "=" * 60)
        print("Starting ZAP Security Scanner")
        print("=" * 60)
        print("🌐 Web Interface: http://localhost:8080")
        print("🔒 Make sure ZAP is running on port 8080")
        print("=" * 60)
        
        # Run the app
        app.run(host='0.0.0.0', port=8080, debug=True)
        
    except Exception as e:
        print(f"✗ Error: {e}")
        print("\nTroubleshooting steps:")
        print("1. Make sure you're running as Administrator if needed")
        print("2. Check if the directory has write permissions")
        print("3. Try running from a different directory")
        print("4. Make sure no antivirus is blocking file creation")
        
        input("\nPress Enter to exit...")
        sys.exit(1)