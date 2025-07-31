#!/usr/bin/env python3
"""
Local debugging script to identify database and scan issues
Run this on your local machine: python local_debug.py
"""

import os
import sqlite3
import sys
from pathlib import Path

def check_database():
    """Check for database files and scan data"""
    print("=== DATABASE DEBUGGING ===")
    
    # Common database locations
    db_paths = [
        './instance/zap_scanner.db',
        './zap_scanner.db',
        'instance/zap_scanner.db',
        'zap_scanner.db'
    ]
    
    for db_path in db_paths:
        if os.path.exists(db_path):
            print(f"✓ Found database: {db_path}")
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Check tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                print(f"  Tables: {[t[0] for t in tables]}")
                
                # Check scan records
                if ('scan_record',) in tables:
                    cursor.execute("SELECT COUNT(*) FROM scan_record")
                    total_scans = cursor.fetchone()[0]
                    print(f"  Total scans: {total_scans}")
                    
                    cursor.execute("SELECT COUNT(*) FROM scan_record WHERE status='completed'")
                    completed_scans = cursor.fetchone()[0]
                    print(f"  Completed scans: {completed_scans}")
                    
                    if completed_scans > 0:
                        cursor.execute("""
                            SELECT id, target_url, vulnerability_count, started_at 
                            FROM scan_record 
                            WHERE status='completed' 
                            ORDER BY started_at DESC LIMIT 5
                        """)
                        recent_scans = cursor.fetchall()
                        print("  Recent completed scans:")
                        for scan in recent_scans:
                            print(f"    ID {scan[0]}: {scan[1]} ({scan[2]} vulns) - {scan[3]}")
                
                conn.close()
                
            except Exception as e:
                print(f"  Error reading database: {e}")
        else:
            print(f"✗ Database not found: {db_path}")
    
    print()

def check_directories():
    """Check required directories"""
    print("=== DIRECTORY STRUCTURE ===")
    
    dirs_to_check = ['instance', 'reports', 'static', 'templates']
    for dir_name in dirs_to_check:
        if os.path.exists(dir_name):
            print(f"✓ {dir_name}/ exists")
            if dir_name == 'reports':
                files = os.listdir(dir_name)
                pdf_files = [f for f in files if f.endswith('.pdf')]
                print(f"  PDF files: {len(pdf_files)}")
        else:
            print(f"✗ {dir_name}/ missing")
    
    print()

def check_environment():
    """Check environment and Flask setup"""
    print("=== ENVIRONMENT CHECK ===")
    
    env_vars = ['DATABASE_URL', 'SESSION_SECRET', 'FLASK_ENV']
    for var in env_vars:
        value = os.environ.get(var, 'Not set')
        print(f"{var}: {value}")
    
    print(f"Python version: {sys.version}")
    print(f"Current directory: {os.getcwd()}")
    print()

def check_flask_app():
    """Try to import and test Flask app"""
    print("=== FLASK APP CHECK ===")
    
    try:
        # Try to import the app
        sys.path.insert(0, '.')
        from app import app, db, models
        
        print("✓ Flask app imported successfully")
        
        with app.app_context():
            try:
                # Test database connection
                latest_scan = models.ScanRecord.query.filter_by(status='completed').first()
                if latest_scan:
                    print(f"✓ Database connected - found scan ID {latest_scan.id}")
                    print(f"  Target: {latest_scan.target_url}")
                    print(f"  Vulnerabilities: {latest_scan.vulnerability_count}")
                else:
                    print("✗ No completed scans found in database")
                    
            except Exception as e:
                print(f"✗ Database query failed: {e}")
                
    except Exception as e:
        print(f"✗ Flask app import failed: {e}")
        print("Make sure you're running this from the project directory")
    
    print()

def main():
    print("ZAP Security Scanner - Local Debugging")
    print("=" * 50)
    
    check_environment()
    check_directories()
    check_database()
    check_flask_app()
    
    print("=== RECOMMENDATIONS ===")
    print("1. If no database found: Run a scan first to create the database")
    print("2. If Flask import fails: Check you're in the correct directory")
    print("3. If scans exist but APIs are empty: Check Flask app configuration")
    print("4. For immediate PDF download, try: curl http://localhost:8080/download_report/[SCAN_ID]")

if __name__ == "__main__":
    main()