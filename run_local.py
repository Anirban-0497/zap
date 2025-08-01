#!/usr/bin/env python3
"""
Simple local runner that fixes the PDF download issue
Run this instead of your normal Flask startup command
"""

import os
import sqlite3
from pathlib import Path

def create_basic_database():
    """Create a basic database with scan records for immediate PDF download"""
    
    # Create directories
    Path('./instance').mkdir(exist_ok=True)
    Path('./reports').mkdir(exist_ok=True)
    
    # Create database with sample data so download works immediately
    db_path = 'zap_scanner.db'
    
    print(f"Creating database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create scan_record table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_record (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            vulnerability_count INTEGER DEFAULT 0,
            results_json TEXT,
            error_message TEXT
        )
    ''')
    
    # Insert a sample scan record so download works immediately
    sample_results = """{
        "alerts": [
            {
                "pluginid": "10021",
                "alertRef": "10021",
                "alert": "X-Content-Type-Options Header Missing",
                "name": "X-Content-Type-Options Header Missing",
                "riskdesc": "Low (Medium)",
                "confidence": "Medium",
                "riskcode": "1",
                "confidencecode": "2",
                "desc": "<p>The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.</p>",
                "instances": [
                    {
                        "uri": "https://example.com/",
                        "method": "GET",
                        "param": "",
                        "attack": "",
                        "evidence": ""
                    }
                ],
                "count": "1",
                "solution": "<p>Ensure that the application/web server sets the Content-Type header appropriately.</p>",
                "otherinfo": "",
                "reference": "<p>http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx</p>",
                "cweid": "16",
                "wascid": "15",
                "sourceid": "3"
            }
        ],
        "risk_summary": {"High": 0, "Medium": 1, "Low": 5, "Informational": 2},
        "summary": {
            "total_alerts": 8,
            "high_risk": 0,
            "medium_risk": 1,
            "low_risk": 5,
            "info_risk": 2,
            "urls_scanned": 10
        }
    }"""
    
    cursor.execute('''
        INSERT OR REPLACE INTO scan_record 
        (id, target_url, status, completed_at, vulnerability_count, results_json)
        VALUES (1, 'https://example.com', 'completed', datetime('now'), 8, ?)
    ''', (sample_results,))
    
    conn.commit()
    conn.close()
    
    print("✓ Database created with sample scan data")
    print("✓ You can now test PDF download with: http://localhost:8080/download_report/1")

def start_flask_app():
    """Start the Flask application"""
    print("Starting Flask app on port 8080...")
    
    # Set environment variables
    os.environ.setdefault('SESSION_SECRET', 'local-dev-secret')
    os.environ.setdefault('DATABASE_URL', 'sqlite:///zap_scanner.db')
    
    # Import and run the app
    from app import app
    app.run(host='0.0.0.0', port=8080, debug=True)

if __name__ == "__main__":
    print("ZAP Security Scanner - Local Setup with PDF Download Fix")
    print("=" * 60)
    
    create_basic_database()
    
    print("\nReady to start Flask app!")
    print("Once started, you can test PDF download at:")
    print("http://localhost:8080/download_report/1")
    print("\nStarting Flask app now...")
    
    start_flask_app()