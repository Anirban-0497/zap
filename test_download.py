#!/usr/bin/env python3
"""
Test script to create a sample scan record and test PDF download functionality
"""
import json
import os
import sys
from datetime import datetime

# Add the project root to the path
sys.path.insert(0, '.')

from app import app, db
from models import ScanRecord
from report_generator import ReportGenerator

def create_test_scan_record():
    """Create a test scan record with sample vulnerabilities"""
    
    # Sample vulnerability data (what would come from a real ZAP scan)
    sample_results = {
        "target_url": "https://example.com",
        "scan_timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "alert_count": 15,
        "scan_types": ["spider", "active"],
        "alerts": [
            {
                "name": "SQL Injection",
                "risk": "High",
                "confidence": "High",
                "description": "SQL injection vulnerabilities allow an attacker to interfere with the queries that an application makes to its database.",
                "solution": "Use parameterized queries and input validation.",
                "url": "https://example.com/login",
                "param": "username",
                "evidence": "' OR '1'='1"
            },
            {
                "name": "Cross Site Scripting (XSS)",
                "risk": "Medium",
                "confidence": "High",
                "description": "Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications.",
                "solution": "Encode all user input and use Content Security Policy.",
                "url": "https://example.com/search",
                "param": "q",
                "evidence": "<script>alert('XSS')</script>"
            },
            {
                "name": "Information Disclosure",
                "risk": "Low",
                "confidence": "Medium",
                "description": "The web server is configured to expose sensitive information.",
                "solution": "Configure the web server to hide version information.",
                "url": "https://example.com/",
                "param": "",
                "evidence": "Server: Apache/2.4.41"
            }
        ],
        "risk_summary": {
            "High": 1,
            "Medium": 1,
            "Low": 1,
            "Informational": 0
        },
        "summary": {
            "total_alerts": 3,
            "high_risk": 1,
            "medium_risk": 1,
            "low_risk": 1,
            "info_risk": 0,
            "urls_scanned": 5
        },
        "authenticated": False,
        "spider_results": {"urls": ["https://example.com", "https://example.com/login", "https://example.com/search"]},
        "active_results": {"scanned_urls": 3}
    }
    
    with app.app_context():
        # Create a test scan record
        scan_record = ScanRecord(
            target_url="https://example.com",
            status="completed",
            started_at=datetime.now(),
            completed_at=datetime.now(),
            vulnerability_count=3,
            results_json=json.dumps(sample_results)
        )
        
        db.session.add(scan_record)
        db.session.commit()
        
        print(f"Created test scan record with ID: {scan_record.id}")
        return scan_record.id

def test_pdf_generation(scan_id):
    """Test PDF generation for the scan record"""
    with app.app_context():
        scan_record = ScanRecord.query.get(scan_id)
        if not scan_record:
            print(f"Scan record {scan_id} not found")
            return False
        
        try:
            # Generate PDF report
            report_gen = ReportGenerator()
            results = json.loads(scan_record.results_json)
            pdf_path = report_gen.generate_pdf_report(results, scan_record.target_url)
            
            if os.path.exists(pdf_path):
                file_size = os.path.getsize(pdf_path)
                print(f"PDF generated successfully: {pdf_path} ({file_size} bytes)")
                return True
            else:
                print(f"PDF file not found: {pdf_path}")
                return False
                
        except Exception as e:
            print(f"Error generating PDF: {str(e)}")
            return False

if __name__ == "__main__":
    print("Creating test scan record...")
    scan_id = create_test_scan_record()
    
    print("Testing PDF generation...")
    success = test_pdf_generation(scan_id)
    
    if success:
        print(f"Test completed successfully! You can now test the download at:")
        print(f"http://localhost:8080/download_report/{scan_id}")
        print(f"Or debug info at: http://localhost:8080/debug_download")
    else:
        print("Test failed!")