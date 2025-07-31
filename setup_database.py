#!/usr/bin/env python3
"""
Database setup script for local environment
Run this to create the database and tables
"""

import os
import sys
from pathlib import Path

def setup_database():
    """Create database and tables"""
    print("Setting up ZAP Scanner database...")
    
    # Add current directory to Python path
    sys.path.insert(0, '.')
    
    try:
        from app import app, db
        
        # Create instance directory if it doesn't exist
        instance_dir = Path('./instance')
        instance_dir.mkdir(exist_ok=True)
        print(f"✓ Created instance directory: {instance_dir.absolute()}")
        
        # Create reports directory if it doesn't exist
        reports_dir = Path('./reports')
        reports_dir.mkdir(exist_ok=True)
        print(f"✓ Created reports directory: {reports_dir.absolute()}")
        
        # Initialize database
        with app.app_context():
            db.create_all()
            print("✓ Database tables created successfully")
            
            # Show database location
            db_url = app.config.get('SQLALCHEMY_DATABASE_URI', 'Not configured')
            print(f"✓ Database location: {db_url}")
        
        print("\n=== DATABASE SETUP COMPLETE ===")
        print("You can now run scans and they will be saved properly.")
        print("After running a scan, the PDF download should work.")
        
    except ImportError as e:
        print(f"✗ Failed to import Flask app: {e}")
        print("Make sure you're running this from the project directory")
        return False
    except Exception as e:
        print(f"✗ Database setup failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = setup_database()
    if success:
        print("\nNext steps:")
        print("1. Start your Flask app: python main.py (or however you start it)")
        print("2. Run a new scan through the web interface")
        print("3. The scan results will now be saved to the database")
        print("4. PDF download will work after scan completion")
    else:
        print("\nSetup failed. Check the error messages above.")