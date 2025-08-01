#!/usr/bin/env python3
"""
Setup script for local PostgreSQL database
Run this script to create the database and tables for ZAP Scanner
"""

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Default PostgreSQL configuration for local setup
DEFAULT_CONFIG = {
    'host': 'localhost',
    'port': '8081',
    'admin_user': 'postgres',
    'admin_password': 'your_admin_password',  # Change this
    'database': 'zap_scanner',
    'app_user': 'zap_user',
    'app_password': 'zap_password'  # Change this
}

def create_database_and_user():
    """Create database and user for ZAP Scanner"""
    try:
        # Connect as admin user
        conn = psycopg2.connect(
            host=DEFAULT_CONFIG['host'],
            port=DEFAULT_CONFIG['port'],
            user=DEFAULT_CONFIG['admin_user'],
            password=DEFAULT_CONFIG['admin_password'],
            database='postgres'  # Connect to default database
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Create database
        try:
            cursor.execute(f"CREATE DATABASE {DEFAULT_CONFIG['database']}")
            print(f"✓ Database '{DEFAULT_CONFIG['database']}' created successfully")
        except psycopg2.errors.DuplicateDatabase:
            print(f"✓ Database '{DEFAULT_CONFIG['database']}' already exists")
        
        # Create user
        try:
            cursor.execute(f"CREATE USER {DEFAULT_CONFIG['app_user']} WITH PASSWORD '{DEFAULT_CONFIG['app_password']}'")
            print(f"✓ User '{DEFAULT_CONFIG['app_user']}' created successfully")
        except psycopg2.errors.DuplicateObject:
            print(f"✓ User '{DEFAULT_CONFIG['app_user']}' already exists")
        
        # Grant privileges
        cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {DEFAULT_CONFIG['database']} TO {DEFAULT_CONFIG['app_user']}")
        print(f"✓ Privileges granted to '{DEFAULT_CONFIG['app_user']}'")
        
        cursor.close()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"✗ Error setting up database: {e}")
        return False

def update_local_config():
    """Update local_config.py with the correct settings"""
    config_content = f'''import os

# Local PostgreSQL configuration
POSTGRES_CONFIG = {{
    'host': '{DEFAULT_CONFIG['host']}',
    'port': '{DEFAULT_CONFIG['port']}',
    'database': '{DEFAULT_CONFIG['database']}',
    'username': '{DEFAULT_CONFIG['app_user']}',
    'password': '{DEFAULT_CONFIG['app_password']}'
}}

# Set the DATABASE_URL environment variable
DATABASE_URL = f"postgresql://{{POSTGRES_CONFIG['username']}}:{{POSTGRES_CONFIG['password']}}@{{POSTGRES_CONFIG['host']}}:{{POSTGRES_CONFIG['port']}}//{{POSTGRES_CONFIG['database']}}"

os.environ['DATABASE_URL'] = DATABASE_URL

print(f"Local PostgreSQL configured: {{POSTGRES_CONFIG['host']}}:{{POSTGRES_CONFIG['port']}}")
print(f"Database: {{POSTGRES_CONFIG['database']}}")
'''
    
    with open('local_config.py', 'w') as f:
        f.write(config_content)
    
    print("✓ local_config.py updated")

def test_connection():
    """Test the database connection"""
    try:
        import local_config
        from app import app, db
        
        with app.app_context():
            db.create_all()
            print("✓ Database tables created successfully")
            print("✓ Connection test passed")
        
        return True
        
    except Exception as e:
        print(f"✗ Connection test failed: {e}")
        return False

if __name__ == '__main__':
    print("ZAP Scanner - Local PostgreSQL Setup")
    print("=" * 40)
    
    print(f"Please update the admin password in this script before running!")
    print(f"Current config: {DEFAULT_CONFIG['host']}:{DEFAULT_CONFIG['port']}")
    
    if input("Continue with setup? (y/N): ").lower() != 'y':
        sys.exit(0)
    
    # Step 1: Create database and user
    if create_database_and_user():
        print("\n✓ Database setup completed")
    else:
        print("\n✗ Database setup failed")
        sys.exit(1)
    
    # Step 2: Update configuration
    update_local_config()
    
    # Step 3: Test connection
    print("\nTesting connection...")
    if test_connection():
        print("\n🎉 Setup completed successfully!")
        print(f"You can now run: python main.py")
        print(f"Your app will connect to PostgreSQL on port {DEFAULT_CONFIG['port']}")
    else:
        print("\n✗ Setup incomplete - connection test failed")