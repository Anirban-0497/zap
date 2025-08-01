#!/usr/bin/env python3
"""
Simple script to create the ZAP Scanner database
"""

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# PostgreSQL connection details
HOST = 'localhost'
PORT = '5432'  # Standard PostgreSQL port
ADMIN_USER = 'postgres'
ADMIN_PASSWORD = 'Arindam@0497'
DATABASE_NAME = 'zap_scanner'

def create_database():
    """Create database for ZAP Scanner"""
    try:
        # Connect to PostgreSQL server
        print("Connecting to PostgreSQL...")
        conn = psycopg2.connect(
            host=HOST,
            port=PORT,
            user=ADMIN_USER,
            password=ADMIN_PASSWORD,
            database='postgres'  # Connect to default database first
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DATABASE_NAME,))
        exists = cursor.fetchone()
        
        if exists:
            print(f"✓ Database '{DATABASE_NAME}' already exists")
        else:
            # Create database
            cursor.execute(f"CREATE DATABASE {DATABASE_NAME}")
            print(f"✓ Database '{DATABASE_NAME}' created successfully")
        
        cursor.close()
        conn.close()
        
        print("✓ Database setup completed!")
        print(f"You can now run: python main.py")
        return True
        
    except psycopg2.OperationalError as e:
        if "Connection refused" in str(e):
            print("✗ Connection refused. Please check:")
            print("  1. PostgreSQL is running")
            print("  2. Port is correct (try 5432 instead of 8081)")
            print("  3. PostgreSQL is configured to accept connections")
        elif "authentication failed" in str(e):
            print("✗ Authentication failed. Please check:")
            print("  1. Username is correct")
            print("  2. Password is correct")
        else:
            print(f"✗ Connection error: {e}")
        return False
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == '__main__':
    print("ZAP Scanner - Database Creation")
    print("=" * 35)
    create_database()