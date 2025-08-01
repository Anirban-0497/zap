#!/usr/bin/env python3
"""
Quick test to verify PostgreSQL connection
"""

import psycopg2

def test_connection():
    try:
        # Test basic connection
        print("Testing PostgreSQL connection...")
        conn = psycopg2.connect(
            host='localhost',
            port='8081',
            user='postgres',
            password='Arindam@0497',
            database='postgres'  # Connect to default database first
        )
        
        cursor = conn.cursor()
        cursor.execute('SELECT version();')
        version = cursor.fetchone()
        print(f"✓ Connected successfully!")
        print(f"✓ PostgreSQL version: {version[0]}")
        
        # List existing databases
        cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
        databases = cursor.fetchall()
        print(f"✓ Available databases: {[db[0] for db in databases]}")
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        return False

if __name__ == '__main__':
    test_connection()