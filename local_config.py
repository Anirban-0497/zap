import os
from urllib.parse import quote_plus

# Local PostgreSQL configuration
POSTGRES_CONFIG = {
    'host': 'localhost',
    'port': '8081',  # Your PostgreSQL is running on port 8081
    'database': 'zap_scanner',
    'username': 'postgres',
    'password': 'Arindam@0497'
}

# URL-encode the password to handle special characters like @
encoded_password = quote_plus(POSTGRES_CONFIG['password'])

# Set the DATABASE_URL environment variable with encoded password
DATABASE_URL = f"postgresql://{POSTGRES_CONFIG['username']}:{encoded_password}@{POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}/{POSTGRES_CONFIG['database']}"

os.environ['DATABASE_URL'] = DATABASE_URL

print(f"Local PostgreSQL configured: {POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}")
print(f"Database: {POSTGRES_CONFIG['database']}")
print(f"Password encoded: {encoded_password[:8]}... (special characters handled)")