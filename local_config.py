import os

# Local PostgreSQL configuration
# Update these values to match your local PostgreSQL setup
POSTGRES_CONFIG = {
    'host': 'localhost',
    'port': '8081',
    'database': 'zap_scanner',  # Change this if needed
    'username': 'postgres',     # Change this to your username
    'password': 'postgres'      # Change this to your actual password
}

# Set the DATABASE_URL environment variable
DATABASE_URL = f"postgresql://{POSTGRES_CONFIG['username']}:{POSTGRES_CONFIG['password']}@{POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}/{POSTGRES_CONFIG['database']}"

os.environ['DATABASE_URL'] = DATABASE_URL

print(f"Local PostgreSQL configured: {POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}")
print(f"Database: {POSTGRES_CONFIG['database']}")