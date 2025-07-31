#!/usr/bin/env python3
"""
Local Setup Script for ZAP Security Scanner
This script helps set up the ZAP Security Scanner on your local machine.
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python {sys.version.split()[0]} detected")
    return True

def check_zap_installation():
    """Check if ZAP is installed and accessible"""
    zap_paths = [
        # Linux/Ubuntu
        '/usr/share/zaproxy/zap.sh',
        '/opt/zaproxy/zap.sh',
        '/usr/local/bin/zap.sh',
        '/usr/bin/zap.sh',
        # macOS
        '/Applications/OWASP ZAP.app/Contents/MacOS/OWASP ZAP',
        # Windows
        'C:\\Program Files\\OWASP\\Zap\\ZAP.exe',
        'C:\\Program Files (x86)\\OWASP\\Zap\\ZAP.exe'
    ]
    
    # Check environment variable first
    zap_path = os.environ.get('ZAP_PATH')
    if zap_path and os.path.isfile(zap_path):
        print(f"✅ ZAP found at: {zap_path}")
        return zap_path
    
    # Check common installation paths
    for path in zap_paths:
        if os.path.isfile(path):
            print(f"✅ ZAP found at: {path}")
            return path
    
    # Try to find in PATH
    try:
        if platform.system() == "Windows":
            result = subprocess.run(['where', 'zap'], capture_output=True, text=True)
        else:
            result = subprocess.run(['which', 'zap.sh'], capture_output=True, text=True)
        
        if result.returncode == 0:
            zap_path = result.stdout.strip()
            print(f"✅ ZAP found in PATH: {zap_path}")
            return zap_path
    except:
        pass
    
    print("❌ ZAP installation not found")
    print_zap_installation_help()
    return None

def print_zap_installation_help():
    """Print ZAP installation instructions"""
    system = platform.system()
    print("\n📦 OWASP ZAP Installation Instructions:")
    print("="*50)
    
    if system == "Linux":
        print("Ubuntu/Debian:")
        print("  sudo apt update")
        print("  sudo apt install zaproxy")
        print("\nOr download from: https://www.zaproxy.org/download/")
        
    elif system == "Darwin":  # macOS
        print("Using Homebrew:")
        print("  brew install --cask owasp-zap")
        print("\nOr download from: https://www.zaproxy.org/download/")
        
    elif system == "Windows":
        print("Using Chocolatey:")
        print("  choco install zap")
        print("\nOr download from: https://www.zaproxy.org/download/")
    
    print("\nAfter installation, you can set ZAP_PATH environment variable:")
    print("  export ZAP_PATH=/path/to/your/zap/installation")

def install_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    # Check if pip is available
    try:
        subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                      capture_output=True, check=True)
        print("✅ pip is available")
    except subprocess.CalledProcessError:
        print("❌ pip is not available")
        return False
    
    # Install dependencies
    dependencies = [
        'flask==3.0.3',
        'flask-sqlalchemy==3.1.1',
        'python-owasp-zap-v2.4==0.0.21',
        'reportlab==4.2.2',
        'beautifulsoup4==4.12.3',
        'psutil==6.0.0',
        'requests==2.32.3',
        'gunicorn==23.0.0'
    ]
    
    try:
        print("Installing packages...")
        subprocess.run([sys.executable, '-m', 'pip', 'install'] + dependencies, 
                      check=True)
        print("✅ All dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def create_env_file():
    """Create .env file with default configuration"""
    env_content = """# ZAP Security Scanner Configuration

# Database configuration (SQLite by default)
DATABASE_URL=sqlite:///./instance/scanner.db

# Flask session secret (change this in production!)
SESSION_SECRET=your-secret-key-change-this-in-production

# Optional: Custom ZAP installation path
# ZAP_PATH=/path/to/your/zap/installation

# Flask environment
FLASK_ENV=development
FLASK_DEBUG=1
"""
    
    env_file = Path('.env')
    if not env_file.exists():
        with open(env_file, 'w') as f:
            f.write(env_content)
        print("✅ Created .env configuration file")
    else:
        print("⚠️  .env file already exists, skipping...")

def create_directories():
    """Create necessary directories"""
    directories = ['instance', 'reports', 'static', 'templates']
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    print("✅ Created necessary directories")

def create_run_script():
    """Create a simple run script"""
    if platform.system() == "Windows":
        script_content = """@echo off
echo Starting ZAP Security Scanner...
python main.py
pause
"""
        script_name = "run.bat"
    else:
        script_content = """#!/bin/bash
echo "Starting ZAP Security Scanner..."
python3 main.py
"""
        script_name = "run.sh"
    
    with open(script_name, 'w') as f:
        f.write(script_content)
    
    if platform.system() != "Windows":
        os.chmod(script_name, 0o755)
    
    print(f"✅ Created run script: {script_name}")

def main():
    """Main setup function"""
    print("🔧 ZAP Security Scanner - Local Setup")
    print("="*40)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Check ZAP installation
    zap_path = check_zap_installation()
    if not zap_path:
        print("\n⚠️  Setup can continue, but ZAP must be installed before running scans")
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Create configuration
    create_env_file()
    create_directories()
    create_run_script()
    
    print("\n✅ Setup completed successfully!")
    print("\n🚀 Next Steps:")
    print("1. If ZAP is not installed, install it using the instructions above")
    print("2. Edit .env file to customize configuration")
    print("3. Run the application:")
    
    if platform.system() == "Windows":
        print("   - Double-click run.bat")
        print("   - Or run: python main.py")
    else:
        print("   - Run: ./run.sh")
        print("   - Or run: python3 main.py")
    
    print("4. Open http://localhost:5000 in your browser")
    print("\n📖 See README.md for detailed documentation")
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)