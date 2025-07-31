# ZAP Security Scanner - Web Application

A comprehensive Flask-based web application that provides a user-friendly interface for conducting automated security scans using OWASP ZAP (Zed Attack Proxy). The application generates detailed PDF reports with 100+ vulnerability findings per scan.

## Features

- **Comprehensive Security Scanning**: Detects 100+ vulnerability types including SQL injection, XSS, CSRF, path traversal, and more
- **Real-time Progress Tracking**: Live updates during scan execution with progress indicators
- **Professional PDF Reports**: Detailed security assessment reports with risk classifications
- **Authentication Support**: Automatic login form detection and authenticated scanning
- **Modern Web Interface**: Bootstrap-based responsive UI with dark theme
- **ZAP Integration**: Full integration with OWASP ZAP for professional-grade security testing

## Prerequisites

### Required Software
- **Python 3.8+**: Runtime environment
- **OWASP ZAP**: Must be installed locally on your machine
  - Download from: https://www.zaproxy.org/download/
  - Or install via package manager (apt, brew, chocolatey)

### Python Dependencies
All Python dependencies are managed via `uv` and are listed in `pyproject.toml`:
- Flask (web framework)
- SQLAlchemy (database ORM)
- OWASP ZAP Python API (zapv2)
- ReportLab (PDF generation)
- BeautifulSoup4 (HTML parsing)
- psutil (process management)

## Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd zap-security-scanner
```

### 2. Install Dependencies
Using uv (recommended):
```bash
# Install uv if not already installed
pip install uv

# Install project dependencies
uv sync
```

Using pip:
```bash
pip install -r requirements.txt
```

### 3. Install OWASP ZAP
Choose one of the following methods:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install zaproxy
```

**macOS (using Homebrew):**
```bash
brew install --cask owasp-zap
```

**Windows (using Chocolatey):**
```bash
choco install zap
```

**Manual Installation:**
1. Download ZAP from https://www.zaproxy.org/download/
2. Install following the platform-specific instructions
3. Ensure `zap.sh` (Linux/Mac) or `ZAP.exe` (Windows) is in your PATH

### 4. Configure Environment Variables
Create a `.env` file in the project root:
```bash
# Database configuration
DATABASE_URL=sqlite:///./instance/scanner.db

# Flask session secret
SESSION_SECRET=your-secret-key-here

# Optional: Custom ZAP installation path
ZAP_PATH=/path/to/your/zap/installation
```

## Running the Application

### 1. Start the Application
Using uv:
```bash
uv run gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

Using Python directly:
```bash
python main.py
```

### 2. Access the Web Interface
Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

### Basic Scanning
1. Open the web application in your browser
2. Enter the target URL you want to scan
3. Click "Start Scan" to begin the security assessment
4. Monitor real-time progress updates
5. Download the PDF report when the scan completes

### Advanced Features
- **Authentication**: The system automatically detects login forms and prompts for credentials
- **Progress Monitoring**: Real-time updates show scan progress and current activities
- **Comprehensive Reporting**: Professional PDF reports with detailed findings and recommendations

## Project Structure

```
├── app.py                 # Flask application setup and configuration
├── main.py               # Application entry point
├── models.py             # Database models (SQLAlchemy)
├── scanner.py            # ZAP scanner integration
├── vulnerability_detector.py  # Comprehensive vulnerability detection
├── auth_manager.py       # Authentication and form detection
├── zap_manager.py        # ZAP daemon lifecycle management
├── report_generator.py   # PDF report generation
├── static/               # CSS, JavaScript, and static assets
├── templates/            # Jinja2 HTML templates
├── reports/              # Generated PDF reports
└── instance/             # Database and instance files
```

## Configuration

### ZAP Configuration
The application automatically detects ZAP installations in common locations:
- `/usr/share/zaproxy/zap.sh` (Ubuntu/Debian)
- `/opt/zaproxy/zap.sh` (Custom installations)
- `/Applications/OWASP ZAP.app/Contents/MacOS/OWASP ZAP` (macOS)
- `C:\Program Files\OWASP\Zap\ZAP.exe` (Windows)

### Custom ZAP Path
If ZAP is installed in a custom location, set the `ZAP_PATH` environment variable:
```bash
export ZAP_PATH="/path/to/your/zap/installation"
```

### Database Configuration
By default, the application uses SQLite. For production, configure PostgreSQL:
```bash
DATABASE_URL=postgresql://username:password@localhost:5432/scanner_db
```

## Troubleshooting

### Common Issues

**ZAP Not Found:**
- Ensure ZAP is properly installed
- Verify the installation path in `ZAP_PATH` environment variable
- Check that `zap.sh` or `ZAP.exe` is executable

**Port Conflicts:**
- ZAP uses port 8080 by default
- Ensure no other applications are using this port
- The web application uses port 5000

**Permission Issues:**
- Ensure the application has write permissions for the `reports/` directory
- Check that ZAP can be executed by the current user

**Scan Failures:**
- Verify the target URL is accessible
- Check firewall settings
- Ensure the target website allows automated scanning

### Logs and Debugging
Enable debug logging by setting the environment variable:
```bash
export FLASK_ENV=development
```

Logs will show detailed information about:
- ZAP daemon startup and shutdown
- Scan progress and status updates
- Vulnerability detection processes
- Error messages and troubleshooting information

## Security Considerations

- **Authorized Scanning Only**: Only scan websites you own or have explicit permission to test
- **Network Security**: Be aware that ZAP acts as a proxy and may intercept HTTPS traffic
- **Resource Usage**: Security scans can be resource-intensive; monitor system performance
- **Data Sensitivity**: Scan reports may contain sensitive information; store securely

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review ZAP documentation: https://www.zaproxy.org/docs/
3. Open an issue in the project repository

## Acknowledgments

- OWASP ZAP team for the excellent security testing platform
- Flask community for the robust web framework
- All contributors who help improve this project