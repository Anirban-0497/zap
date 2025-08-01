# Windows Setup Guide

## Quick Start for Windows

Your ZAP Security Scanner now includes a Windows-specific runner that handles database path issues automatically.

### Option 1: Use Windows Runner (Recommended)
```bash
python run_windows.py
```

### Option 2: Use PostgreSQL (Advanced)
If you prefer PostgreSQL, run your local PostgreSQL server and use:
```bash
python main.py
```

### Option 3: Simple Runner
```bash
python simple_run.py
```

## Troubleshooting Windows Issues

**Database Permission Errors:**
- Run Command Prompt as Administrator
- Make sure antivirus isn't blocking file creation
- Try running from your user directory (C:\Users\YourName\)

**ZAP Connection:**
- Make sure ZAP is running on port 8080 (as shown in your screenshot)
- Use API key: `72cnks1ojc5359jc7e4g0pt650`

**Expected Output:**
```
Windows Environment Setup:
Current Directory: C:\Users\anirb\Downloads\zap (4)\zap
Instance Directory: C:\Users\anirb\Downloads\zap (4)\zap\instance
Database Path: C:\Users\anirb\Downloads\zap (4)\zap\instance\zap_scanner.db
✓ Database file access test successful
✓ Flask app imported successfully
Starting ZAP Security Scanner
🌐 Web Interface: http://localhost:8080
```

## Interface URL
Once running, access your modern security scanner at:
**http://localhost:8080**

The new interface features:
- Beautiful glassmorphism design
- Professional gradient backgrounds  
- Interactive scan configuration cards
- Real-time progress monitoring
- Modern button styling with animations