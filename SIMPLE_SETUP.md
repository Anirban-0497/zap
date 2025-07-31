# Simple Local Setup

## Requirements
- Python 3.8+
- OWASP ZAP installed on your machine

## Quick Setup

1. **Download all files** from this project to your local folder

2. **Install dependencies:**
```bash
pip install flask flask-sqlalchemy python-owasp-zap-v2.4 reportlab beautifulsoup4 psutil requests
```

3. **Run the application:**
```bash
python main.py
```

4. **Open browser:** http://localhost:5000

## That's it!

The app will automatically find your ZAP installation and start scanning with 100+ vulnerability detection.

## If ZAP not found
Set the path manually:
```bash
export ZAP_PATH="/path/to/your/zap"
```

Then run `python main.py` again.