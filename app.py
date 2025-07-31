import os
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
import threading
import time
from datetime import datetime
import json

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///zap_scanner.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Import modules after app creation to avoid circular imports
from scanner import ZAPScanner
from report_generator import ReportGenerator

# Global scanner instance
scanner = None
scan_status = {
    'running': False,
    'progress': 0,
    'status': 'idle',
    'current_url': '',
    'scan_id': None,
    'results': None,
    'error': None
}

with app.app_context():
    # Import models here so their tables are created
    import models
    db.create_all()

@app.route('/')
def index():
    """Main page with URL input form"""
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    global scanner, scan_status
    
    target_url = request.form.get('url', '').strip()
    scan_types = request.form.getlist('scan_types')
    
    if not target_url:
        flash('Please enter a valid URL', 'error')
        return redirect(url_for('index'))
    
    if not scan_types:
        flash('Please select at least one scan type', 'error')
        return redirect(url_for('index'))
    
    # Validate URL format
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Check if a scan is already running
    if scan_status['running']:
        flash('A scan is already in progress. Please wait for it to complete.', 'warning')
        return redirect(url_for('index'))
    
    try:
        # Initialize scanner
        scanner = ZAPScanner()
        
        # Create scan record
        scan_record = models.ScanRecord(
            target_url=target_url,
            status='started',
            started_at=datetime.utcnow()
        )
        db.session.add(scan_record)
        db.session.commit()
        
        # Reset scan status
        scan_status.update({
            'running': True,
            'progress': 0,
            'status': 'initializing',
            'current_url': target_url,
            'scan_id': scan_record.id,
            'scan_types': scan_types,
            'results': None,
            'error': None
        })
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=run_scan, args=(target_url, scan_record.id, scan_types))
        scan_thread.daemon = True
        scan_thread.start()
        
        flash('Scan started successfully!', 'success')
        return redirect(url_for('scan_progress'))
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        flash(f'Error starting scan: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/scan_progress')
def scan_progress():
    """Show scan progress page"""
    return render_template('scan_results.html', scan_status=scan_status)

@app.route('/api/scan_status')
def api_scan_status():
    """API endpoint to get current scan status"""
    return jsonify(scan_status)

@app.route('/api/stop_scan', methods=['POST'])
def api_stop_scan():
    """API endpoint to stop current scan"""
    global scanner, scan_status
    
    try:
        if scanner and scan_status['running']:
            scanner.stop_scan()
            scan_status.update({
                'running': False,
                'status': 'stopped',
                'error': 'Scan stopped by user'
            })
            
            # Update database record
            if scan_status['scan_id']:
                scan_record = models.ScanRecord.query.get(scan_status['scan_id'])
                if scan_record:
                    scan_record.status = 'stopped'
                    scan_record.completed_at = datetime.utcnow()
                    db.session.commit()
            
            return jsonify({'success': True, 'message': 'Scan stopped successfully'})
        else:
            return jsonify({'success': False, 'message': 'No active scan to stop'})
    except Exception as e:
        logger.error(f"Error stopping scan: {str(e)}")
        return jsonify({'success': False, 'message': f'Error stopping scan: {str(e)}'})

@app.route('/download_report/<int:scan_id>')
def download_report(scan_id):
    """Download PDF report for a completed scan"""
    try:
        scan_record = models.ScanRecord.query.get_or_404(scan_id)
        
        if not scan_record.results_json:
            flash('No results available for this scan', 'error')
            return redirect(url_for('index'))
        
        # Generate PDF report
        report_gen = ReportGenerator()
        results = json.loads(scan_record.results_json)
        pdf_path = report_gen.generate_pdf_report(results, scan_record.target_url)
        
        return send_file(pdf_path, as_attachment=True, download_name=f'security_report_{scan_id}.pdf')
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        flash(f'Error generating report: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/scan_history')
def scan_history():
    """Show scan history"""
    scans = models.ScanRecord.query.order_by(models.ScanRecord.started_at.desc()).limit(20).all()
    return render_template('scan_history.html', scans=scans)

def run_scan(target_url, scan_id, scan_types):
    """Run the actual security scan in background"""
    global scanner, scan_status
    
    try:
        with app.app_context():
            # Update status
            scan_status['status'] = 'starting_zap'
            scan_status['progress'] = 5
            
            # Start ZAP and perform scan
            scanner.start_zap()
            
            spider_results = None
            active_results = None
            current_progress = 10
            
            # Spider scan (crawling) - if selected
            if 'spider' in scan_types:
                scan_status['status'] = 'crawling'
                scan_status['progress'] = current_progress
                
                spider_results = scanner.spider_scan(target_url, update_callback=update_scan_progress)
                current_progress = 50 if 'active' in scan_types else 85
            
            # Active scan (vulnerability detection) - if selected
            if 'active' in scan_types:
                scan_status['status'] = 'active_scanning'
                scan_status['progress'] = current_progress
                
                active_results = scanner.active_scan(target_url, update_callback=update_scan_progress)
                current_progress = 85
            
            scan_status['status'] = 'generating_report'
            scan_status['progress'] = 90
            
            # Get final results
            results = scanner.get_scan_results()
            results['scan_types'] = scan_types
            
            # Update database
            scan_record = models.ScanRecord.query.get(scan_id)
            if scan_record:
                scan_record.status = 'completed'
                scan_record.completed_at = datetime.utcnow()
                scan_record.results_json = json.dumps(results)
                scan_record.vulnerability_count = len(results.get('alerts', []))
                db.session.commit()
            
            # Update final status
            scan_status.update({
                'running': False,
                'progress': 100,
                'status': 'completed',
                'results': results
            })
            
            logger.info(f"Scan completed successfully for {target_url} with types: {scan_types}")
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        
        try:
            with app.app_context():
                # Update error status
                scan_status.update({
                    'running': False,
                    'status': 'error',
                    'error': str(e)
                })
                
                # Update database
                scan_record = models.ScanRecord.query.get(scan_id)
                if scan_record:
                    scan_record.status = 'failed'
                    scan_record.completed_at = datetime.utcnow()
                    scan_record.error_message = str(e)
                    db.session.commit()
        except Exception as db_error:
            logger.error(f"Failed to update database after scan error: {str(db_error)}")
    
    finally:
        # Clean up
        if scanner:
            scanner.cleanup()

def update_scan_progress(progress, status_msg=None):
    """Update scan progress"""
    global scan_status
    scan_status['progress'] = min(progress, 95)  # Cap at 95% until final completion
    if status_msg:
        scan_status['status'] = status_msg

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
