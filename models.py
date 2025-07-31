from app import db
from datetime import datetime
from sqlalchemy import Text

class ScanRecord(db.Model):
    """Model to store scan records and results"""
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending')  # pending, started, completed, failed, stopped
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    vulnerability_count = db.Column(db.Integer, default=0)
    results_json = db.Column(Text)  # Store scan results as JSON
    error_message = db.Column(Text)
    
    def __repr__(self):
        return f'<ScanRecord {self.id}: {self.target_url}>'
    
    @property
    def duration(self):
        """Calculate scan duration"""
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return None
    
    @property
    def status_badge_class(self):
        """Return Bootstrap badge class for status"""
        status_classes = {
            'pending': 'bg-secondary',
            'started': 'bg-primary',
            'completed': 'bg-success',
            'failed': 'bg-danger',
            'stopped': 'bg-warning'
        }
        return status_classes.get(self.status, 'bg-secondary')
