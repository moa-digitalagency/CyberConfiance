"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Modeles de journalisation: ActivityLog, SecurityLog, ThreatLog.
"""

from datetime import datetime
from models.base import db


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action_type = db.Column(db.String(100), nullable=False)
    action_detail = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    extra_data = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='activity_logs')
    
    def __repr__(self):
        return f'<ActivityLog {self.action_type} - {self.created_at}>'


class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    extra_data = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='security_logs')

    def __repr__(self):
        return f'<SecurityLog {self.event_type} - {self.severity}>'


class ThreatLog(db.Model):
    __tablename__ = 'threat_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    threat_type = db.Column(db.String(50), nullable=False)
    threat_details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    platform = db.Column(db.String(100))
    device_type = db.Column(db.String(50))
    vpn_detected = db.Column(db.Boolean, default=False)
    metadata_json = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)
    admin_notes = db.Column(db.Text)
    
    def __repr__(self):
        return f'<ThreatLog {self.incident_id} - {self.threat_type}>'
