"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Utilitaires de journalisation pour les activites et evenements de securite.
"""

from models import ActivityLog, SecurityLog, db
from flask import request
from flask_login import current_user
from datetime import datetime

def log_activity(action_type, action_detail=None, success=True, error_message=None, extra_data=None):
    """Log user activity"""
    try:
        log = ActivityLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action_type=action_type,
            action_detail=action_detail,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            success=success,
            error_message=error_message,
            extra_data=extra_data
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging activity: {e}")
        db.session.rollback()

def log_security_event(event_type, severity, description, blocked=False, extra_data=None):
    """Log security-related events"""
    try:
        log = SecurityLog(
            event_type=event_type,
            severity=severity,
            description=description,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            user_id=current_user.id if current_user.is_authenticated else None,
            blocked=blocked,
            extra_data=extra_data
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"Error logging security event: {e}")
        db.session.rollback()
