"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Blueprint admin avec decorateurs d'autorisation.
"""

from flask import Blueprint, redirect, url_for, request, flash
from flask_login import login_required, current_user
from functools import wraps

bp = Blueprint('admin_panel', __name__, url_prefix='/my4dm1n')

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not (current_user.is_active and current_user.role == 'admin'):
            flash('Accès refusé. Vous devez être administrateur actif.', 'danger')
            return redirect(url_for('main.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    """Decorator for routes accessible by moderators and admins"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not (current_user.is_active and current_user.role in ['admin', 'moderator']):
            flash('Accès refusé. Rôle modérateur ou administrateur requis.', 'danger')
            return redirect(url_for('main.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/')
@admin_required
def index():
    """Redirection automatique vers le dashboard"""
    return redirect(url_for('admin_panel.dashboard'))

from routes.admin import dashboard, history, content, settings
