"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier auth.py du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com

"""

"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Routes d'authentification: login, logout.
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required
from urllib.parse import urlparse, urljoin
from datetime import datetime
from models import User
import __init__ as app_module

db = app_module.db

bp = Blueprint('auth', __name__)

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

@bp.route('/admin')
@bp.route('/admin/')
@bp.route('/admin/<path:subpath>')
def admin_block(subpath=None):
    """Block all /admin access - return 404 for security"""
    from flask import abort
    abort(404)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash('Connexion réussie!', 'success')
            next_page = request.form.get('next') or request.args.get('next')

            if not next_page or not is_safe_url(next_page):
                next_page = None

            if user.role == 'admin':
                return redirect(next_page or url_for('admin_panel.dashboard'))
            return redirect(next_page or url_for('main.index'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
    
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnexion réussie.', 'success')
    return redirect(url_for('main.index'))
