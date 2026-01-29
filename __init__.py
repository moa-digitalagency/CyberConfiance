"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier __init__.py du projet CyberConfiance
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

Factory Flask et configuration de l'application.
Initialise les extensions, les blueprints et les gestionnaires d'erreurs.
"""

from flask import Flask, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, expose
from flask_login import LoginManager, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel
from config import Config

class SecureAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return redirect(url_for('main.login', next='/my4dm1n/admin/'))
        return super(SecureAdminIndexView, self).index()

db = SQLAlchemy()
admin = Admin(
    name='CyberConfiance Admin', 
    template_mode='bootstrap3', 
    url='/my4dm1n/admin', 
    endpoint='admin',
    index_view=SecureAdminIndexView()
)
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
babel = Babel()

def get_locale():
    """Determine the best language for the user"""
    if 'language' in session:
        return session['language']
    return request.accept_languages.best_match(['fr', 'en']) or 'fr'

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024
    
    db.init_app(app)
    admin.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    babel.init_app(app, locale_selector=get_locale)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(int(user_id))
    
    import re
    
    @app.template_filter('striptags')
    def strip_tags(text):
        """Remove HTML tags from a string"""
        if not text:
            return ''
        clean = re.compile('<.*?>')
        return re.sub(clean, '', str(text))
    
    @app.context_processor
    def inject_site_settings():
        """Make site settings available to all templates"""
        from models import SiteSettings, SEOMetadata
        from urllib.parse import urljoin
        
        settings = {}
        all_settings = SiteSettings.query.all()
        for s in all_settings:
            settings[s.key] = s.value
        
        class SettingsObj:
            def __init__(self, data):
                for key, value in data.items():
                    setattr(self, key, value)
            def get(self, key, default=None):
                return getattr(self, key, default)
        
        site_settings = SettingsObj(settings) if settings else None
        
        current_path = request.path
        seo_meta = SEOMetadata.query.filter_by(page_path=current_path, is_active=True).first()
        
        if not seo_meta:
            seo_meta = SEOMetadata.query.filter_by(page_path='/', is_active=True).first()
        
        og_image_absolute = None
        if seo_meta and seo_meta.og_image:
            if seo_meta.og_image.startswith(('http://', 'https://')):
                og_image_absolute = seo_meta.og_image
            else:
                og_image_absolute = urljoin(request.url_root, seo_meta.og_image.lstrip('/'))
        
        custom_head_code = settings.get('custom_head_code', '')
        
        return dict(
            site_settings=site_settings, 
            seo_meta=seo_meta,
            og_image_absolute=og_image_absolute,
            custom_head_code=custom_head_code
        )
    
    @app.after_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

        # Security Headers
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Server'] = 'CyberConfiance Secure Server'

        # Content Security Policy (Strict)
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https: http:; "
            "connect-src 'self';"
        )
        response.headers['Content-Security-Policy'] = csp

        return response
    
    from flask_wtf.csrf import CSRFError
    
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        from flask import flash, redirect, url_for, request
        from flask_login import current_user
        flash('Erreur de validation CSRF. Veuillez réessayer.', 'danger')
        
        if current_user.is_authenticated and current_user.role == 'admin':
            return redirect(url_for('admin_panel.dashboard'))
        return redirect(url_for('main.index'))
    
    @app.errorhandler(404)
    def handle_not_found(e):
        from flask import render_template
        return render_template('error_404.html'), 404
    
    @app.errorhandler(413)
    def handle_file_too_large(e):
        from flask import flash, redirect, request, url_for
        flash('Le fichier est trop volumineux. Taille maximale: 200 Mo.', 'error')
        if request.referrer:
            return redirect(request.referrer)
        return redirect(url_for('main.index'))
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        from flask import render_template
        import traceback
        print(f"ERROR 500: {str(e)}")
        print(traceback.format_exc())
        db.session.rollback()
        return render_template('error_500.html'), 500
    
    from routes import main, admin_routes, admin_panel, request_forms, admin_requests, pages, content, auth, outils
    app.register_blueprint(main.bp)
    app.register_blueprint(pages.bp)
    app.register_blueprint(content.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(admin_routes.bp)
    app.register_blueprint(admin_panel.bp)
    app.register_blueprint(request_forms.bp)
    app.register_blueprint(admin_requests.bp)
    app.register_blueprint(outils.bp)
    
    with app.app_context():
        db.create_all()
        initialize_data()
        from utils.seed_data import seed_all_data
        seed_all_data(db)
    
    return app

def initialize_data():
    from models import User, GlossaryTerm, Tool, Resource, News
    import os
    
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    admin_password_set = bool(os.environ.get('ADMIN_PASSWORD'))
    
    if User.query.count() == 0:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        admin = User(username='admin', email='admin@cyberconfiance.fr', is_admin=True)
        admin.role = 'admin'
        admin.set_password(admin_password)
        db.session.add(admin)
        
        if os.environ.get('ADMIN_PASSWORD'):
            print("✓ Admin user created with custom password from ADMIN_PASSWORD environment variable.")
        else:
            # Log discret pour l'admin uniquement (console serveur)
            print("⚠️  Admin: credentials par défaut utilisés (username: admin)")
    else:
        if not is_debug and not admin_password_set:
            admin = User.query.filter_by(username='admin', is_admin=True).first()
            if admin and admin.check_password('admin123'):
                # Log critique pour l'admin (console serveur uniquement)
                print("⚠️  SÉCURITÉ: Mot de passe admin par défaut détecté en production - Configurez ADMIN_PASSWORD")
    
    if GlossaryTerm.query.count() == 0:
        glossary_data = [
            {"term": "2FA", "definition": "Authentification à deux facteurs : méthode de sécurité qui exige deux preuves d'identité pour accéder à un compte."},
            {"term": "Phishing", "definition": "Technique de fraude visant à obtenir des informations personnelles en se faisant passer pour une entité de confiance."},
            {"term": "Deepfake", "definition": "Vidéo ou audio falsifié utilisant l'intelligence artificielle pour imiter une personne réelle."},
            {"term": "Ransomware", "definition": "Logiciel malveillant qui chiffre les fichiers d'un utilisateur et demande une rançon pour les déchiffrer."},
        ]
        
        terms = [GlossaryTerm(term=item["term"], definition=item["definition"]) for item in glossary_data]
        db.session.add_all(terms)
    
    if Resource.query.count() == 0:
        resources_data = [
            {"title": "Guide de cybersécurité", "link": "/resources/guide.pdf", "description": "Guide complet pour la sécurité numérique."},
            {"title": "Vidéo de sensibilisation", "link": "/resources/video.mp4", "description": "Vidéo explicative sur les bonnes pratiques de cybersécurité."},
            {"title": "Articles d'actualité", "link": "/resources/articles", "description": "Articles récents sur les menaces et les solutions en cybersécurité."},
        ]
        
        resources = [Resource(title=r["title"], url=r["link"], description=r["description"]) for r in resources_data]
        db.session.add_all(resources)
    
    if News.query.count() == 0:
        news_data = [
            {"title": "Nouvelle menace détectée", "content": "Une nouvelle variante de ransomware a été détectée dans plusieurs entreprises. Restez vigilant et mettez à jour vos logiciels."},
            {"title": "Formation en ligne disponible", "content": "Une nouvelle formation en ligne sur la cybersécurité est désormais disponible sur notre site."},
        ]
        
        news_items = [News(title=n["title"], content=n["content"]) for n in news_data]
        db.session.add_all(news_items)
        
    db.session.commit()
    print("Sample data initialized!")
