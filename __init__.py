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
    
    app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
    
    db.init_app(app)
    admin.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    babel.init_app(app, locale_selector=get_locale)
    login_manager.login_view = 'main.login'
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
        from models import SiteSettings
        site_settings = SiteSettings.query.first()
        return dict(site_settings=site_settings)
    
    @app.after_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
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
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        from flask import render_template
        import traceback
        print(f"ERROR 500: {str(e)}")
        print(traceback.format_exc())
        db.session.rollback()
        return render_template('error_500.html'), 500
    
    from routes import main, admin_routes, admin_panel, request_forms, admin_requests
    app.register_blueprint(main.bp)
    app.register_blueprint(admin_routes.bp)
    app.register_blueprint(admin_panel.bp)
    app.register_blueprint(request_forms.bp)
    app.register_blueprint(admin_requests.bp)
    
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
