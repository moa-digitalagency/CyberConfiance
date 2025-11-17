from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_login import LoginManager
from config import Config

db = SQLAlchemy()
admin = Admin(name='CyberConfiance Admin', template_mode='bootstrap3')
login_manager = LoginManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    db.init_app(app)
    admin.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))
    
    from app.routes import main, admin_routes
    app.register_blueprint(main.bp)
    app.register_blueprint(admin_routes.bp)
    
    with app.app_context():
        db.create_all()
        initialize_data()
    
    return app

def initialize_data():
    from app.models import User, Rule, GlossaryTerm
    import os
    
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    admin_password_set = bool(os.environ.get('ADMIN_PASSWORD'))
    
    if User.query.count() == 0:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        admin = User(username='admin', email='admin@cyberconfiance.fr', is_admin=True)
        admin.set_password(admin_password)
        db.session.add(admin)
        
        if os.environ.get('ADMIN_PASSWORD'):
            print("✓ Admin user created with custom password from ADMIN_PASSWORD environment variable.")
        else:
            print("=" * 80)
            print("⚠️  WARNING: Using default admin credentials!")
            print("   Username: admin")
            print("   Password: admin123")
            print("   ")
            print("   For production, set ADMIN_PASSWORD environment variable:")
            print("   export ADMIN_PASSWORD='your_secure_password'")
            print("=" * 80)
    else:
        if not is_debug and not admin_password_set:
            admin = User.query.filter_by(username='admin', is_admin=True).first()
            if admin and admin.check_password('admin123'):
                print("=" * 80)
                print("⚠️  CRITICAL SECURITY WARNING!")
                print("   Admin account is using the DEFAULT PASSWORD in PRODUCTION mode!")
                print("   ")
                print("   Set ADMIN_PASSWORD environment variable immediately:")
                print("   export ADMIN_PASSWORD='your_secure_password'")
                print("   ")
                print("   Then delete and recreate the admin user in the database,")
                print("   or change the password in the /admin panel.")
                print("=" * 80)
    
    if Rule.query.count() == 0:
        sample_rules = [
            Rule(title="Utilisez des mots de passe forts et uniques", 
                 description="Créez des mots de passe d'au moins 12 caractères avec majuscules, minuscules, chiffres et symboles. Utilisez un mot de passe différent pour chaque service.", 
                 order=1),
            Rule(title="Activez l'authentification à deux facteurs", 
                 description="Ajoutez une couche de sécurité supplémentaire en activant l'authentification à deux facteurs (2FA) sur tous vos comptes importants.", 
                 order=2),
            Rule(title="Méfiez-vous des emails suspects", 
                 description="Ne cliquez pas sur les liens ou pièces jointes provenant d'expéditeurs inconnus. Vérifiez toujours l'adresse email de l'expéditeur.", 
                 order=3),
            Rule(title="Maintenez vos logiciels à jour", 
                 description="Installez régulièrement les mises à jour de sécurité pour votre système d'exploitation, navigateur et applications.", 
                 order=4),
            Rule(title="Utilisez un antivirus", 
                 description="Installez et maintenez à jour un logiciel antivirus fiable pour protéger votre ordinateur contre les malwares.", 
                 order=5),
            Rule(title="Sauvegardez régulièrement vos données", 
                 description="Effectuez des sauvegardes régulières de vos données importantes sur un support externe ou dans le cloud.", 
                 order=6),
        ]
        db.session.add_all(sample_rules)
        
    if GlossaryTerm.query.count() == 0:
        sample_terms = [
            GlossaryTerm(term="Phishing", definition="Technique d'attaque visant à obtenir des informations confidentielles en se faisant passer pour un tiers de confiance."),
            GlossaryTerm(term="Malware", definition="Logiciel malveillant conçu pour endommager ou accéder sans autorisation à un système informatique."),
            GlossaryTerm(term="Ransomware", definition="Type de malware qui chiffre les données de la victime et demande une rançon pour les déchiffrer."),
            GlossaryTerm(term="VPN", definition="Virtual Private Network - Réseau privé virtuel qui crée une connexion sécurisée et chiffrée sur Internet."),
            GlossaryTerm(term="Pare-feu", definition="Système de sécurité qui contrôle le trafic réseau entrant et sortant selon des règles prédéfinies."),
        ]
        db.session.add_all(sample_terms)
        
    db.session.commit()
    print("Sample data initialized!")
