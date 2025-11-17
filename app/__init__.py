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
    from app.models import User, Rule, GlossaryTerm, Scenario, Tool, Resource, News
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
        rules_data = [
            {"title": "Utilisez un mot de passe fort", "content": "Un mot de passe fort doit contenir au moins 12 caractères, inclure des lettres majuscules et minuscules, des chiffres et des symboles. Évitez les mots du dictionnaire et les informations personnelles."},
            {"title": "Activez l'authentification à deux facteurs", "content": "L'authentification à deux facteurs (2FA) ajoute une couche de sécurité supplémentaire en exigeant une seconde preuve d'identité lors de la connexion."},
            {"title": "Mettez à jour régulièrement vos logiciels", "content": "Les mises à jour corrigent souvent des failles de sécurité. Configurez vos appareils pour qu'ils se mettent à jour automatiquement."},
            {"title": "Soyez vigilant face au phishing", "content": "Ne cliquez pas sur des liens suspects dans les emails ou les messages. Vérifiez toujours l'adresse de l'expéditeur et l'URL avant de saisir vos identifiants."},
            {"title": "Utilisez un gestionnaire de mots de passe", "content": "Un gestionnaire de mots de passe vous aide à stocker et générer des mots de passe uniques pour chaque compte."},
            {"title": "Sécurisez vos appareils mobiles", "content": "Utilisez un code PIN, un motif ou une reconnaissance biométrique pour verrouiller vos appareils mobiles."},
            {"title": "Ne partagez pas vos informations personnelles", "content": "Évitez de partager vos informations personnelles sur les réseaux sociaux ou les sites non sécurisés."},
            {"title": "Utilisez un antivirus", "content": "Installez un antivirus fiable et assurez-vous qu'il est toujours à jour."},
            {"title": "Soyez prudent sur les réseaux Wi-Fi publics", "content": "Évitez d'accéder à des comptes sensibles sur les réseaux Wi-Fi publics. Utilisez un VPN si nécessaire."},
            {"title": "Sauvegardez régulièrement vos données", "content": "Effectuez des sauvegardes régulières de vos données importantes sur un support externe ou dans le cloud."},
            {"title": "Utilisez un pare-feu", "content": "Un pare-feu bloque les connexions non autorisées à votre réseau."},
            {"title": "Évitez les logiciels piratés", "content": "Les logiciels piratés peuvent contenir des malwares. Téléchargez uniquement des logiciels à partir de sources officielles."},
            {"title": "Formez vos collaborateurs", "content": "Sensibilisez vos collaborateurs aux bonnes pratiques de cybersécurité."},
            {"title": "Utilisez des adresses email distinctes", "content": "Utilisez une adresse email différente pour chaque service afin de limiter les risques en cas de fuite."},
            {"title": "Surveillez vos comptes", "content": "Vérifiez régulièrement l'activité de vos comptes et activez les alertes de sécurité."},
            {"title": "Vérifiez les autorisations des applications", "content": "Examinez régulièrement les autorisations accordées aux applications installées sur vos appareils."},
            {"title": "Ne cliquez pas sur les pièces jointes suspectes", "content": "Les pièces jointes peuvent contenir des virus. Vérifiez toujours l'expéditeur avant d'ouvrir une pièce jointe."},
            {"title": "Utilisez un VPN", "content": "Un VPN crypte votre connexion et protège vos données lors de la navigation sur Internet."},
            {"title": "Évitez les sites non sécurisés", "content": "Ne saisissez jamais vos identifiants sur des sites qui ne commencent pas par https://."},
            {"title": "Restez informé", "content": "Suivez les actualités en cybersécurité pour rester au courant des nouvelles menaces et des meilleures pratiques."},
        ]
        
        rules = [Rule(title=rule["title"], description=rule["content"], order=idx+1) for idx, rule in enumerate(rules_data)]
        db.session.add_all(rules)
        
    if GlossaryTerm.query.count() == 0:
        glossary_data = [
            {"term": "2FA", "definition": "Authentification à deux facteurs : méthode de sécurité qui exige deux preuves d'identité pour accéder à un compte."},
            {"term": "Phishing", "definition": "Technique de fraude visant à obtenir des informations personnelles en se faisant passer pour une entité de confiance."},
            {"term": "Deepfake", "definition": "Vidéo ou audio falsifié utilisant l'intelligence artificielle pour imiter une personne réelle."},
            {"term": "Ransomware", "definition": "Logiciel malveillant qui chiffre les fichiers d'un utilisateur et demande une rançon pour les déchiffrer."},
        ]
        
        terms = [GlossaryTerm(term=item["term"], definition=item["definition"]) for item in glossary_data]
        db.session.add_all(terms)
    
    if Scenario.query.count() == 0:
        scenarios_data = [
            {"title": "Phishing par email", "content": "Un utilisateur reçoit un email qui semble provenir de sa banque, lui demandant de cliquer sur un lien pour vérifier son compte. Le lien redirige vers un faux site qui vole les identifiants."},
            {"title": "Ransomware", "content": "Un fichier malveillant s'installe sur l'ordinateur d'un utilisateur et chiffre tous ses fichiers. Les cybercriminels demandent une rançon pour les déchiffrer."},
            {"title": "Wi-Fi public non sécurisé", "content": "Un utilisateur se connecte à un réseau Wi-Fi public non sécurisé et un pirate intercepte ses données personnelles."},
            {"title": "Deepfake", "content": "Un vidéo falsifiée montre un dirigeant d'entreprise en train de donner des instructions frauduleuses, ce qui peut entraîner des pertes financières."},
        ]
        
        scenarios = [Scenario(title=s["title"], description=s["content"]) for s in scenarios_data]
        db.session.add_all(scenarios)
    
    if Tool.query.count() == 0:
        tools_data = [
            {"title": "Clé de sécurité", "content": "Un dispositif physique qui ajoute une couche d'authentification à deux facteurs."},
            {"title": "Disque dur crypté", "content": "Un disque dur qui chiffre automatiquement toutes les données stockées."},
            {"title": "Filtre de confidentialité", "content": "Un accessoire pour protéger l'écran des regards indiscrets."},
            {"title": "VPN", "content": "Un service qui crypte la connexion Internet et protège les données."},
        ]
        
        tools = [Tool(name=t["title"], description=t["content"]) for t in tools_data]
        db.session.add_all(tools)
    
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
