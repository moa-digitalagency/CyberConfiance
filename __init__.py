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
    
    from routes import main, admin_routes
    app.register_blueprint(main.bp)
    app.register_blueprint(admin_routes.bp)
    
    with app.app_context():
        db.create_all()
        initialize_data()
    
    return app

def initialize_data():
    from models import User, Rule, GlossaryTerm, Scenario, Tool, Resource, News
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
            {"title": "Séparez strictement vos usages privés et professionnels", "content": "Utilisez des appareils distincts pour vos activités professionnelles et personnelles. Évitez d'installer des applications non vérifiées sur vos appareils professionnels. Ne partagez jamais vos identifiants professionnels sur des plateformes non sécurisées."},
            {"title": "Protégez vos accès par des mots de passe complexes et uniques", "content": "Créez des mots de passe robustes (minimum 12 caractères, incluant majuscules, minuscules, chiffres et symboles). Utilisez des mots de passe uniques pour chaque compte. Utilisez un gestionnaire de mots de passe pour stocker vos identifiants de manière sécurisée."},
            {"title": "Activez l'authentification à deux facteurs (2FA)", "content": "Activez le 2FA sur tous vos comptes sensibles. Choisissez une méthode sécurisée (applications d'authentification, clés USB physiques). Le 2FA renforce considérablement la sécurité même si votre mot de passe est compromis."},
            {"title": "Protégez vos équipements physiques", "content": "Gardez vos appareils toujours sous votre contrôle. Protégez vos appareils avec des codes de verrouillage et du chiffrement. Utilisez des câbles de verrouillage pour vos ordinateurs portables lors des déplacements."},
            {"title": "Verrouillez vos appareils et espaces de travail", "content": "Verrouillez systématiquement vos appareils quand vous vous absentez. Rangez toujours vos documents sensibles dans des tiroirs fermés à clé. Installez des filtres de confidentialité sur vos écrans."},
            {"title": "Soyez vigilant avec les courriels et les liens non sollicités", "content": "Analysez l'expéditeur avant de cliquer sur un lien. Soyez prudent avec les pièces jointes. Vérifiez les URL avant de saisir vos identifiants. Le phishing est l'une des techniques les plus courantes des cybercriminels."},
            {"title": "Sauvegardez vos données régulièrement et de manière sécurisée", "content": "Établissez un plan de sauvegarde régulier. Stockez vos sauvegardes dans des endroits sécurisés hors ligne. Testez régulièrement vos sauvegardes pour vous assurer qu'elles fonctionnent."},
            {"title": "Évitez les réseaux publics non sécurisés", "content": "Évitez les réseaux Wi-Fi publics pour accéder à des comptes sensibles. Utilisez un VPN pour chiffrer vos communications. Vérifiez le nom du réseau avant de vous connecter."},
            {"title": "Faites preuve de vigilance lors de vos échanges téléphoniques ou en visioconférence", "content": "Utilisez des outils sécurisés et chiffrés pour vos communications. Protégez l'accès aux réunions par des codes. Sensibilisez vos participants aux risques d'espionnage."},
            {"title": "Veillez à la sécurité de votre smartphone", "content": "Utilisez uniquement des applications provenant de sources fiables. Vérifiez les autorisations demandées par les applications. Activez le chiffrement des données de votre appareil."},
            {"title": "Surveillez votre identité numérique sur les réseaux sociaux", "content": "Limitez la quantité d'informations personnelles partagées publiquement. Désactivez l'enregistrement des métadonnées sur vos photos. Surveillez régulièrement votre présence numérique pour détecter d'éventuelles usurpations."},
            {"title": "Mettez à jour vos logiciels et appareils régulièrement", "content": "Les mises à jour corrigent des failles de sécurité. Activez les mises à jour automatiques. Vérifiez que tous vos appareils connectés sont également à jour."},
            {"title": "Formez-vous et sensibilisez votre équipe aux bonnes pratiques", "content": "Organisez des sessions de formation régulières. Partagez des consignes claires sur les bonnes pratiques. Simulez des attaques pour évaluer la vigilance. Encouragez la communication en cas de doute."},
            {"title": "Installez des filtres de confidentialité sur vos écrans", "content": "Les filtres de confidentialité empêchent l'espionnage visuel dans les espaces publics. Utilisez des écrans secondaires pour les présentations. Protégez vos appareils des regards indiscrets."},
            {"title": "Évitez d'utiliser des équipements non vérifiés", "content": "N'utilisez que des équipements vérifiés et de confiance. Désactivez l'exécution automatique des périphériques USB. Les clés USB et disques externes peuvent contenir des logiciels malveillants."},
            {"title": "Stockez vos données sensibles dans des espaces sécurisés", "content": "Chiffrez vos données sensibles avant de les stocker. Utilisez des services de stockage cloud sécurisés et certifiés. Limitez l'accès aux données aux seules personnes autorisées."},
            {"title": "Identifiez et gérez vos points d'accès critiques", "content": "Identifiez tous les points d'accès critiques (ports, serveurs, comptes administrateurs). Appliquez des mots de passe robustes et uniques. Surveillez régulièrement les accès et tentatives de connexion."},
            {"title": "Soyez prudent avec les demandes d'informations sensibles", "content": "Vérifiez toujours l'identité de la personne qui demande des informations. Ne communiquez jamais d'informations sensibles par téléphone ou email sans vérification. Méfiez-vous des techniques d'ingénierie sociale."},
            {"title": "Utilisez des outils de chiffrement pour vos communications", "content": "Utilisez des outils de messagerie chiffrée (Signal, ProtonMail). Activez le chiffrement des emails et fichiers sensibles. Le chiffrement protège vos communications contre l'espionnage."},
            {"title": "Réagissez rapidement en cas d'incident de sécurité", "content": "Mettez en place un plan de réponse aux incidents. Alertez rapidement les responsables en cas de suspicion. Documentez chaque incident pour améliorer la prévention. Réagir rapidement limite les dégâts."},
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
