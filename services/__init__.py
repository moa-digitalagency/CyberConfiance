from models import Article, Rule, Tool, Scenario, Resource, News, Contact, GlossaryTerm
import __init__ as app_module
import os
import requests
import hashlib
from urllib.parse import quote
db = app_module.db

class HaveIBeenPwnedService:
    @staticmethod
    def check_email_breach(email):
        """
        Vérifie si un email a été compromis en utilisant l'API Have I Been Pwned
        Retourne une liste de breaches et le nombre total
        """
        api_key = os.environ.get('HIBP_API_KEY')
        if not api_key:
            return {'error': 'Clé API non configurée', 'breaches': [], 'count': 0}
        
        encoded_email = quote(email, safe='')
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}"
        headers = {
            'hibp-api-key': api_key,
            'User-Agent': 'CyberConfiance-App'
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                return {
                    'error': None,
                    'breaches': breaches,
                    'count': len(breaches),
                    'email': email
                }
            elif response.status_code == 404:
                return {
                    'error': None,
                    'breaches': [],
                    'count': 0,
                    'email': email
                }
            elif response.status_code == 401:
                return {'error': 'Clé API invalide', 'breaches': [], 'count': 0}
            elif response.status_code == 429:
                return {'error': 'Trop de requêtes, veuillez réessayer plus tard', 'breaches': [], 'count': 0}
            else:
                return {'error': f'Erreur API: {response.status_code}', 'breaches': [], 'count': 0}
                
        except requests.exceptions.Timeout:
            return {'error': 'Délai d\'attente dépassé', 'breaches': [], 'count': 0}
        except requests.exceptions.RequestException as e:
            return {'error': f'Erreur de connexion: {str(e)}', 'breaches': [], 'count': 0}
    
    @staticmethod
    def get_breach_recommendations(breach_count):
        """
        Génère des recommandations basées sur le nombre de breaches
        """
        if breach_count == 0:
            return {
                'level': 'safe',
                'title': 'Aucune fuite détectée',
                'message': 'Votre adresse email n\'apparaît dans aucune base de données de fuites connues.',
                'recommendations': [
                    '🔐 Sécurité proactive : Utilisez des mots de passe forts et uniques pour chaque service, activez l\'authentification à deux facteurs (2FA) sur tous vos comptes importants.',
                    '⚠️ Vigilance constante : Restez attentif aux emails de phishing et vérifiez régulièrement l\'activité de vos comptes pour détecter tout comportement suspect.'
                ]
            }
        elif breach_count <= 3:
            return {
                'level': 'warning',
                'title': 'Fuites détectées - Action recommandée',
                'message': f'Votre email apparaît dans {breach_count} base(s) de données de fuites.',
                'recommendations': [
                    '🚨 Actions immédiates : Changez tous les mots de passe des services compromis. Créez des mots de passe forts et uniques pour chaque compte (utilisez un gestionnaire de mots de passe).',
                    '🛡️ Renforcement de la sécurité : Activez l\'authentification à deux facteurs (2FA) sur tous vos comptes, particulièrement ceux liés à vos finances, réseaux sociaux et emails.',
                    '💳 Surveillance financière : Si cet email est utilisé pour vos comptes bancaires ou services de paiement, surveillez vos transactions et relevés de carte. Contactez votre banque en cas d\'activité suspecte.',
                    '📧 Protection anti-phishing : Redoublez de vigilance face aux emails suspects, surtout ceux demandant des informations personnelles ou des actions urgentes.'
                ]
            }
        else:
            return {
                'level': 'danger',
                'title': 'Alerte sécurité - Action immédiate requise',
                'message': f'ATTENTION: Votre email apparaît dans {breach_count} bases de données de fuites!',
                'recommendations': [
                    '🔥 URGENT - Sécurisation des comptes : Changez IMMÉDIATEMENT tous vos mots de passe en utilisant un gestionnaire de mots de passe. Activez l\'authentification à deux facteurs (2FA) sur TOUS vos comptes sans exception.',
                    '💰 Protection financière critique : Si cet email est lié à des comptes bancaires, services de paiement ou crypto-monnaies, contactez immédiatement vos institutions financières. Vérifiez tous vos relevés, bloquez votre carte si nécessaire et surveillez votre crédit.',
                    '🆔 Gestion de l\'identité : Envisagez sérieusement de créer une nouvelle adresse email pour vos comptes sensibles (banque, santé, administration). Surveillez l\'utilisation frauduleuse de votre identité.',
                    '⚠️ Vigilance maximale : Vous êtes une cible de choix pour le phishing et les arnaques. Ne cliquez jamais sur des liens suspects, vérifiez l\'identité de tout contact inattendu et signalez toute activité suspecte.'
                ]
            }
    
    @staticmethod
    def get_data_breach_scenarios():
        """
        Retourne les scénarios d'attaque possibles pour chaque type de donnée compromise
        """
        return {
            'Email addresses': {
                'icon': '📧',
                'risk': 'Moyen',
                'scenario': 'Les pirates peuvent vous envoyer des emails de phishing personnalisés, s\'inscrire à des services en votre nom, ou vendre votre adresse à des spammeurs.'
            },
            'Passwords': {
                'icon': '🔑',
                'risk': 'Critique',
                'scenario': 'Si vous réutilisez ce mot de passe ailleurs, les pirates peuvent accéder à tous ces comptes. Changement immédiat requis.'
            },
            'Names': {
                'icon': '👤',
                'risk': 'Faible',
                'scenario': 'Combiné à d\'autres données, votre nom permet des attaques de phishing ciblées et l\'usurpation d\'identité.'
            },
            'Phone numbers': {
                'icon': '📱',
                'risk': 'Élevé',
                'scenario': 'Les pirates peuvent vous envoyer des SMS de phishing, vous appeler en se faisant passer pour votre banque, ou effectuer un SIM swapping pour prendre contrôle de vos comptes.'
            },
            'Physical addresses': {
                'icon': '🏠',
                'risk': 'Moyen',
                'scenario': 'Votre adresse peut servir à de l\'usurpation d\'identité, des arnaques postales, ou des cambriolages en croisant avec d\'autres données publiques.'
            },
            'Dates of birth': {
                'icon': '🎂',
                'risk': 'Élevé',
                'scenario': 'Élément clé pour l\'usurpation d\'identité. Combiné à votre nom, permet d\'ouvrir des comptes bancaires, contracter des crédits, ou accéder à vos dossiers médicaux.'
            },
            'Credit cards': {
                'icon': '💳',
                'risk': 'Critique',
                'scenario': 'Utilisation frauduleuse immédiate pour des achats en ligne. Contactez votre banque IMMÉDIATEMENT pour bloquer la carte et surveiller vos transactions.'
            },
            'Bank account numbers': {
                'icon': '🏦',
                'risk': 'Critique',
                'scenario': 'Les pirates peuvent effectuer des prélèvements, créer des chèques frauduleux, ou usurper votre identité financière. Alertez votre banque sans délai.'
            },
            'Social security numbers': {
                'icon': '🆔',
                'risk': 'Critique',
                'scenario': 'Le Saint Graal de l\'usurpation d\'identité. Permet d\'ouvrir des comptes, contracter des prêts, accéder aux services sociaux, et détruire votre crédit pendant des années.'
            },
            'IP addresses': {
                'icon': '🌐',
                'risk': 'Faible',
                'scenario': 'Révèle votre localisation approximative et fournisseur Internet. Peut servir à des attaques ciblées ou tracer vos activités en ligne.'
            },
            'Geographic locations': {
                'icon': '📍',
                'risk': 'Moyen',
                'scenario': 'Révèle vos habitudes et lieux fréquentés. Risque de harcèlement, cambriolage, ou ciblage publicitaire abusif.'
            },
            'Usernames': {
                'icon': '👁️',
                'risk': 'Faible',
                'scenario': 'Permet de retrouver vos autres comptes en ligne et construire un profil détaillé de votre présence numérique pour des attaques ciblées.'
            },
            'Security questions and answers': {
                'icon': '❓',
                'risk': 'Élevé',
                'scenario': 'Les pirates peuvent réinitialiser vos mots de passe en répondant à ces questions. Changez immédiatement vos questions de sécurité sur tous vos comptes.'
            },
            'Partial credit card data': {
                'icon': '💳',
                'risk': 'Élevé',
                'scenario': 'Même partielles, ces données combinées à d\'autres fuites permettent de reconstituer le numéro complet ou de valider des transactions.'
            },
            'Personal health data': {
                'icon': '🏥',
                'risk': 'Critique',
                'scenario': 'Chantage possible, discrimination à l\'embauche ou pour les assurances, usurpation d\'identité médicale pour obtenir des prescriptions ou soins.'
            },
            'Biometric data': {
                'icon': '👆',
                'risk': 'Critique',
                'scenario': 'Contrairement aux mots de passe, vous ne pouvez pas changer vos empreintes digitales. Risque permanent d\'usurpation d\'identité biométrique.'
            }
        }

class ContentService:
    @staticmethod
    def get_published_articles():
        return Article.query.filter_by(published=True).order_by(Article.created_at.desc()).all()
    
    @staticmethod
    def get_all_rules():
        return Rule.query.order_by(Rule.order).all()
    
    @staticmethod
    def get_all_tools():
        return Tool.query.order_by(Tool.name).all()
    
    @staticmethod
    def get_all_scenarios():
        return Scenario.query.order_by(Scenario.created_at.asc()).all()
    
    @staticmethod
    def get_all_resources():
        return Resource.query.order_by(Resource.created_at.desc()).all()
    
    @staticmethod
    def get_latest_news(limit=10):
        return News.query.order_by(News.published_date.desc()).limit(limit).all()
    
    @staticmethod
    def get_glossary_terms():
        return GlossaryTerm.query.order_by(GlossaryTerm.term).all()
    
    @staticmethod
    def save_contact(name, email, subject, message):
        contact = Contact(name=name, email=email, subject=subject, message=message)
        db.session.add(contact)
        db.session.commit()
        return contact
