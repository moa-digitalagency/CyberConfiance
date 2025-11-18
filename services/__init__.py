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
                    'Continuez à utiliser des mots de passe forts et uniques',
                    'Activez l\'authentification à deux facteurs (2FA) sur vos comptes importants',
                    'Soyez vigilant face aux emails de phishing',
                    'Vérifiez régulièrement vos comptes pour détecter toute activité suspecte'
                ]
            }
        elif breach_count <= 3:
            return {
                'level': 'warning',
                'title': 'Fuites détectées - Action recommandée',
                'message': f'Votre email apparaît dans {breach_count} base(s) de données de fuites.',
                'recommendations': [
                    'Changez immédiatement les mots de passe des comptes compromis',
                    'Utilisez des mots de passe uniques pour chaque service',
                    'Activez l\'authentification à deux facteurs (2FA) partout où c\'est possible',
                    'Surveillez vos comptes bancaires et vos relevés de carte de crédit',
                    'Méfiez-vous des emails suspects ou des tentatives de phishing'
                ]
            }
        else:
            return {
                'level': 'danger',
                'title': 'Alerte sécurité - Action immédiate requise',
                'message': f'ATTENTION: Votre email apparaît dans {breach_count} bases de données de fuites!',
                'recommendations': [
                    'URGENT: Changez tous vos mots de passe immédiatement',
                    'Utilisez un gestionnaire de mots de passe pour créer des mots de passe forts et uniques',
                    'Activez l\'authentification à deux facteurs (2FA) sur TOUS vos comptes',
                    'Vérifiez vos comptes bancaires et bloquez votre carte si nécessaire',
                    'Contactez vos banques et services importants pour signaler la compromission',
                    'Surveillez votre crédit et vos informations personnelles',
                    'Envisagez de changer d\'adresse email pour les comptes sensibles',
                    'Soyez extrêmement vigilant face aux tentatives de phishing et d\'arnaque'
                ]
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
