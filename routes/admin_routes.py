from flask import Blueprint, render_template, redirect, url_for
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
import __init__ as app_module
db = app_module.db
admin = app_module.admin
from models import Article, Rule, Tool, Scenario, Resource, News, Contact, GlossaryTerm, User, BreachAnalysis, QuizResult, SecurityAnalysis

bp = Blueprint('admin_bp', __name__, url_prefix='/admin_bp')

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('main.login'))

class BreachAnalysisView(SecureModelView):
    column_list = ['id', 'email', 'breach_count', 'risk_level', 'ip_address', 'created_at']
    column_searchable_list = ['email', 'ip_address']
    column_filters = ['risk_level', 'breach_count', 'created_at']
    column_sortable_list = ['id', 'email', 'breach_count', 'risk_level', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'email': 'Email',
        'breach_count': 'Nb. de fuites',
        'risk_level': 'Niveau de risque',
        'breaches_found': 'Fuites trouvées',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'created_at': 'Date de recherche'
    }

class QuizResultView(SecureModelView):
    column_list = ['id', 'email', 'overall_score', 'created_at', 'ip_address']
    column_searchable_list = ['email', 'ip_address']
    column_filters = ['overall_score', 'created_at']
    column_sortable_list = ['id', 'email', 'overall_score', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'email': 'Email',
        'overall_score': 'Score global (%)',
        'category_scores': 'Scores par catégorie',
        'answers': 'Réponses',
        'hibp_summary': 'Résumé HIBP',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'created_at': 'Date du quiz'
    }

class SecurityAnalysisView(SecureModelView):
    column_list = ['id', 'input_type', 'input_value', 'threat_detected', 'threat_level', 'malicious_count', 'total_engines', 'created_at']
    column_searchable_list = ['input_value', 'ip_address']
    column_filters = ['input_type', 'threat_detected', 'threat_level', 'created_at']
    column_sortable_list = ['id', 'input_type', 'threat_detected', 'threat_level', 'malicious_count', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'input_value': 'Valeur analysée',
        'input_type': 'Type',
        'analysis_results': 'Résultats',
        'threat_detected': 'Menace détectée',
        'threat_level': 'Niveau de menace',
        'malicious_count': 'Détections malveillantes',
        'total_engines': 'Total moteurs',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'created_at': 'Date d\'analyse'
    }

admin.add_view(SecureModelView(User, db.session, name='Utilisateurs'))
admin.add_view(SecureModelView(Article, db.session, name='Articles'))
admin.add_view(SecureModelView(Rule, db.session, name='Règles'))
admin.add_view(SecureModelView(Tool, db.session, name='Outils'))
admin.add_view(SecureModelView(Scenario, db.session, name='Scénarios'))
admin.add_view(SecureModelView(Resource, db.session, name='Ressources'))
admin.add_view(SecureModelView(News, db.session, name='Actualités'))
admin.add_view(SecureModelView(Contact, db.session, name='Contacts'))
admin.add_view(SecureModelView(GlossaryTerm, db.session, name='Glossaire'))
admin.add_view(BreachAnalysisView(BreachAnalysis, db.session, name='Analyses de fuites'))
admin.add_view(QuizResultView(QuizResult, db.session, name='Résultats de quiz'))
admin.add_view(SecurityAnalysisView(SecurityAnalysis, db.session, name='Analyses de sécurité'))
