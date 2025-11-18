from flask import Blueprint, render_template, redirect, url_for
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
import __init__ as app_module
db = app_module.db
admin = app_module.admin
from models import Article, Rule, Tool, Scenario, Resource, News, Contact, GlossaryTerm, User, BreachAnalysis

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
