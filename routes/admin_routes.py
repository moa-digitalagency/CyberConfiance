from flask import Blueprint, render_template, redirect, url_for
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
import __init__ as app_module
db = app_module.db
admin = app_module.admin
from models import Article, Rule, Tool, Scenario, Resource, News, Contact, GlossaryTerm, User

bp = Blueprint('admin_bp', __name__, url_prefix='/admin_bp')

class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('main.login'))

admin.add_view(SecureModelView(User, db.session, name='Utilisateurs'))
admin.add_view(SecureModelView(Article, db.session, name='Articles'))
admin.add_view(SecureModelView(Rule, db.session, name='Règles'))
admin.add_view(SecureModelView(Tool, db.session, name='Outils'))
admin.add_view(SecureModelView(Scenario, db.session, name='Scénarios'))
admin.add_view(SecureModelView(Resource, db.session, name='Ressources'))
admin.add_view(SecureModelView(News, db.session, name='Actualités'))
admin.add_view(SecureModelView(Contact, db.session, name='Contacts'))
admin.add_view(SecureModelView(GlossaryTerm, db.session, name='Glossaire'))
