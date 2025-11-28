from flask import Blueprint, render_template, redirect, url_for
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from markupsafe import Markup
import __init__ as app_module
db = app_module.db
admin = app_module.admin
from models import (User, BreachAnalysis, QuizResult, SecurityAnalysis, ActivityLog, 
                    SecurityLog, SiteSettings, RequestSubmission, QRCodeAnalysis, PromptAnalysis)

bp = Blueprint('admin_bp', __name__, url_prefix='/admin_bp')

class SecureModelView(ModelView):
    """Admin-only view"""
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_active and current_user.role == 'admin'
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('main.login'))

class ModeratorModelView(ModelView):
    """View accessible by moderators and admins"""
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_active and current_user.role in ['admin', 'moderator']
    
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('main.login'))

class BreachAnalysisView(SecureModelView):
    column_list = ['id', 'document_code', 'email', 'breach_count', 'risk_level', 'ip_address', 'created_at', 'pdf_download']
    column_searchable_list = ['email', 'ip_address', 'document_code']
    column_filters = ['risk_level', 'breach_count', 'created_at']
    column_sortable_list = ['id', 'document_code', 'email', 'breach_count', 'risk_level', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'document_code': 'Code document',
        'email': 'Email',
        'breach_count': 'Nb. de fuites',
        'risk_level': 'Niveau de risque',
        'breaches_found': 'Fuites trouvées',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'created_at': 'Date de recherche',
        'pdf_download': 'Rapport PDF'
    }
    
    def _pdf_formatter(view, context, model, name):
        if model.id:
            return Markup(f'<a href="/generate-breach-pdf/{model.id}" class="btn btn-sm btn-primary" target="_blank">📄 Télécharger PDF</a>')
        return ''
    
    column_formatters = {
        'pdf_download': _pdf_formatter
    }

class QuizResultView(SecureModelView):
    column_list = ['id', 'document_code', 'email', 'overall_score', 'created_at', 'ip_address']
    column_searchable_list = ['email', 'ip_address', 'document_code']
    column_filters = ['overall_score', 'created_at']
    column_sortable_list = ['id', 'document_code', 'email', 'overall_score', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'document_code': 'Code document',
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
    column_list = ['id', 'document_code', 'input_type', 'input_value', 'threat_detected', 'threat_level', 'malicious_count', 'total_engines', 'created_at', 'pdf_download']
    column_searchable_list = ['input_value', 'ip_address', 'document_code']
    column_filters = ['input_type', 'threat_detected', 'threat_level', 'created_at']
    column_sortable_list = ['id', 'document_code', 'input_type', 'threat_detected', 'threat_level', 'malicious_count', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'document_code': 'Code document',
        'input_value': 'Valeur analysée',
        'input_type': 'Type',
        'analysis_results': 'Résultats',
        'threat_detected': 'Menace détectée',
        'threat_level': 'Niveau de menace',
        'malicious_count': 'Détections malveillantes',
        'total_engines': 'Total moteurs',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'created_at': 'Date d\'analyse',
        'pdf_download': 'Rapport PDF'
    }
    
    def _pdf_formatter(view, context, model, name):
        if model.id:
            return Markup(f'<a href="/generate-security-pdf/{model.id}" class="btn btn-sm btn-primary" target="_blank">📄 Télécharger PDF</a>')
        return ''
    
    column_formatters = {
        'pdf_download': _pdf_formatter
    }

class RequestSubmissionView(SecureModelView):
    column_list = ['id', 'request_type', 'is_anonymous', 'contact_email', 'threat_detected', 'status', 'created_at']
    column_searchable_list = ['contact_email', 'contact_name', 'description', 'ip_address']
    column_filters = ['request_type', 'is_anonymous', 'threat_detected', 'status', 'created_at']
    column_sortable_list = ['id', 'request_type', 'threat_detected', 'status', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    column_editable_list = ['status', 'admin_notes']
    form_columns = ['request_type', 'description', 'urls', 'file_name', 'is_anonymous', 'contact_name', 'contact_email', 'contact_phone', 'threat_detected', 'status', 'admin_notes', 'vt_file_results', 'vt_url_results', 'vt_text_results']
    column_labels = {
        'id': 'ID',
        'request_type': 'Type de demande',
        'description': 'Description',
        'urls': 'URLs',
        'file_name': 'Nom du fichier',
        'is_anonymous': 'Anonyme',
        'contact_name': 'Nom',
        'contact_email': 'Email',
        'contact_phone': 'Téléphone',
        'threat_detected': 'Menace détectée',
        'status': 'Statut',
        'admin_notes': 'Notes admin',
        'vt_file_results': 'Résultats VT fichier',
        'vt_url_results': 'Résultats VT URLs',
        'vt_text_results': 'Résultats VT texte',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'created_at': 'Date de demande',
        'updated_at': 'Mis à jour le'
    }

class UserManagementView(SecureModelView):
    """Enhanced user management with role controls"""
    column_list = ['id', 'username', 'email', 'role', 'is_active', 'created_at', 'last_login']
    column_searchable_list = ['username', 'email']
    column_filters = ['role', 'is_active', 'created_at']
    column_sortable_list = ['id', 'username', 'email', 'role', 'is_active', 'created_at', 'last_login']
    column_default_sort = ('created_at', True)
    
    form_columns = ['username', 'email', 'role', 'is_active', 'is_admin']
    
    column_labels = {
        'id': 'ID',
        'username': 'Nom d\'utilisateur',
        'email': 'Email',
        'role': 'Rôle',
        'is_admin': 'Admin (legacy)',
        'is_active': 'Actif',
        'created_at': 'Créé le',
        'last_login': 'Dernière connexion',
        'password_hash': 'Hash du mot de passe'
    }
    
    column_descriptions = {
        'role': 'admin = Administrateur complet, moderator = Modérateur, user = Utilisateur standard',
        'is_admin': 'Champ legacy - utiliser "role" à la place',
        'is_active': 'Utilisateur peut se connecter'
    }
    
    form_choices = {
        'role': [
            ('admin', 'Administrateur'),
            ('moderator', 'Modérateur'),
            ('user', 'Utilisateur')
        ]
    }
    
    column_exclude_list = ['password_hash']
    form_excluded_columns = ['password_hash', 'created_at', 'last_login', 'activity_logs', 'security_logs', 'settings_updates', 'seo_updates']
    
    def on_model_change(self, form, model, is_created):
        """Sync is_admin with role"""
        if model.role == 'admin':
            model.is_admin = True
        else:
            model.is_admin = False

class ActivityLogView(SecureModelView):
    column_list = ['id', 'action_type', 'action_detail', 'ip_address', 'success', 'created_at']
    column_searchable_list = ['action_type', 'action_detail', 'ip_address']
    column_filters = ['action_type', 'success', 'created_at']
    column_sortable_list = ['id', 'action_type', 'success', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'action_type': 'Type d\'action',
        'action_detail': 'Détail',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'success': 'Succès',
        'error_message': 'Message d\'erreur',
        'created_at': 'Date'
    }

class SecurityLogView(SecureModelView):
    column_list = ['id', 'event_type', 'severity', 'description', 'ip_address', 'blocked', 'created_at']
    column_searchable_list = ['event_type', 'description', 'ip_address']
    column_filters = ['event_type', 'severity', 'blocked', 'created_at']
    column_sortable_list = ['id', 'event_type', 'severity', 'blocked', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'event_type': 'Type d\'événement',
        'severity': 'Sévérité',
        'description': 'Description',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'blocked': 'Bloqué',
        'created_at': 'Date'
    }

class SiteSettingsView(SecureModelView):
    column_list = ['id', 'key', 'value', 'category', 'updated_at']
    column_searchable_list = ['key', 'value', 'category']
    column_filters = ['category', 'is_public']
    column_sortable_list = ['id', 'key', 'category', 'updated_at']
    column_default_sort = ('category', False)
    can_create = True
    can_edit = True
    can_delete = True
    column_labels = {
        'id': 'ID',
        'key': 'Clé',
        'value': 'Valeur',
        'value_type': 'Type',
        'description': 'Description',
        'category': 'Catégorie',
        'is_public': 'Public',
        'updated_at': 'Mis à jour le'
    }
    form_excluded_columns = ['updated_by', 'updater']

class QRCodeAnalysisView(SecureModelView):
    column_list = ['id', 'document_code', 'extracted_url', 'threat_detected', 'threat_level', 'redirect_count', 'created_at', 'pdf_download']
    column_searchable_list = ['extracted_url', 'final_url', 'ip_address', 'document_code']
    column_filters = ['threat_detected', 'threat_level', 'created_at']
    column_sortable_list = ['id', 'document_code', 'threat_detected', 'threat_level', 'redirect_count', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'document_code': 'Code document',
        'original_filename': 'Fichier original',
        'extracted_url': 'URL extraite',
        'final_url': 'URL finale',
        'redirect_count': 'Nb. redirections',
        'threat_detected': 'Menace detectee',
        'threat_level': 'Niveau de menace',
        'js_redirects_detected': 'Redirections JS',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'created_at': 'Date d\'analyse',
        'pdf_download': 'Rapport PDF'
    }
    
    def _pdf_formatter(view, context, model, name):
        if model.id:
            return Markup(f'<a href="/generate-qrcode-pdf/{model.id}" class="btn btn-sm btn-primary" target="_blank">Telecharger PDF</a>')
        return ''
    
    column_formatters = {
        'pdf_download': _pdf_formatter
    }

class PromptAnalysisView(SecureModelView):
    column_list = ['id', 'document_code', 'prompt_length', 'threat_detected', 'threat_level', 'injection_detected', 'code_detected', 'created_at', 'pdf_download']
    column_searchable_list = ['prompt_text', 'ip_address', 'document_code']
    column_filters = ['threat_detected', 'threat_level', 'injection_detected', 'code_detected', 'created_at']
    column_sortable_list = ['id', 'document_code', 'prompt_length', 'threat_detected', 'threat_level', 'created_at']
    column_default_sort = ('created_at', True)
    can_create = False
    can_edit = False
    column_labels = {
        'id': 'ID',
        'document_code': 'Code document',
        'prompt_length': 'Longueur',
        'threat_detected': 'Menace detectee',
        'threat_level': 'Niveau de menace',
        'injection_detected': 'Injection',
        'code_detected': 'Code detecte',
        'obfuscation_detected': 'Obfuscation',
        'ip_address': 'Adresse IP',
        'user_agent': 'Navigateur',
        'created_at': 'Date d\'analyse',
        'pdf_download': 'Rapport PDF'
    }
    
    def _pdf_formatter(view, context, model, name):
        if model.id:
            return Markup(f'<a href="/generate-prompt-pdf/{model.id}" class="btn btn-sm btn-primary" target="_blank">Telecharger PDF</a>')
        return ''
    
    column_formatters = {
        'pdf_download': _pdf_formatter
    }

admin.add_view(UserManagementView(User, db.session, name='Utilisateurs'))
admin.add_view(RequestSubmissionView(RequestSubmission, db.session, name='Demandes - Fact-checking & Consultation'))
admin.add_view(BreachAnalysisView(BreachAnalysis, db.session, name='Historique - Analyses de fuites'))
admin.add_view(QuizResultView(QuizResult, db.session, name='Historique - Resultats de quiz'))
admin.add_view(SecurityAnalysisView(SecurityAnalysis, db.session, name='Historique - Analyses de securite'))
admin.add_view(QRCodeAnalysisView(QRCodeAnalysis, db.session, name='Historique - Analyses QR Code'))
admin.add_view(PromptAnalysisView(PromptAnalysis, db.session, name='Historique - Analyses Prompt'))
admin.add_view(ActivityLogView(ActivityLog, db.session, name='Historique - Logs d\'activité'))
admin.add_view(SecurityLogView(SecurityLog, db.session, name='Historique - Logs de sécurité'))
admin.add_view(SiteSettingsView(SiteSettings, db.session, name='Paramètres site'))
