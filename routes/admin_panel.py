from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from functools import wraps
from models import (db, User, ActivityLog, SecurityLog, QuizResult, SecurityAnalysis, 
                    BreachAnalysis, Rule, Scenario, Tool, GlossaryTerm, SiteSettings, SEOMetadata,
                    News, Newsletter, Contact)
from utils.logging_utils import log_activity
from datetime import datetime, timedelta
from sqlalchemy import func, desc

bp = Blueprint('admin_panel', __name__, url_prefix='/my4dm1n')

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not (current_user.is_active and current_user.role == 'admin'):
            flash('Accès refusé. Vous devez être administrateur actif.', 'danger')
            return redirect(url_for('main.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def moderator_required(f):
    """Decorator for routes accessible by moderators and admins"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not (current_user.is_active and current_user.role in ['admin', 'moderator']):
            flash('Accès refusé. Rôle modérateur ou administrateur requis.', 'danger')
            return redirect(url_for('main.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/')
@admin_required
def index():
    """Redirection automatique vers le dashboard"""
    return redirect(url_for('admin_panel.dashboard'))

@bp.route('/dashboard')
@admin_required
def dashboard():
    """Dashboard principal avec statistiques"""
    log_activity('ADMIN_DASHBOARD_VIEW', 'Consultation du dashboard admin')
    
    period = request.args.get('period', 'week')
    
    now = datetime.utcnow()
    if period == 'day':
        start_date = now - timedelta(days=1)
        period_label = "Aujourd'hui"
    elif period == 'week':
        start_date = now - timedelta(days=7)
        period_label = "Cette semaine"
    elif period == 'month':
        start_date = now - timedelta(days=30)
        period_label = "Ce mois"
    elif period == 'year':
        start_date = now - timedelta(days=365)
        period_label = "Cette année"
    else:
        start_date = now - timedelta(days=7)
        period_label = "Cette semaine"
    
    total_users = User.query.count()
    new_users_period = User.query.filter(User.created_at >= start_date).count()
    
    total_visits = ActivityLog.query.count()
    visits_period = ActivityLog.query.filter(ActivityLog.created_at >= start_date).count()
    
    unique_ips = db.session.query(func.count(func.distinct(ActivityLog.ip_address))).filter(
        ActivityLog.created_at >= start_date
    ).scalar() or 0
    
    pages_visited = db.session.query(
        ActivityLog.action_type, 
        func.count(ActivityLog.id).label('count')
    ).filter(
        ActivityLog.created_at >= start_date
    ).group_by(ActivityLog.action_type).order_by(desc('count')).limit(10).all()
    
    total_quiz_results = QuizResult.query.count()
    quiz_period = QuizResult.query.filter(QuizResult.created_at >= start_date).count()
    avg_quiz_score = db.session.query(func.avg(QuizResult.overall_score)).filter(
        QuizResult.created_at >= start_date
    ).scalar() or 0
    
    total_security_analyses = SecurityAnalysis.query.count()
    security_period = SecurityAnalysis.query.filter(SecurityAnalysis.created_at >= start_date).count()
    threats_detected = SecurityAnalysis.query.filter(
        SecurityAnalysis.created_at >= start_date,
        SecurityAnalysis.threat_detected == True
    ).count()
    
    total_breach_analyses = BreachAnalysis.query.count()
    breach_period = BreachAnalysis.query.filter(BreachAnalysis.created_at >= start_date).count()
    high_risk_breaches = BreachAnalysis.query.filter(
        BreachAnalysis.created_at >= start_date,
        BreachAnalysis.risk_level.in_(['critique', 'élevé'])
    ).count()
    
    recent_activities = ActivityLog.query.order_by(desc(ActivityLog.created_at)).limit(10).all()
    recent_security_logs = SecurityLog.query.order_by(desc(SecurityLog.created_at)).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         period=period,
                         period_label=period_label,
                         total_users=total_users,
                         new_users_period=new_users_period,
                         total_visits=total_visits,
                         visits_period=visits_period,
                         unique_visitors=unique_ips,
                         unique_ips=unique_ips,
                         pages_visited=pages_visited,
                         total_quiz_results=total_quiz_results,
                         quiz_period=quiz_period,
                         avg_quiz_score=round(avg_quiz_score, 1),
                         total_security_analyses=total_security_analyses,
                         security_period=security_period,
                         threats_detected=threats_detected,
                         total_breach_analyses=total_breach_analyses,
                         breach_period=breach_period,
                         high_risk_breaches=high_risk_breaches,
                         recent_activities=recent_activities,
                         recent_security_logs=recent_security_logs)

@bp.route('/content')
@moderator_required
def content_management():
    """Gestion du contenu frontend - accessible aux modérateurs"""
    log_activity('ADMIN_CONTENT_VIEW', 'Consultation gestion contenu')
    
    rules_count = Rule.query.count()
    scenarios_count = Scenario.query.count()
    tools_count = Tool.query.count()
    glossary_count = GlossaryTerm.query.count()
    
    return render_template('admin/content.html',
                         rules_count=rules_count,
                         scenarios_count=scenarios_count,
                         tools_count=tools_count,
                         glossary_count=glossary_count)

@bp.route('/history/quiz')
@admin_required
def quiz_history():
    """Historique des quiz"""
    log_activity('ADMIN_QUIZ_HISTORY_VIEW', 'Consultation historique quiz')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    search = request.args.get('search', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = QuizResult.query
    
    if search:
        query = query.filter(QuizResult.email.contains(search))
    
    if date_from:
        query = query.filter(QuizResult.created_at >= datetime.fromisoformat(date_from))
    
    if date_to:
        query = query.filter(QuizResult.created_at <= datetime.fromisoformat(date_to))
    
    results = query.order_by(desc(QuizResult.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/quiz_history.html', results=results, search=search, date_from=date_from, date_to=date_to)

@bp.route('/history/security')
@admin_required
def security_history():
    """Historique des analyses de sécurité"""
    log_activity('ADMIN_SECURITY_HISTORY_VIEW', 'Consultation historique analyses sécurité')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    search = request.args.get('search', '')
    input_type = request.args.get('type', '')
    threat_only = request.args.get('threat_only', '')
    
    query = SecurityAnalysis.query
    
    if search:
        query = query.filter(SecurityAnalysis.input_value.contains(search))
    
    if input_type:
        query = query.filter(SecurityAnalysis.input_type == input_type)
    
    if threat_only == 'true':
        query = query.filter(SecurityAnalysis.threat_detected == True)
    
    results = query.order_by(desc(SecurityAnalysis.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/security_history.html', results=results, search=search, input_type=input_type, threat_only=threat_only)

@bp.route('/history/breach')
@admin_required
def breach_history():
    """Historique des analyses de fuites"""
    log_activity('ADMIN_BREACH_HISTORY_VIEW', 'Consultation historique analyses fuites')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    search = request.args.get('search', '')
    risk_level = request.args.get('risk_level', '')
    
    query = BreachAnalysis.query
    
    if search:
        query = query.filter(BreachAnalysis.email.contains(search))
    
    if risk_level:
        query = query.filter(BreachAnalysis.risk_level == risk_level)
    
    results = query.order_by(desc(BreachAnalysis.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/breach_history.html', results=results, search=search, risk_level=risk_level)

@bp.route('/history/quiz/<int:quiz_id>')
@admin_required
def quiz_detail(quiz_id):
    """Détails d'un résultat de quiz"""
    quiz = QuizResult.query.get_or_404(quiz_id)
    log_activity('ADMIN_QUIZ_DETAIL_VIEW', f'Consultation détails quiz #{quiz_id}')
    return render_template('admin/quiz_detail.html', quiz=quiz)

@bp.route('/history/security/<int:analysis_id>')
@admin_required
def security_detail(analysis_id):
    """Détails d'une analyse de sécurité"""
    analysis = SecurityAnalysis.query.get_or_404(analysis_id)
    log_activity('ADMIN_SECURITY_DETAIL_VIEW', f'Consultation détails analyse sécurité #{analysis_id}')
    return render_template('admin/security_detail.html', analysis=analysis)

@bp.route('/history/breach/<int:breach_id>')
@admin_required
def breach_detail(breach_id):
    """Détails d'une analyse de fuite"""
    breach = BreachAnalysis.query.get_or_404(breach_id)
    log_activity('ADMIN_BREACH_DETAIL_VIEW', f'Consultation détails analyse fuite #{breach_id}')
    return render_template('admin/breach_detail.html', breach=breach)

@bp.route('/logs/activity')
@admin_required
def activity_logs():
    """Logs d'activité"""
    log_activity('ADMIN_ACTIVITY_LOGS_VIEW', 'Consultation logs activité')
    
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    action_type = request.args.get('action_type', '')
    user_id = request.args.get('user_id', '')
    success_only = request.args.get('success', '')
    
    query = ActivityLog.query
    
    if action_type:
        query = query.filter(ActivityLog.action_type.contains(action_type))
    
    if user_id:
        query = query.filter(ActivityLog.user_id == int(user_id))
    
    if success_only == 'true':
        query = query.filter(ActivityLog.success == True)
    elif success_only == 'false':
        query = query.filter(ActivityLog.success == False)
    
    logs = query.order_by(desc(ActivityLog.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/activity_logs.html', logs=logs, action_type=action_type, user_id=user_id, success_only=success_only)

@bp.route('/logs/security')
@admin_required
def security_logs():
    """Logs de sécurité"""
    log_activity('ADMIN_SECURITY_LOGS_VIEW', 'Consultation logs sécurité')
    
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    event_type = request.args.get('event_type', '')
    severity = request.args.get('severity', '')
    blocked_only = request.args.get('blocked', '')
    
    query = SecurityLog.query
    
    if event_type:
        query = query.filter(SecurityLog.event_type.contains(event_type))
    
    if severity:
        query = query.filter(SecurityLog.severity == severity)
    
    if blocked_only == 'true':
        query = query.filter(SecurityLog.blocked == True)
    
    logs = query.order_by(desc(SecurityLog.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/security_logs.html', logs=logs, event_type=event_type, severity=severity, blocked_only=blocked_only)

@bp.route('/settings/site', methods=['GET', 'POST'])
@admin_required
def site_settings():
    """Paramètres du site"""
    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('setting_'):
                setting_key = key.replace('setting_', '')
                setting = SiteSettings.query.filter_by(key=setting_key).first()
                if setting:
                    setting.value = value
                    setting.updated_by = current_user.id
                else:
                    setting = SiteSettings()
                    setting.key = setting_key
                    setting.value = value
                    setting.updated_by = current_user.id
                    db.session.add(setting)
        
        db.session.commit()
        log_activity('ADMIN_SETTINGS_UPDATE', 'Mise à jour paramètres site', success=True)
        flash('Paramètres mis à jour avec succès', 'success')
        return redirect(url_for('admin_panel.site_settings'))
    
    settings = SiteSettings.query.all()
    log_activity('ADMIN_SETTINGS_VIEW', 'Consultation paramètres site')
    
    return render_template('admin/site_settings.html', settings=settings)

@bp.route('/settings/seo', methods=['GET', 'POST'])
@admin_required
def seo_settings():
    """Paramètres SEO"""
    if request.method == 'POST':
        page_path = request.form.get('page_path')
        seo = SEOMetadata.query.filter_by(page_path=page_path).first()
        
        if not seo:
            seo = SEOMetadata()
            seo.page_path = page_path
            db.session.add(seo)
        
        seo.title = request.form.get('title')
        seo.description = request.form.get('description')
        seo.keywords = request.form.get('keywords')
        seo.og_title = request.form.get('og_title')
        seo.og_description = request.form.get('og_description')
        seo.og_image = request.form.get('og_image')
        seo.canonical_url = request.form.get('canonical_url')
        seo.robots = request.form.get('robots')
        seo.is_active = request.form.get('is_active') == 'on'
        seo.updated_by = current_user.id
        
        db.session.commit()
        log_activity('ADMIN_SEO_UPDATE', f'Mise à jour SEO pour {page_path}', success=True)
        flash(f'Paramètres SEO pour {page_path} mis à jour', 'success')
        return redirect(url_for('admin_panel.seo_settings'))
    
    seo_pages = SEOMetadata.query.all()
    log_activity('ADMIN_SEO_VIEW', 'Consultation paramètres SEO')
    
    return render_template('admin/seo_settings.html', seo_pages=seo_pages)

@bp.route('/blog')
@moderator_required
def blog_management():
    """Gestion des articles de blog"""
    log_activity('ADMIN_BLOG_VIEW', 'Consultation gestion blog')
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    category = request.args.get('category', '')
    source = request.args.get('source', '')
    
    query = News.query
    
    if category:
        query = query.filter(News.category == category)
    
    if source:
        query = query.filter(News.source == source)
    
    articles = query.order_by(desc(News.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    categories = db.session.query(News.category).distinct().all()
    categories = [cat[0] for cat in categories if cat[0]]
    sources = db.session.query(News.source).distinct().all()
    sources = [src[0] for src in sources if src[0]]
    
    return render_template('admin/blog.html', articles=articles, categories=categories, sources=sources, selected_category=category, selected_source=source)

@bp.route('/newsletter')
@moderator_required
def newsletter_management():
    """Liste des inscriptions newsletter"""
    log_activity('ADMIN_NEWSLETTER_VIEW', 'Consultation inscriptions newsletter')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    subscribed_only = request.args.get('subscribed', 'true')
    
    query = Newsletter.query
    
    if subscribed_only == 'true':
        query = query.filter(Newsletter.subscribed == True)
    
    subscriptions = query.order_by(desc(Newsletter.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    total_subscribed = Newsletter.query.filter(Newsletter.subscribed == True).count()
    
    return render_template('admin/newsletter.html', subscriptions=subscriptions, total_subscribed=total_subscribed, subscribed_only=subscribed_only)

@bp.route('/contacts')
@moderator_required
def contact_management():
    """Liste des messages de contact"""
    log_activity('ADMIN_CONTACTS_VIEW', 'Consultation messages contact')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    status = request.args.get('status', '')
    
    query = Contact.query
    
    if status:
        query = query.filter(Contact.status == status)
    
    contacts = query.order_by(desc(Contact.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/contacts.html', contacts=contacts, status=status)

@bp.route('/contacts/send', methods=['POST'])
@moderator_required
def send_contact_message():
    """Envoyer un message aux contacts sélectionnés"""
    recipients = request.form.get('recipients', '')
    subject = request.form.get('subject', '')
    message = request.form.get('message', '')
    
    if not recipients or not subject or not message:
        flash('Tous les champs sont requis', 'danger')
        return redirect(url_for('admin_panel.contact_management'))
    
    log_activity('ADMIN_CONTACT_MESSAGE_SEND', f'Envoi message à {recipients}', success=True)
    flash(f'Message envoyé à {recipients} (fonctionnalité de démonstration - implémentez l\'envoi d\'emails réel)', 'success')
    
    return redirect(url_for('admin_panel.contact_management'))

@bp.route('/content/edit/<page>', methods=['GET', 'POST'])
@moderator_required
def edit_page_content(page):
    """Édition du contenu d'une page"""
    page_names = {
        'home': 'Page d\'accueil',
        'about': 'À propos',
        'services': 'Services',
        'contact': 'Contact'
    }
    
    if page not in page_names:
        flash('Page non trouvée', 'danger')
        return redirect(url_for('admin_panel.content_management'))
    
    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('setting_'):
                setting_key = key.replace('setting_', '')
                setting = SiteSettings.query.filter_by(key=setting_key, category=page).first()
                if setting:
                    setting.value = value
                    setting.updated_by = current_user.id
                else:
                    setting = SiteSettings()
                    setting.key = setting_key
                    setting.value = value
                    setting.category = page
                    setting.updated_by = current_user.id
                    db.session.add(setting)
        
        db.session.commit()
        log_activity('ADMIN_PAGE_CONTENT_UPDATE', f'Mise à jour contenu page {page}', success=True)
        flash(f'Contenu de la page {page_names[page]} mis à jour avec succès', 'success')
        return redirect(url_for('admin_panel.edit_page_content', page=page))
    
    settings = SiteSettings.query.filter_by(category=page).all()
    log_activity('ADMIN_PAGE_CONTENT_VIEW', f'Consultation contenu page {page}')
    
    return render_template('admin/edit_page_content.html', 
                         page=page, 
                         page_name=page_names[page], 
                         settings=settings)

@bp.route('/api/stats')
@admin_required
def api_stats():
    """API pour les statistiques en temps réel"""
    days = request.args.get('days', 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    quiz_stats = db.session.query(
        func.date(QuizResult.created_at).label('date'),
        func.count(QuizResult.id).label('count')
    ).filter(QuizResult.created_at >= start_date).group_by(func.date(QuizResult.created_at)).all()
    
    security_stats = db.session.query(
        func.date(SecurityAnalysis.created_at).label('date'),
        func.count(SecurityAnalysis.id).label('count')
    ).filter(SecurityAnalysis.created_at >= start_date).group_by(func.date(SecurityAnalysis.created_at)).all()
    
    return jsonify({
        'quiz_stats': [{'date': str(s.date), 'count': s.count} for s in quiz_stats],
        'security_stats': [{'date': str(s.date), 'count': s.count} for s in security_stats]
    })
