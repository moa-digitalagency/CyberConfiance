"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Historique des analyses et logs admin.
"""

from flask import render_template, request, redirect, url_for, flash
from models import (db, ActivityLog, SecurityLog, QuizResult, SecurityAnalysis, 
                    BreachAnalysis, QRCodeAnalysis, PromptAnalysis)
from utils.logging_utils import log_activity
from datetime import datetime
from sqlalchemy import func, desc
from routes.admin import bp, admin_required

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
    
    average_score = db.session.query(func.avg(QuizResult.overall_score)).scalar() or 0
    
    return render_template('admin/quiz_history.html', results=results, search=search, date_from=date_from, date_to=date_to, average_score=average_score)

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
    
    threat_count = SecurityAnalysis.query.filter(SecurityAnalysis.threat_detected == True).count()
    
    return render_template('admin/security_history.html', results=results, search=search, input_type=input_type, threat_only=threat_only, threat_count=threat_count)

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
    
    total_breaches = db.session.query(func.sum(BreachAnalysis.breach_count)).scalar() or 0
    
    return render_template('admin/breach_history.html', results=results, search=search, risk_level=risk_level, total_breaches=total_breaches)

@bp.route('/history/breach/<int:breach_id>/delete', methods=['POST'])
@admin_required
def delete_breach_result(breach_id):
    """Supprimer un résultat d'analyse de fuite"""
    breach = BreachAnalysis.query.get_or_404(breach_id)
    try:
        db.session.delete(breach)
        db.session.commit()
        log_activity('ADMIN_BREACH_DELETE', f'Suppression analyse fuite #{breach_id}')
        flash('Résultat d\'analyse de fuite supprimé avec succès.', 'success')
    except Exception as e:
        db.session.rollback()
        log_activity('ADMIN_BREACH_DELETE_ERROR', f'Erreur suppression analyse fuite #{breach_id}: {str(e)}')
        flash(f'Erreur lors de la suppression: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel.breach_history'))

@bp.route('/history/quiz/<int:quiz_id>')
@admin_required
def quiz_detail(quiz_id):
    """Détails d'un résultat de quiz"""
    quiz = QuizResult.query.get_or_404(quiz_id)
    log_activity('ADMIN_QUIZ_DETAIL_VIEW', f'Consultation détails quiz #{quiz_id}')
    return render_template('admin/quiz_detail.html', quiz=quiz)

@bp.route('/history/quiz/<int:quiz_id>/delete', methods=['POST'])
@admin_required
def delete_quiz_result(quiz_id):
    """Supprimer un résultat de quiz"""
    quiz = QuizResult.query.get_or_404(quiz_id)
    try:
        db.session.delete(quiz)
        db.session.commit()
        log_activity('ADMIN_QUIZ_DELETE', f'Suppression quiz #{quiz_id}')
        flash('Résultat de quiz supprimé avec succès.', 'success')
    except Exception as e:
        db.session.rollback()
        log_activity('ADMIN_QUIZ_DELETE_ERROR', f'Erreur suppression quiz #{quiz_id}: {str(e)}')
        flash(f'Erreur lors de la suppression: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel.quiz_history'))

@bp.route('/history/security/<int:analysis_id>')
@admin_required
def security_detail(analysis_id):
    """Détails d'une analyse de sécurité"""
    analysis = SecurityAnalysis.query.get_or_404(analysis_id)
    log_activity('ADMIN_SECURITY_DETAIL_VIEW', f'Consultation détails analyse sécurité #{analysis_id}')
    return render_template('admin/security_detail.html', analysis=analysis)

@bp.route('/history/security/<int:analysis_id>/delete', methods=['POST'])
@admin_required
def delete_security_result(analysis_id):
    """Supprimer un résultat d'analyse de sécurité"""
    analysis = SecurityAnalysis.query.get_or_404(analysis_id)
    try:
        db.session.delete(analysis)
        db.session.commit()
        log_activity('ADMIN_SECURITY_DELETE', f'Suppression analyse sécurité #{analysis_id}')
        flash('Résultat d\'analyse de sécurité supprimé avec succès.', 'success')
    except Exception as e:
        db.session.rollback()
        log_activity('ADMIN_SECURITY_DELETE_ERROR', f'Erreur suppression analyse sécurité #{analysis_id}: {str(e)}')
        flash(f'Erreur lors de la suppression: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel.security_history'))

@bp.route('/history/breach/<int:breach_id>')
@admin_required
def breach_detail(breach_id):
    """Détails d'une analyse de fuite"""
    breach = BreachAnalysis.query.get_or_404(breach_id)
    log_activity('ADMIN_BREACH_DETAIL_VIEW', f'Consultation détails analyse fuite #{breach_id}')
    return render_template('admin/breach_detail.html', breach=breach)

@bp.route('/history/qrcode')
@admin_required
def qrcode_history():
    """Historique des analyses QR Code"""
    log_activity('ADMIN_QRCODE_HISTORY_VIEW', 'Consultation historique analyses QR Code')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    search = request.args.get('search', '')
    threat_level = request.args.get('threat_level', '')
    threat_only = request.args.get('threat_only', '')
    
    query = QRCodeAnalysis.query
    
    if search:
        query = query.filter(
            (QRCodeAnalysis.extracted_url.contains(search)) |
            (QRCodeAnalysis.original_filename.contains(search))
        )
    
    if threat_level:
        query = query.filter(QRCodeAnalysis.threat_level == threat_level)
    
    if threat_only == 'true':
        query = query.filter(QRCodeAnalysis.threat_detected == True)
    
    results = query.order_by(desc(QRCodeAnalysis.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    threat_count = QRCodeAnalysis.query.filter(QRCodeAnalysis.threat_detected == True).count()
    total_count = QRCodeAnalysis.query.count()
    
    return render_template('admin/qrcode_history.html', 
                         results=results, 
                         search=search, 
                         threat_level=threat_level, 
                         threat_only=threat_only, 
                         threat_count=threat_count,
                         total_count=total_count)

@bp.route('/history/qrcode/<int:analysis_id>')
@admin_required
def qrcode_detail(analysis_id):
    """Details d'une analyse QR Code"""
    analysis = QRCodeAnalysis.query.get_or_404(analysis_id)
    log_activity('ADMIN_QRCODE_DETAIL_VIEW', f'Consultation details analyse QR Code #{analysis_id}')
    return render_template('admin/qrcode_detail.html', analysis=analysis)

@bp.route('/history/qrcode/<int:analysis_id>/delete', methods=['POST'])
@admin_required
def delete_qrcode_result(analysis_id):
    """Supprimer un resultat d'analyse QR Code"""
    analysis = QRCodeAnalysis.query.get_or_404(analysis_id)
    try:
        db.session.delete(analysis)
        db.session.commit()
        log_activity('ADMIN_QRCODE_DELETE', f'Suppression analyse QR Code #{analysis_id}')
        flash('Resultat d\'analyse QR Code supprime avec succes.', 'success')
    except Exception as e:
        db.session.rollback()
        log_activity('ADMIN_QRCODE_DELETE_ERROR', f'Erreur suppression analyse QR Code #{analysis_id}: {str(e)}')
        flash(f'Erreur lors de la suppression: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel.qrcode_history'))

@bp.route('/history/prompt')
@admin_required
def prompt_history():
    """Historique des analyses de Prompt"""
    log_activity('ADMIN_PROMPT_HISTORY_VIEW', 'Consultation historique analyses Prompt')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    search = request.args.get('search', '')
    threat_level = request.args.get('threat_level', '')
    threat_only = request.args.get('threat_only', '')
    
    query = PromptAnalysis.query
    
    if search:
        query = query.filter(PromptAnalysis.prompt_text.contains(search))
    
    if threat_level:
        query = query.filter(PromptAnalysis.threat_level == threat_level)
    
    if threat_only == 'true':
        query = query.filter(PromptAnalysis.threat_detected == True)
    
    results = query.order_by(desc(PromptAnalysis.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    threat_count = PromptAnalysis.query.filter(PromptAnalysis.threat_detected == True).count()
    injection_count = PromptAnalysis.query.filter(PromptAnalysis.injection_detected == True).count()
    total_count = PromptAnalysis.query.count()
    
    return render_template('admin/prompt_history.html', 
                         results=results, 
                         search=search, 
                         threat_level=threat_level, 
                         threat_only=threat_only, 
                         threat_count=threat_count,
                         injection_count=injection_count,
                         total_count=total_count)

@bp.route('/history/prompt/<int:analysis_id>')
@admin_required
def prompt_detail(analysis_id):
    """Details d'une analyse de Prompt"""
    analysis = PromptAnalysis.query.get_or_404(analysis_id)
    log_activity('ADMIN_PROMPT_DETAIL_VIEW', f'Consultation details analyse Prompt #{analysis_id}')
    return render_template('admin/prompt_detail.html', analysis=analysis)

@bp.route('/history/prompt/<int:analysis_id>/delete', methods=['POST'])
@admin_required
def delete_prompt_result(analysis_id):
    """Supprimer un resultat d'analyse de Prompt"""
    analysis = PromptAnalysis.query.get_or_404(analysis_id)
    try:
        db.session.delete(analysis)
        db.session.commit()
        log_activity('ADMIN_PROMPT_DELETE', f'Suppression analyse Prompt #{analysis_id}')
        flash('Resultat d\'analyse de Prompt supprime avec succes.', 'success')
    except Exception as e:
        db.session.rollback()
        log_activity('ADMIN_PROMPT_DELETE_ERROR', f'Erreur suppression analyse Prompt #{analysis_id}: {str(e)}')
        flash(f'Erreur lors de la suppression: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel.prompt_history'))

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
