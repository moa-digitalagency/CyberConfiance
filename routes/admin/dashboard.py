"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Dashboard admin avec statistiques et visualisations.
"""

from flask import render_template, request, redirect, url_for, flash, jsonify
from models import (db, User, ActivityLog, SecurityLog, QuizResult, SecurityAnalysis, BreachAnalysis)
from utils.logging_utils import log_activity
from datetime import datetime, timedelta
from sqlalchemy import func, desc
from routes.admin import bp, admin_required

@bp.route('/dashboard')
@admin_required
def dashboard():
    """Dashboard principal avec statistiques"""
    try:
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
        
        try:
            total_users = User.query.count()
            new_users_period = User.query.filter(User.created_at >= start_date).count()
        except Exception as e:
            print(f"[ERROR] Users query failed: {e}")
            total_users = 0
            new_users_period = 0
        
        try:
            total_visits = ActivityLog.query.count()
            visits_period = ActivityLog.query.filter(ActivityLog.created_at >= start_date).count()
        except Exception as e:
            print(f"[ERROR] ActivityLog query failed: {e}")
            total_visits = 0
            visits_period = 0
        
        try:
            unique_ips = db.session.query(func.count(func.distinct(ActivityLog.ip_address))).filter(
                ActivityLog.created_at >= start_date
            ).scalar() or 0
        except Exception as e:
            print(f"[ERROR] Unique IPs query failed: {e}")
            unique_ips = 0
        
        try:
            pages_visited = db.session.query(
                ActivityLog.action_type, 
                func.count(ActivityLog.id).label('count')
            ).filter(
                ActivityLog.created_at >= start_date
            ).group_by(ActivityLog.action_type).order_by(desc('count')).limit(10).all()
        except Exception as e:
            print(f"[ERROR] Pages visited query failed: {e}")
            pages_visited = []
        
        try:
            total_quiz_results = QuizResult.query.count()
            quiz_period = QuizResult.query.filter(QuizResult.created_at >= start_date).count()
            avg_quiz_score = db.session.query(func.avg(QuizResult.overall_score)).filter(
                QuizResult.created_at >= start_date
            ).scalar() or 0
        except Exception as e:
            print(f"[ERROR] Quiz query failed: {e}")
            total_quiz_results = 0
            quiz_period = 0
            avg_quiz_score = 0
        
        try:
            total_security_analyses = SecurityAnalysis.query.count()
            security_period = SecurityAnalysis.query.filter(SecurityAnalysis.created_at >= start_date).count()
            threats_detected = SecurityAnalysis.query.filter(
                SecurityAnalysis.created_at >= start_date,
                SecurityAnalysis.threat_detected == True
            ).count()
        except Exception as e:
            print(f"[ERROR] SecurityAnalysis query failed: {e}")
            total_security_analyses = 0
            security_period = 0
            threats_detected = 0
        
        try:
            total_breach_analyses = BreachAnalysis.query.count()
            breach_period = BreachAnalysis.query.filter(BreachAnalysis.created_at >= start_date).count()
            high_risk_breaches = BreachAnalysis.query.filter(
                BreachAnalysis.created_at >= start_date,
                BreachAnalysis.risk_level.in_(['critique', 'élevé'])
            ).count()
        except Exception as e:
            print(f"[ERROR] BreachAnalysis query failed: {e}")
            total_breach_analyses = 0
            breach_period = 0
            high_risk_breaches = 0
        
        try:
            recent_activities = ActivityLog.query.order_by(desc(ActivityLog.created_at)).limit(10).all()
        except Exception as e:
            print(f"[ERROR] Recent activities query failed: {e}")
            recent_activities = []
        
        try:
            recent_security_logs = SecurityLog.query.order_by(desc(SecurityLog.created_at)).limit(10).all()
        except Exception as e:
            print(f"[ERROR] Recent security logs query failed: {e}")
            db.session.rollback()
            recent_security_logs = []
        
        db.session.rollback()
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
                             avg_quiz_score=round(avg_quiz_score, 1) if avg_quiz_score else 0,
                             total_security_analyses=total_security_analyses,
                             security_period=security_period,
                             threats_detected=threats_detected,
                             total_breach_analyses=total_breach_analyses,
                             breach_period=breach_period,
                             high_risk_breaches=high_risk_breaches,
                             recent_activities=recent_activities,
                             recent_security_logs=recent_security_logs)
    except Exception as e:
        print(f"[ERROR] Dashboard error: {e}")
        import traceback
        traceback.print_exc()
        flash(f'Erreur lors du chargement du dashboard: {str(e)}', 'danger')
        return redirect(url_for('main.index'))

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
