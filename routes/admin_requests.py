"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Routes de gestion des demandes utilisateurs (admin).
"""

from flask import Blueprint, render_template, request, send_file, abort
from models import RequestSubmission, db
from routes.admin_panel import admin_required
from sqlalchemy import desc
import os

bp = Blueprint('admin_requests', __name__, url_prefix='/my4dm1n/requests')

@bp.route('/')
@admin_required
def requests_dashboard():
    """View all request submissions"""
    page = request.args.get('page', 1, type=int)
    filter_type = request.args.get('type', 'all')
    
    query = RequestSubmission.query
    
    if filter_type != 'all':
        if filter_type == 'osint':
            query = query.filter(RequestSubmission.request_type.in_(['osint', 'osint-investigation']))
        else:
            query = query.filter_by(request_type=filter_type)
    
    submissions = query.order_by(desc(RequestSubmission.created_at)).paginate(
        page=page, per_page=20, error_out=False
    )
    
    stats = {
        'total': RequestSubmission.query.count(),
        'fact_checking': RequestSubmission.query.filter_by(request_type='fact-checking').count(),
        'osint': RequestSubmission.query.filter(RequestSubmission.request_type.in_(['osint', 'osint-investigation'])).count(),
        'cyberconsultation': RequestSubmission.query.filter_by(request_type='cyberconsultation').count(),
        'cybercrime': RequestSubmission.query.filter_by(request_type='cybercrime-report').count(),
        'threats_detected': RequestSubmission.query.filter_by(threat_detected=True).count(),
        'pending': RequestSubmission.query.filter_by(status='pending').count(),
    }
    
    return render_template('admin/requests_dashboard.html', 
                         submissions=submissions,
                         stats=stats,
                         filter_type=filter_type)

@bp.route('/<int:submission_id>')
@admin_required
def request_detail(submission_id):
    """View detailed information about a submission"""
    submission = RequestSubmission.query.get_or_404(submission_id)
    return render_template('admin/request_detail.html', submission=submission)

@bp.route('/<int:submission_id>/update-status', methods=['POST'])
@admin_required
def update_status(submission_id):
    """Update submission status"""
    submission = RequestSubmission.query.get_or_404(submission_id)
    submission.status = request.form.get('status', 'pending')
    submission.admin_notes = request.form.get('admin_notes', '')
    db.session.commit()
    
    from flask import flash, redirect, url_for
    flash('Submission status updated', 'success')
    return redirect(url_for('admin_requests.request_detail', submission_id=submission_id))

@bp.route('/<int:submission_id>/download-file')
@admin_required
def download_file(submission_id):
    """Download the attached file for a submission"""
    submission = RequestSubmission.query.get_or_404(submission_id)
    
    if not submission.file_path or not os.path.exists(submission.file_path):
        abort(404, "Fichier non trouvé")
    
    return send_file(
        submission.file_path,
        as_attachment=True,
        download_name=submission.file_name or 'fichier_joint'
    )
