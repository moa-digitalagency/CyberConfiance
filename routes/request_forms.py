from flask import Blueprint, render_template, request, flash, redirect, url_for
from services.request_submission_service import RequestSubmissionService
from utils.logging_utils import log_activity

bp = Blueprint('request_forms', __name__)

@bp.route('/request/factchecking', methods=['GET', 'POST'])
def factchecking():
    """Fact-checking request form with VirusTotal security"""
    if request.method == 'POST':
        result = RequestSubmissionService.process_submission(
            request_type='fact-checking',
            form_data=request.form,
            files=request.files
        )
        
        if result['success']:
            log_activity('FACTCHECK_SUBMIT', 'Fact-checking request submitted', success=True)
            flash(result['message'], 'success')
            return redirect(url_for('request_forms.factchecking'))
        else:
            if result.get('threat_detected'):
                log_activity('FACTCHECK_THREAT', result['message'], success=False)
            flash(result['message'], 'danger')
    
    return render_template('services/factchecking_form.html')

@bp.route('/outils/methodologie-osint', methods=['GET', 'POST'])
def osint():
    """OSINT analysis request form with VirusTotal security"""
    if request.method == 'POST':
        result = RequestSubmissionService.process_submission(
            request_type='osint',
            form_data=request.form,
            files=request.files
        )
        
        if result['success']:
            log_activity('OSINT_SUBMIT', 'OSINT request submitted', success=True)
            flash(result['message'], 'success')
            return redirect(url_for('request_forms.osint'))
        else:
            if result.get('threat_detected'):
                log_activity('OSINT_THREAT', result['message'], success=False)
            flash(result['message'], 'danger')
    
    return render_template('outils/methodologie_osint.html')

@bp.route('/request/cyberconsultation', methods=['GET', 'POST'])
def cyberconsultation():
    """Cyberconsultation request form with VirusTotal security"""
    if request.method == 'POST':
        result = RequestSubmissionService.process_submission(
            request_type='cyberconsultation',
            form_data=request.form,
            files=request.files
        )
        
        if result['success']:
            log_activity('CONSULTATION_SUBMIT', 'Cyberconsultation request submitted', success=True)
            flash(result['message'], 'success')
            return redirect(url_for('request_forms.cyberconsultation'))
        else:
            if result.get('threat_detected'):
                log_activity('CONSULTATION_THREAT', result['message'], success=False)
            flash(result['message'], 'danger')
    
    return render_template('services/cyberconsultation_form.html')
