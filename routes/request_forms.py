from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from services.request_submission_service import RequestSubmissionService
from utils.logging_utils import log_activity
from utils.metadata_collector import collect_request_metadata, generate_incident_id
from datetime import datetime

bp = Blueprint('request_forms', __name__)

@bp.route('/request/factchecking', methods=['GET', 'POST'])
def factchecking():
    """Fact-checking request form with security analysis"""
    if request.method == 'POST':
        result = RequestSubmissionService.process_submission(
            request_type='fact-checking',
            form_data=request.form,
            files=request.files
        )
        
        if result['success']:
            log_activity('FACTCHECK_SUBMIT', 'Demande de vérification soumise', success=True)
            flash(result['message'], 'success')
            return redirect(url_for('request_forms.factchecking'))
        else:
            if result.get('threat_detected'):
                log_activity('FACTCHECK_THREAT', result['message'], success=False)
                # Store only incident ID in session, full data in database
                metadata = collect_request_metadata()
                incident_id = generate_incident_id()
                
                # Store threat details in database for security and audit
                from models import db, ThreatLog
                threat_log = ThreatLog(
                    incident_id=incident_id,
                    threat_type=result.get('threat_type', 'unknown'),
                    threat_details=result.get('message'),
                    ip_address=metadata['ip_address'],
                    user_agent=metadata['user_agent'],
                    platform=metadata['platform'],
                    device_type=metadata['device_type'],
                    vpn_detected=metadata['vpn_detected'],
                    metadata_json=metadata
                )
                db.session.add(threat_log)
                db.session.commit()
                
                # Store incident ID in session AND pass as query parameter for reliability
                # This ensures the alert works even if cookies are blocked or not yet established
                session['threat_incident_id'] = incident_id
                return redirect(url_for('request_forms.security_threat', incident_id=incident_id))
            flash(result['message'], 'danger')
    
    return render_template('services/factchecking_form.html')

@bp.route('/outils/methodologie-osint', methods=['GET', 'POST'])
def osint():
    """OSINT analysis request form with security analysis"""
    if request.method == 'POST':
        result = RequestSubmissionService.process_submission(
            request_type='osint',
            form_data=request.form,
            files=request.files
        )
        
        if result['success']:
            log_activity('OSINT_SUBMIT', 'Demande OSINT soumise', success=True)
            flash(result['message'], 'success')
            return redirect(url_for('request_forms.osint'))
        else:
            if result.get('threat_detected'):
                log_activity('OSINT_THREAT', result['message'], success=False)
                # Store only incident ID in session, full data in database
                metadata = collect_request_metadata()
                incident_id = generate_incident_id()
                
                # Store threat details in database for security and audit
                from models import db, ThreatLog
                threat_log = ThreatLog(
                    incident_id=incident_id,
                    threat_type=result.get('threat_type', 'unknown'),
                    threat_details=result.get('message'),
                    ip_address=metadata['ip_address'],
                    user_agent=metadata['user_agent'],
                    platform=metadata['platform'],
                    device_type=metadata['device_type'],
                    vpn_detected=metadata['vpn_detected'],
                    metadata_json=metadata
                )
                db.session.add(threat_log)
                db.session.commit()
                
                # Store incident ID in session AND pass as query parameter for reliability
                # This ensures the alert works even if cookies are blocked or not yet established
                session['threat_incident_id'] = incident_id
                return redirect(url_for('request_forms.security_threat', incident_id=incident_id))
            flash(result['message'], 'danger')
    
    return render_template('outils/methodologie_osint.html')

@bp.route('/request/cyberconsultation', methods=['GET', 'POST'])
def cyberconsultation():
    """Cyberconsultation request form with security analysis"""
    if request.method == 'POST':
        result = RequestSubmissionService.process_submission(
            request_type='cyberconsultation',
            form_data=request.form,
            files=request.files
        )
        
        if result['success']:
            log_activity('CONSULTATION_SUBMIT', 'Demande de cyberconsultation soumise', success=True)
            flash(result['message'], 'success')
            return redirect(url_for('request_forms.cyberconsultation'))
        else:
            if result.get('threat_detected'):
                log_activity('CONSULTATION_THREAT', result['message'], success=False)
                # Store only incident ID in session, full data in database
                metadata = collect_request_metadata()
                incident_id = generate_incident_id()
                
                # Store threat details in database for security and audit
                from models import db, ThreatLog
                threat_log = ThreatLog(
                    incident_id=incident_id,
                    threat_type=result.get('threat_type', 'unknown'),
                    threat_details=result.get('message'),
                    ip_address=metadata['ip_address'],
                    user_agent=metadata['user_agent'],
                    platform=metadata['platform'],
                    device_type=metadata['device_type'],
                    vpn_detected=metadata['vpn_detected'],
                    metadata_json=metadata
                )
                db.session.add(threat_log)
                db.session.commit()
                
                # Store incident ID in session AND pass as query parameter for reliability
                # This ensures the alert works even if cookies are blocked or not yet established
                session['threat_incident_id'] = incident_id
                return redirect(url_for('request_forms.security_threat', incident_id=incident_id))
            flash(result['message'], 'danger')
    
    return render_template('services/cyberconsultation_form.html')

@bp.route('/request/osint-investigation', methods=['POST'])
def osint_investigation():
    """OSINT Investigation request form submission (POST only - form is in cyberconsultation page)"""
    result = RequestSubmissionService.process_submission(
        request_type='osint-investigation',
        form_data=request.form,
        files=request.files
    )
    
    if result['success']:
        log_activity('OSINT_INVESTIGATION_SUBMIT', 'Demande d\'enquête OSINT soumise', success=True)
        flash(result['message'], 'success')
        return redirect(url_for('request_forms.cyberconsultation'))
    else:
        if result.get('threat_detected'):
            log_activity('OSINT_INVESTIGATION_THREAT', result['message'], success=False)
            # Store only incident ID in session, full data in database
            metadata = collect_request_metadata()
            incident_id = generate_incident_id()
            
            # Store threat details in database for security and audit
            from models import db, ThreatLog
            threat_log = ThreatLog(
                incident_id=incident_id,
                threat_type=result.get('threat_type', 'unknown'),
                threat_details=result.get('message'),
                ip_address=metadata['ip_address'],
                user_agent=metadata['user_agent'],
                platform=metadata['platform'],
                device_type=metadata['device_type'],
                vpn_detected=metadata['vpn_detected'],
                metadata_json=metadata
            )
            db.session.add(threat_log)
            db.session.commit()
            
            # Store incident ID in session AND pass as query parameter for reliability
            # This ensures the alert works even if cookies are blocked or not yet established
            session['threat_incident_id'] = incident_id
            return redirect(url_for('request_forms.security_threat', incident_id=incident_id))
        flash(result['message'], 'danger')
        return redirect(url_for('request_forms.cyberconsultation'))

@bp.route('/request/cybercrime-report', methods=['GET', 'POST'])
def cybercrime_report():
    """Cybercrime report form with enhanced security"""
    if request.method == 'POST':
        # Extract crime type and platform for better logging
        crime_type = request.form.get('crime_type', 'unknown')
        platform = request.form.get('platform', 'not specified')
        
        result = RequestSubmissionService.process_submission(
            request_type='cybercrime-report',
            form_data=request.form,
            files=request.files
        )
        
        if result['success']:
            log_activity('CYBERCRIME_REPORT_SUBMIT', 
                        f'Cybercrime report submitted: {crime_type} on {platform}', 
                        success=True)
            flash(result['message'], 'success')
            return redirect(url_for('request_forms.cybercrime_report'))
        else:
            if result.get('threat_detected'):
                log_activity('CYBERCRIME_REPORT_THREAT', 
                           f'{result["message"]} - Crime type: {crime_type}', 
                           success=False)
                # Store only incident ID in session, full data in database
                metadata = collect_request_metadata()
                incident_id = generate_incident_id()
                
                # Store threat details in database for security and audit
                from models import db, ThreatLog
                threat_log = ThreatLog(
                    incident_id=incident_id,
                    threat_type=result.get('threat_type', 'unknown'),
                    threat_details=result.get('message'),
                    ip_address=metadata['ip_address'],
                    user_agent=metadata['user_agent'],
                    platform=metadata['platform'],
                    device_type=metadata['device_type'],
                    vpn_detected=metadata['vpn_detected'],
                    metadata_json=metadata
                )
                db.session.add(threat_log)
                db.session.commit()
                
                # Store incident ID in session AND pass as query parameter for reliability
                # This ensures the alert works even if cookies are blocked or not yet established
                session['threat_incident_id'] = incident_id
                return redirect(url_for('request_forms.security_threat', incident_id=incident_id))
            flash(result['message'], 'danger')
    
    return render_template('services/cybercrime_report_form.html')

@bp.route('/security-threat')
def security_threat():
    """Display security threat warning page with all metadata
    
    Can be accessed via:
    - Query parameter: /security-threat?incident_id=XXX (for direct access, admin review)
    - Session: /security-threat (after threat detection redirects)
    
    The incident_id is kept in session to allow page refreshes and multi-tab access.
    Admins can share direct links using ?incident_id= parameter.
    """
    # Try to get incident ID from query parameter first (for direct access/admin review)
    # Then fall back to session (for normal threat detection flow)
    incident_id = request.args.get('incident_id') or session.get('threat_incident_id')
    
    if not incident_id:
        # If no incident ID, redirect to home
        return redirect(url_for('main.index'))
    
    # Retrieve threat data from database
    from models import ThreatLog
    threat_log = ThreatLog.query.filter_by(incident_id=incident_id).first()
    
    if not threat_log:
        # If incident not found, clear session and redirect
        session.pop('threat_incident_id', None)
        return redirect(url_for('main.index'))
    
    # Keep incident_id in session to allow page refreshes and multi-tab access
    # Session will be cleared automatically when user closes browser or logs out
    # This is safe because we only store the ID, not sensitive metadata
    
    return render_template('security_threat.html',
                         threat_type=threat_log.threat_type,
                         threat_details=threat_log.threat_details,
                         metadata=threat_log.metadata_json,
                         incident_id=threat_log.incident_id,
                         timestamp=threat_log.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'))
