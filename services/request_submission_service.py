"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier request_submission_service.py du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com

"""

"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Service de traitement des demandes utilisateurs avec scan de securite.
"""

from models import RequestSubmission, db
from services.security import SecurityAnalyzerService
from services.file_upload_service import FileUploadService
from utils.document_code_generator import ensure_unique_code
from flask import request
from utils.metadata_collector import get_client_ip
import os
import json
from decimal import Decimal
from datetime import datetime, date

class RequestSubmissionService:
    """Service for processing form submissions with security scanning"""
    
    @staticmethod
    def _ensure_json_serializable(data, _processing=None):
        """
        Recursively convert any object to JSON-serializable format.
        Handles sets, Decimals, datetime, bytes, custom objects, etc.
        Protects against circular references.
        
        Note: Shared references (same object referenced from multiple locations) will be
        normalized independently each time they're encountered. This ensures data integrity
        by avoiding mutable cache corruption, at a small performance cost.
        
        Args:
            data: The data to serialize
            _processing: Set of object IDs currently being processed (for cycle detection)
        
        Returns:
            JSON-serializable version of the data
        """
        if _processing is None:
            _processing = set()
        
        if data is None:
            return None
        
        # Handle primitive types first (no cycle risk)
        if isinstance(data, (str, int, float, bool)):
            return data
        
        # Handle datetime and date objects
        if isinstance(data, (datetime, date)):
            return data.isoformat()
        
        # Handle Decimal
        if isinstance(data, Decimal):
            try:
                return float(data)
            except (OverflowError, ValueError):
                return str(data)
        
        # Handle bytes
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                return data.hex()
        
        # For complex types, check for circular references
        obj_id = id(data)
        if obj_id in _processing:
            return "[Circular Reference]"
        
        # Mark as currently processing
        _processing.add(obj_id)
        
        try:
            # Handle sets
            if isinstance(data, set):
                return [RequestSubmissionService._ensure_json_serializable(item, _processing) for item in data]
            
            # Handle lists recursively
            elif isinstance(data, list):
                return [RequestSubmissionService._ensure_json_serializable(item, _processing) for item in data]
            
            # Handle tuples recursively
            elif isinstance(data, tuple):
                return [RequestSubmissionService._ensure_json_serializable(item, _processing) for item in data]
            
            # Handle dictionaries recursively
            elif isinstance(data, dict):
                return {
                    str(key): RequestSubmissionService._ensure_json_serializable(value, _processing)
                    for key, value in data.items()
                }
            
            # For any other object type, try to convert to dict if it has __dict__, otherwise use str()
            elif hasattr(data, '__dict__'):
                return RequestSubmissionService._ensure_json_serializable(data.__dict__, _processing)
            
            else:
                # Last resort: convert to string
                return str(data)
            
        finally:
            # Remove from processing set when done
            _processing.discard(obj_id)
    
    @staticmethod
    def process_submission(request_type, form_data, files):
        """
        Process a request submission with full security scanning
        
        Args:
            request_type: Type of request ('fact-checking', 'osint', 'cyberconsultation', 'cybercrime-report')
            form_data: Form data dictionary
            files: Uploaded files
        
        Returns:
            dict: Processing results with success status and any warnings
        """
        analyzer = SecurityAnalyzerService()
        
        description = form_data.get('description', '')
        urls_input = form_data.get('urls', '')
        is_anonymous = form_data.get('is_anonymous') == 'on'
        
        # Extract crime type, platform and identifier for cybercrime reports
        crime_type = None
        platform = None
        platform_identifier = None
        if request_type == 'cybercrime-report':
            crime_type = form_data.get('crime_type')
            platform = form_data.get('platform')
            platform_identifier = form_data.get('platform_identifier')
        
        # Extract fields for cyberconsultation requests
        consultation_type = None
        organization_size = None
        business_sector = None
        priority = None
        if request_type == 'cyberconsultation':
            consultation_type = form_data.get('consultation_type')
            organization_size = form_data.get('organization_size')
            business_sector = form_data.get('business_sector')
            priority = form_data.get('priority')
        
        # Extract fields for OSINT investigation requests (both osint and osint-investigation)
        investigation_type = None
        context = None
        target_identifier = None
        timeline = None
        known_information = None
        if request_type in ['osint', 'osint-investigation']:
            investigation_type = form_data.get('investigation_type')
            context = form_data.get('context')
            target_identifier = form_data.get('target_identifier')
            timeline = form_data.get('timeline')
            known_information = form_data.get('known_information')
        
        contact_name = None if is_anonymous else form_data.get('name')
        contact_email = None if is_anonymous else form_data.get('email')
        contact_phone = None if is_anonymous else form_data.get('phone')
        
        threat_detected = False
        vt_file_results = None
        vt_url_results = []
        vt_text_results = None
        file_name = None
        file_path = None
        file_size = None
        file_hash = None
        
        text_scan = analyzer.analyze_text(description)
        vt_text_results = RequestSubmissionService._ensure_json_serializable(text_scan)
        if text_scan.get('threat_detected'):
            threat_detected = True
            return {
                'success': False,
                'threat_detected': True,
                'threat_type': 'text',
                'message': '⚠️ ILLEGAL ACTIVITY ATTEMPT DETECTED! Malicious content found in your submission. This incident has been logged.'
            }
        
        if urls_input:
            urls = [url.strip() for url in urls_input.split('\n') if url.strip()]
            for url in urls[:5]:
                url_scan = analyzer.analyze(url, 'url')
                vt_url_results.append(RequestSubmissionService._ensure_json_serializable(url_scan))
                if url_scan.get('threat_detected'):
                    threat_detected = True
                    return {
                        'success': False,
                        'threat_detected': True,
                        'threat_type': 'url',
                        'message': f'⚠️ ILLEGAL ACTIVITY ATTEMPT DETECTED! Malicious URL detected: {url}. This incident has been logged.'
                    }
        
        if 'file' in files:
            file = files['file']
            if file and file.filename:
                upload_result = FileUploadService.process_upload(file)
                
                if not upload_result['success']:
                    return {
                        'success': False,
                        'message': upload_result.get('error', 'File upload failed')
                    }
                
                vt_file_results = RequestSubmissionService._ensure_json_serializable(upload_result['scan_result'])
                if upload_result['threat_detected']:
                    if os.path.exists(upload_result['temp_path']):
                        os.remove(upload_result['temp_path'])
                    
                    return {
                        'success': False,
                        'threat_detected': True,
                        'threat_type': 'file',
                        'message': '⚠️ ILLEGAL ACTIVITY ATTEMPT DETECTED! Malicious file detected. This incident has been logged.'
                    }
                
                file_name = upload_result['filename']
                file_hash = upload_result['file_hash']
                file_size = upload_result['file_size']
                file_path = upload_result['temp_path']
        
        submission = RequestSubmission(
            request_type=request_type,
            description=description,
            urls=urls_input,
            crime_type=crime_type,
            platform=platform,
            platform_identifier=platform_identifier,
            consultation_type=consultation_type,
            organization_size=organization_size,
            business_sector=business_sector,
            priority=priority,
            investigation_type=investigation_type,
            context=context,
            target_identifier=target_identifier,
            timeline=timeline,
            known_information=known_information,
            file_name=file_name,
            file_path=file_path,
            file_size=file_size,
            file_hash=file_hash,
            vt_file_results=vt_file_results,
            vt_url_results=vt_url_results,
            vt_text_results=vt_text_results,
            is_anonymous=is_anonymous,
            contact_name=contact_name,
            contact_email=contact_email,
            contact_phone=contact_phone,
            threat_detected=threat_detected,
            status='pending',
            document_code=ensure_unique_code(RequestSubmission),
            ip_address=get_client_ip(request),
            user_agent=request.headers.get('User-Agent', '')[:500]
        )
        
        db.session.add(submission)
        db.session.commit()
        
        return {
            'success': True,
            'submission_id': submission.id,
            'message': 'Votre demande a été soumise avec succès. Nous l\'examinerons et vous contacterons.'
        }
