"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier file_upload_service.py du projet CyberConfiance
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

Service de telechargement securise de fichiers avec scan VirusTotal.
"""

import os
import hashlib
import tempfile
import filetype
from werkzeug.utils import secure_filename
from services.security import SecurityAnalyzerService

MAX_FILE_SIZE = 200 * 1024 * 1024

class FileUploadService:
    """Service for handling secure file uploads with VirusTotal scanning"""
    
    @staticmethod
    def allowed_file(filename):
        """Check if file has an extension (all types allowed)"""
        return '.' in filename
    
    @staticmethod
    def get_file_hash(file_path):
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def validate_file_size(file):
        """Check if file size is within limits"""
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        return size <= MAX_FILE_SIZE, size
    
    @staticmethod
    def save_temp_file(file):
        """Save file to temporary location and return path"""
        if not file or file.filename == '':
            return None, "No file selected"
        
        if not FileUploadService.allowed_file(file.filename):
            return None, "Fichier invalide. Veuillez fournir un nom de fichier valide avec une extension."
        
        is_valid_size, file_size = FileUploadService.validate_file_size(file)
        if not is_valid_size:
            return None, f"File too large. Maximum size: {MAX_FILE_SIZE / (1024 * 1024)}MB"
        
        filename = secure_filename(file.filename)
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, f"upload_{os.urandom(16).hex()}_{filename}")
        
        file.save(temp_path)
        
        kind = filetype.guess(temp_path)
        
        return temp_path, None
    
    @staticmethod
    def scan_file_with_vt(file_path):
        """Scan file with VirusTotal using file hash"""
        try:
            file_hash = FileUploadService.get_file_hash(file_path)
            
            analyzer = SecurityAnalyzerService()
            result = analyzer.analyze(file_hash, 'hash')
            
            return result, file_hash
        except Exception as e:
            return {
                'error': True,
                'message': f'Error scanning file: {str(e)}'
            }, None
    
    @staticmethod
    def process_upload(file):
        """Complete file upload process: save, validate, scan"""
        temp_path, error = FileUploadService.save_temp_file(file)
        
        if error:
            return {
                'success': False,
                'error': error
            }
        
        try:
            scan_result, file_hash = FileUploadService.scan_file_with_vt(temp_path)
            
            file_size = os.path.getsize(temp_path)
            
            threat_detected = scan_result.get('threat_detected', False)
            
            return {
                'success': True,
                'temp_path': temp_path,
                'filename': secure_filename(file.filename),
                'file_hash': file_hash,
                'file_size': file_size,
                'scan_result': scan_result,
                'threat_detected': threat_detected
            }
        except Exception as e:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            return {
                'success': False,
                'error': f'Error processing file: {str(e)}'
            }
