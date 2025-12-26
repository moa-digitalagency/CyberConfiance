"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Utilitaires de securite: validation d'entrees et detection de menaces.
"""

import re
from flask import request
from utils.logging_utils import log_security_event

def is_valid_email(email):
    """Validate email format"""
    if not email or len(email) > 254:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_url(url):
    """Validate URL format"""
    if not url or len(url) > 2048:
        return False
    pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
    return re.match(pattern, url) is not None

def is_valid_domain(domain):
    """Validate domain format"""
    if not domain or len(domain) > 253:
        return False
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def is_valid_ip(ip):
    """Validate IPv4 or IPv6 address"""
    if not ip or len(ip) > 45:
        return False
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'
    
    if re.match(ipv4_pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    return bool(re.match(ipv6_pattern, ip))

def is_valid_hash(hash_value):
    """Validate hash format (MD5, SHA-1, SHA-256)"""
    if not hash_value:
        return False
    
    md5_pattern = r'^[a-fA-F0-9]{32}$'
    sha1_pattern = r'^[a-fA-F0-9]{40}$'
    sha256_pattern = r'^[a-fA-F0-9]{64}$'
    
    return bool(re.match(md5_pattern, hash_value) or 
                re.match(sha1_pattern, hash_value) or 
                re.match(sha256_pattern, hash_value))

def sanitize_input(text, max_length=1000):
    """Sanitize user input"""
    if not text:
        return ""
    
    text = str(text).strip()
    
    if len(text) > max_length:
        text = text[:max_length]
    
    dangerous_patterns = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
    ]
    
    for pattern in dangerous_patterns:
        text = re.sub(pattern, '', text, flags=re.IGNORECASE)
    
    return text

def check_rate_limit_exceeded(identifier, max_requests=10, time_window=60):
    """Check if rate limit is exceeded"""
    pass

def validate_file_upload(file):
    """Validate uploaded file"""
    if not file:
        return False, "Aucun fichier fourni"
    
    if file.filename == '':
        return False, "Nom de fichier vide"
    
    max_size = 32 * 1024 * 1024
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    
    if size > max_size:
        return False, "Le fichier dépasse la taille maximale de 32 MB"
    
    return True, "Fichier valide"

def detect_sql_injection(text):
    """Detect potential SQL injection attempts"""
    if not text:
        return False
    
    sql_keywords = [
        r'\bunion\b.*\bselect\b',
        r'\bselect\b.*\bfrom\b',
        r'\bdrop\b.*\btable\b',
        r'\binsert\b.*\binto\b',
        r'\bdelete\b.*\bfrom\b',
        r'\bupdate\b.*\bset\b',
        r'--',
        r'/\*.*\*/',
        r';.*\b(drop|delete|update|insert)\b'
    ]
    
    for pattern in sql_keywords:
        if re.search(pattern, str(text), re.IGNORECASE):
            log_security_event(
                event_type='SQL_INJECTION_ATTEMPT',
                severity='high',
                description=f'Possible SQL injection detected: {text[:100]}',
                blocked=True
            )
            return True
    
    return False

def detect_xss_attempt(text):
    """Detect potential XSS attempts"""
    if not text:
        return False
    
    xss_patterns = [
        r'<script[^>]*>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>'
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, str(text), re.IGNORECASE):
            log_security_event(
                event_type='XSS_ATTEMPT',
                severity='high',
                description=f'Possible XSS attempt detected: {text[:100]}',
                blocked=True
            )
            return True
    
    return False
