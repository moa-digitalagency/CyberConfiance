"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Collecteur de metadonnees de requete pour l'audit et la securite.
"""

from flask import request
from user_agents import parse
import uuid
from datetime import datetime


def collect_request_metadata():
    """
    Collect comprehensive metadata from the current request
    
    Returns:
        dict: Dictionary containing all request metadata
    """
    user_agent_string = request.headers.get('User-Agent', '')
    user_agent = parse(user_agent_string)
    
    # Detect potential VPN usage (basic detection)
    vpn_detected = detect_vpn(request)
    
    # Get client IP (considering proxies)
    ip_address = get_client_ip(request)
    
    # Get language preferences
    language = request.headers.get('Accept-Language', 'unknown')
    if language:
        language = language.split(',')[0]
    
    # Filter out sensitive headers before storing
    safe_headers = sanitize_headers(request.headers)
    
    metadata = {
        'ip_address': ip_address,
        'user_agent': user_agent_string,
        'platform': get_platform_name(user_agent),
        'device_type': get_device_type(user_agent),
        'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
        'os': f"{user_agent.os.family} {user_agent.os.version_string}",
        'language': language,
        'referrer': request.headers.get('Referer', ''),
        'vpn_detected': vpn_detected,
        'timestamp': datetime.utcnow().isoformat(),
        'headers': safe_headers,
        'method': request.method,
        'path': request.path,
        'is_mobile': user_agent.is_mobile,
        'is_tablet': user_agent.is_tablet,
        'is_pc': user_agent.is_pc,
        'is_bot': user_agent.is_bot
    }
    
    return metadata


def get_client_ip(req):
    """
    Get the real client IP address, considering proxies
    
    Args:
        req: Flask request object
        
    Returns:
        str: Client IP address
    """
    # Check for forwarded IPs (proxy/load balancer)
    if req.headers.get('X-Forwarded-For'):
        return req.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif req.headers.get('X-Real-IP'):
        return req.headers.get('X-Real-IP')
    else:
        return req.remote_addr


def detect_vpn(req):
    """
    Basic VPN detection based on headers and IP characteristics
    
    Args:
        req: Flask request object
        
    Returns:
        bool: True if VPN is potentially detected
    """
    # Check for common VPN/proxy headers
    vpn_indicators = [
        'X-Forwarded-For',
        'X-ProxyUser-Ip',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'Via'
    ]
    
    for indicator in vpn_indicators:
        if req.headers.get(indicator):
            return True
    
    # Additional checks could be added here (IP reputation databases, etc.)
    return False


def get_platform_name(user_agent):
    """
    Get a user-friendly platform name
    
    Args:
        user_agent: Parsed user agent object
        
    Returns:
        str: Platform name
    """
    if user_agent.is_mobile:
        return f"{user_agent.os.family} (Mobile)"
    elif user_agent.is_tablet:
        return f"{user_agent.os.family} (Tablet)"
    elif user_agent.is_pc:
        return f"{user_agent.os.family} (PC)"
    else:
        return user_agent.os.family


def get_device_type(user_agent):
    """
    Get device type
    
    Args:
        user_agent: Parsed user agent object
        
    Returns:
        str: Device type
    """
    if user_agent.is_mobile:
        return "Smartphone"
    elif user_agent.is_tablet:
        return "Tablette"
    elif user_agent.is_pc:
        return "Ordinateur"
    elif user_agent.is_bot:
        return "Bot/Crawler"
    else:
        return "Inconnu"


def sanitize_headers(headers):
    """
    Filter out sensitive headers before storing
    
    Args:
        headers: Request headers object
        
    Returns:
        dict: Sanitized headers without sensitive information
    """
    # List of headers to exclude from storage
    sensitive_headers = [
        'Authorization',
        'Cookie',
        'Set-Cookie',
        'X-Api-Key',
        'X-Auth-Token',
        'X-Csrf-Token',
        'Proxy-Authorization',
        'WWW-Authenticate',
        'Authentication-Info',
        'X-Session-Token',
        'X-Access-Token',
        'Bearer'
    ]
    
    safe_headers = {}
    for key, value in headers:
        # Only store non-sensitive headers
        if key not in sensitive_headers:
            safe_headers[key] = value
    
    return safe_headers


def generate_incident_id():
    """
    Generate a unique incident ID
    
    Returns:
        str: Unique incident ID
    """
    return f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
