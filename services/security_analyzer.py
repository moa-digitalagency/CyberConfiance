import vt
import os
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse

class SecurityAnalyzerService:
    """Service for analyzing security threats"""
    
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY') or os.environ.get('VT_API_KEY')
        
        self.malicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=\s*["\']',
            r'eval\s*\(',
            r'exec\s*\(',
            r'base64_decode',
            r'system\s*\(',
            r'shell_exec',
            r'passthru',
            r'\$_(GET|POST|REQUEST|COOKIE)\[',
            r'<?php',
            r'<%',
        ]
    
    def analyze(self, input_value, input_type):
        """
        Analyze hash, domain, IP, URL, file, or text
        
        Args:
            input_value: The value to analyze (hash, domain, IP, URL, text)
            input_type: Type of input ('hash', 'domain', 'ip', 'url', 'text')
        
        Returns:
            dict: Analysis results
        """
        if input_type == 'text':
            return self.analyze_text(input_value)
        
        if not self.api_key:
            return {
                'error': True,
                'message': 'Service de vérification non disponible. Configuration requise.'
            }
        
        try:
            with vt.Client(self.api_key) as client:
                if input_type == 'hash':
                    return self._analyze_file_hash(client, input_value)
                elif input_type == 'domain':
                    return self._analyze_domain(client, input_value)
                elif input_type == 'ip':
                    return self._analyze_ip(client, input_value)
                elif input_type == 'url':
                    return self._analyze_url(client, input_value)
                else:
                    return {
                        'error': True,
                        'message': 'Type d\'analyse non supporté'
                    }
        except vt.APIError as e:
            error_str = str(e)
            if 'NotFoundError' in error_str:
                return {
                    'error': False,
                    'found': False,
                    'message': 'Aucune menace connue détectée dans notre base de données.',
                    'malicious': 0,
                    'total': 0
                }
            generic_error = 'Service d\'analyse temporairement indisponible. Veuillez réessayer plus tard.'
            if 'authentication' in error_str.lower() or 'api key' in error_str.lower():
                generic_error = 'Service d\'analyse non configuré. Contactez l\'administrateur.'
            return {
                'error': True,
                'message': generic_error
            }
        except Exception as e:
            return {
                'error': True,
                'message': 'Erreur lors de la connexion au service d\'analyse. Veuillez réessayer.'
            }
    
    def _analyze_file_hash(self, client, file_hash):
        """Analyze a file hash"""
        try:
            file_obj = client.get_object(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            return {
                'error': False,
                'found': True,
                'type': 'file',
                'hash': file_hash,
                'malicious': malicious,
                'suspicious': suspicious,
                'total': total,
                'clean': stats.get('harmless', 0) + stats.get('undetected', 0),
                'stats': stats,
                'names': file_obj.get('names', []),
                'size': file_obj.get('size', 0),
                'type_description': file_obj.get('type_description', 'Inconnu'),
                'creation_date': file_obj.get('creation_date'),
                'threat_detected': malicious > 0 or suspicious > 0,
                'threat_level': self._calculate_threat_level(malicious, suspicious, total)
            }
        except Exception as e:
            raise e
    
    def _analyze_domain(self, client, domain):
        """Analyze a domain"""
        try:
            domain_obj = client.get_object(f"/domains/{domain}")
            stats = domain_obj.last_analysis_stats
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            return {
                'error': False,
                'found': True,
                'type': 'domain',
                'domain': domain,
                'malicious': malicious,
                'suspicious': suspicious,
                'total': total,
                'clean': stats.get('harmless', 0) + stats.get('undetected', 0),
                'stats': stats,
                'reputation': domain_obj.get('reputation', 0),
                'categories': domain_obj.get('categories', {}),
                'creation_date': domain_obj.get('creation_date'),
                'threat_detected': malicious > 0 or suspicious > 0,
                'threat_level': self._calculate_threat_level(malicious, suspicious, total)
            }
        except Exception as e:
            raise e
    
    def _analyze_ip(self, client, ip_address):
        """Analyze an IP address"""
        try:
            ip_obj = client.get_object(f"/ip_addresses/{ip_address}")
            stats = ip_obj.last_analysis_stats
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            return {
                'error': False,
                'found': True,
                'type': 'ip',
                'ip': ip_address,
                'malicious': malicious,
                'suspicious': suspicious,
                'total': total,
                'clean': stats.get('harmless', 0) + stats.get('undetected', 0),
                'stats': stats,
                'country': ip_obj.get('country', 'Inconnu'),
                'asn': ip_obj.get('asn', ''),
                'as_owner': ip_obj.get('as_owner', ''),
                'threat_detected': malicious > 0 or suspicious > 0,
                'threat_level': self._calculate_threat_level(malicious, suspicious, total)
            }
        except Exception as e:
            raise e
    
    def _analyze_url(self, client, url):
        """Analyze a URL"""
        try:
            url_id = vt.url_id(url)
            url_obj = client.get_object(f"/urls/{url_id}")
            stats = url_obj.last_analysis_stats
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            return {
                'error': False,
                'found': True,
                'type': 'url',
                'url': url,
                'malicious': malicious,
                'suspicious': suspicious,
                'total': total,
                'clean': stats.get('harmless', 0) + stats.get('undetected', 0),
                'stats': stats,
                'categories': url_obj.get('categories', {}),
                'times_submitted': url_obj.get('times_submitted', 0),
                'threat_detected': malicious > 0 or suspicious > 0,
                'threat_level': self._calculate_threat_level(malicious, suspicious, total)
            }
        except Exception as e:
            raise e
    
    def _calculate_threat_level(self, malicious, suspicious, total):
        """Calculate threat level based on detection ratios"""
        if total == 0:
            return 'inconnu'
        
        malicious_ratio = malicious / total
        suspicious_ratio = suspicious / total
        combined_ratio = malicious_ratio + (suspicious_ratio * 0.5)
        
        if combined_ratio >= 0.5:
            return 'critique'
        elif combined_ratio >= 0.25:
            return 'élevé'
        elif combined_ratio >= 0.1:
            return 'modéré'
        elif combined_ratio > 0:
            return 'faible'
        else:
            return 'sûr'
    
    def analyze_text(self, text):
        """
        Analyze text for malicious patterns and embedded URLs
        
        Args:
            text: Text content to analyze
        
        Returns:
            dict: Analysis results
        """
        if not text or len(text.strip()) == 0:
            return {
                'error': False,
                'threat_detected': False,
                'message': 'No content to analyze'
            }
        
        malicious_found = []
        for pattern in self.malicious_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                malicious_found.append({
                    'pattern': pattern,
                    'match': match.group()[:100],
                    'position': match.start()
                })
        
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls_found = re.findall(url_pattern, text)
        
        url_threats = []
        if urls_found and self.api_key:
            for url in urls_found[:5]:
                url_result = self.analyze(url, 'url')
                if not url_result.get('error') and url_result.get('threat_detected'):
                    url_threats.append({
                        'url': url,
                        'result': url_result
                    })
        
        threat_detected = len(malicious_found) > 0 or len(url_threats) > 0
        
        return {
            'error': False,
            'type': 'text',
            'threat_detected': threat_detected,
            'malicious_patterns_found': len(malicious_found),
            'malicious_patterns': malicious_found[:10],
            'urls_scanned': len(urls_found),
            'malicious_urls': url_threats,
            'threat_level': 'critique' if threat_detected else 'sûr',
            'message': 'Malicious content detected!' if threat_detected else 'Content appears safe'
        }
