import vt
import os
import hashlib
from datetime import datetime

class SecurityAnalyzerService:
    """Service for analyzing security threats via external API"""
    
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY')
    
    def analyze(self, input_value, input_type):
        """
        Analyze hash, domain, IP, URL, or file
        
        Args:
            input_value: The value to analyze (hash, domain, IP, URL)
            input_type: Type of input ('hash', 'domain', 'ip', 'url', 'file')
        
        Returns:
            dict: Analysis results
        """
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
