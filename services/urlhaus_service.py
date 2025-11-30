import os
import requests
from typing import Dict, Optional
from urllib.parse import urlparse

class URLhausService:
    """Service for checking URLs against URLhaus malware database"""
    
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY_2')
        self.base_url = "https://urlhaus-api.abuse.ch/v1"
    
    def is_available(self) -> bool:
        return self.api_key is not None and len(self.api_key) > 0
    
    def check_url(self, url: str) -> Dict:
        """
        Check a URL against URLhaus malware database
        
        Args:
            url: URL to check
            
        Returns:
            dict: Analysis results with threat information
        """
        if not self.is_available():
            return {
                'error': True,
                'source': 'urlhaus',
                'message': 'URLhaus API non configurée'
            }
        
        try:
            headers = {
                'Auth-Key': self.api_key
            }
            data = {
                'url': url
            }
            
            response = requests.post(
                f"{self.base_url}/url/",
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                query_status = result.get('query_status', '')
                
                if query_status == 'ok':
                    threat_type = result.get('threat', 'unknown')
                    url_status = result.get('url_status', 'unknown')
                    tags = result.get('tags', [])
                    
                    payloads = []
                    if 'payloads' in result:
                        for payload in result.get('payloads', [])[:5]:
                            payloads.append({
                                'filename': payload.get('filename', 'unknown'),
                                'file_type': payload.get('file_type', 'unknown'),
                                'signature': payload.get('signature', ''),
                                'virustotal': payload.get('virustotal', {})
                            })
                    
                    return {
                        'error': False,
                        'source': 'urlhaus',
                        'threat_detected': True,
                        'threat_type': threat_type,
                        'url_status': url_status,
                        'tags': tags,
                        'payloads': payloads,
                        'date_added': result.get('date_added', ''),
                        'urlhaus_reference': result.get('urlhaus_reference', ''),
                        'threat_level': self._calculate_threat_level(threat_type, url_status)
                    }
                elif query_status == 'no_results':
                    return {
                        'error': False,
                        'source': 'urlhaus',
                        'threat_detected': False,
                        'message': 'URL non trouvée dans la base URLhaus',
                        'threat_level': 'sûr'
                    }
                else:
                    return {
                        'error': True,
                        'source': 'urlhaus',
                        'message': f'Statut de requête: {query_status}'
                    }
            else:
                return {
                    'error': True,
                    'source': 'urlhaus',
                    'message': f'Erreur API URLhaus: {response.status_code}'
                }
                
        except requests.exceptions.Timeout:
            return {
                'error': True,
                'source': 'urlhaus',
                'message': 'Timeout - URLhaus ne répond pas'
            }
        except requests.exceptions.RequestException as e:
            return {
                'error': True,
                'source': 'urlhaus',
                'message': f'Erreur de connexion: {str(e)}'
            }
        except Exception as e:
            return {
                'error': True,
                'source': 'urlhaus',
                'message': f'Erreur inattendue: {str(e)}'
            }
    
    def check_host(self, host: str) -> Dict:
        """
        Check a host/domain against URLhaus database
        
        Args:
            host: Hostname or domain to check
            
        Returns:
            dict: Analysis results with threat information
        """
        if not self.is_available():
            return {
                'error': True,
                'source': 'urlhaus',
                'message': 'URLhaus API non configurée'
            }
        
        try:
            headers = {
                'Auth-Key': self.api_key
            }
            data = {
                'host': host
            }
            
            response = requests.post(
                f"{self.base_url}/host/",
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                query_status = result.get('query_status', '')
                
                if query_status == 'ok':
                    url_count = result.get('url_count', 0)
                    urls = result.get('urls', [])
                    
                    malware_urls = []
                    for url_info in urls[:10]:
                        malware_urls.append({
                            'url': url_info.get('url', ''),
                            'url_status': url_info.get('url_status', ''),
                            'threat': url_info.get('threat', ''),
                            'date_added': url_info.get('date_added', '')
                        })
                    
                    return {
                        'error': False,
                        'source': 'urlhaus',
                        'threat_detected': url_count > 0,
                        'host': host,
                        'url_count': url_count,
                        'malware_urls': malware_urls,
                        'blacklists': result.get('blacklists', {}),
                        'threat_level': 'critique' if url_count > 5 else ('élevé' if url_count > 0 else 'sûr')
                    }
                elif query_status == 'no_results':
                    return {
                        'error': False,
                        'source': 'urlhaus',
                        'threat_detected': False,
                        'host': host,
                        'message': 'Hôte non trouvé dans la base URLhaus',
                        'threat_level': 'sûr'
                    }
                else:
                    return {
                        'error': True,
                        'source': 'urlhaus',
                        'message': f'Statut de requête: {query_status}'
                    }
            else:
                return {
                    'error': True,
                    'source': 'urlhaus',
                    'message': f'Erreur API URLhaus: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'error': True,
                'source': 'urlhaus',
                'message': f'Erreur: {str(e)}'
            }
    
    def check_payload(self, file_hash: str, hash_type: str = 'sha256') -> Dict:
        """
        Check a file hash against URLhaus payload database
        
        Args:
            file_hash: File hash to check
            hash_type: Type of hash (md5, sha256)
            
        Returns:
            dict: Analysis results with threat information
        """
        if not self.is_available():
            return {
                'error': True,
                'source': 'urlhaus',
                'message': 'URLhaus API non configurée'
            }
        
        try:
            headers = {
                'Auth-Key': self.api_key
            }
            data = {
                f'{hash_type}_hash': file_hash
            }
            
            response = requests.post(
                f"{self.base_url}/payload/",
                headers=headers,
                data=data,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                query_status = result.get('query_status', '')
                
                if query_status == 'ok':
                    return {
                        'error': False,
                        'source': 'urlhaus',
                        'threat_detected': True,
                        'file_type': result.get('file_type', 'unknown'),
                        'file_size': result.get('file_size', 0),
                        'signature': result.get('signature', ''),
                        'firstseen': result.get('firstseen', ''),
                        'lastseen': result.get('lastseen', ''),
                        'url_count': result.get('url_count', 0),
                        'virustotal': result.get('virustotal', {}),
                        'threat_level': 'critique'
                    }
                elif query_status == 'no_results':
                    return {
                        'error': False,
                        'source': 'urlhaus',
                        'threat_detected': False,
                        'message': 'Hash non trouvé dans la base URLhaus',
                        'threat_level': 'sûr'
                    }
                else:
                    return {
                        'error': True,
                        'source': 'urlhaus',
                        'message': f'Statut de requête: {query_status}'
                    }
            else:
                return {
                    'error': True,
                    'source': 'urlhaus',
                    'message': f'Erreur API URLhaus: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'error': True,
                'source': 'urlhaus',
                'message': f'Erreur: {str(e)}'
            }
    
    def _calculate_threat_level(self, threat_type: str, url_status: str) -> str:
        """Calculate threat level based on threat type and status"""
        if url_status == 'online':
            return 'critique'
        elif threat_type in ['malware_download', 'ransomware']:
            return 'critique'
        elif url_status == 'offline':
            return 'élevé'
        else:
            return 'modéré'
    
    def get_threat_description(self, threat_type: str) -> str:
        """Get human-readable description for threat type"""
        descriptions = {
            'malware_download': 'Téléchargement de malware',
            'ransomware': 'Ransomware',
            'phishing': 'Phishing',
            'cryptominer': 'Cryptominer',
            'trojan': 'Cheval de Troie',
            'botnet': 'Botnet C&C'
        }
        return descriptions.get(threat_type, threat_type or 'Menace inconnue')
