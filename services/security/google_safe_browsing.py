import os
import requests
from typing import Dict, Tuple, List

class GoogleSafeBrowsingService:
    """Service for checking URLs against Google Safe Browsing API"""
    
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY_1')
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.threat_types = [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
        ]
    
    def is_available(self) -> bool:
        return self.api_key is not None and len(self.api_key) > 0
    
    def check_url(self, url: str) -> Dict:
        """
        Check a URL against Google Safe Browsing API
        
        Args:
            url: URL to check
            
        Returns:
            dict: Analysis results with threat information
        """
        if not self.is_available():
            return {
                'error': True,
                'source': 'google_safe_browsing',
                'message': 'Google Safe Browsing API non configurée'
            }
        
        try:
            payload = {
                "client": {
                    "clientId": "cyberconfiance",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": self.threat_types,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if 'matches' in result and len(result['matches']) > 0:
                    threats = []
                    threat_types_found = set()
                    
                    for match in result['matches']:
                        threat_type = match.get('threatType', 'UNKNOWN')
                        threat_types_found.add(threat_type)
                        threats.append({
                            'type': threat_type,
                            'platform': match.get('platformType', 'UNKNOWN'),
                            'url': match.get('threat', {}).get('url', url)
                        })
                    
                    return {
                        'error': False,
                        'source': 'google_safe_browsing',
                        'threat_detected': True,
                        'threat_count': len(threats),
                        'threat_types': list(threat_types_found),
                        'threats': threats,
                        'threat_level': self._calculate_threat_level(threat_types_found)
                    }
                else:
                    return {
                        'error': False,
                        'source': 'google_safe_browsing',
                        'threat_detected': False,
                        'threat_count': 0,
                        'threat_types': [],
                        'threats': [],
                        'threat_level': 'sûr'
                    }
            elif response.status_code == 400:
                return {
                    'error': True,
                    'source': 'google_safe_browsing',
                    'message': 'Requête invalide'
                }
            elif response.status_code == 403:
                return {
                    'error': True,
                    'source': 'google_safe_browsing',
                    'message': 'Clé API Google invalide ou quota dépassé'
                }
            else:
                return {
                    'error': True,
                    'source': 'google_safe_browsing',
                    'message': f'Erreur API Google: {response.status_code}'
                }
                
        except requests.exceptions.Timeout:
            return {
                'error': True,
                'source': 'google_safe_browsing',
                'message': 'Timeout - Google Safe Browsing ne répond pas'
            }
        except requests.exceptions.RequestException as e:
            return {
                'error': True,
                'source': 'google_safe_browsing',
                'message': f'Erreur de connexion: {str(e)}'
            }
        except Exception as e:
            return {
                'error': True,
                'source': 'google_safe_browsing',
                'message': f'Erreur inattendue: {str(e)}'
            }
    
    def check_urls(self, urls: List[str]) -> Dict:
        """
        Check multiple URLs against Google Safe Browsing API (batch)
        
        Args:
            urls: List of URLs to check (max 500)
            
        Returns:
            dict: Analysis results for all URLs
        """
        if not self.is_available():
            return {
                'error': True,
                'source': 'google_safe_browsing',
                'message': 'Google Safe Browsing API non configurée'
            }
        
        urls = urls[:500]
        
        try:
            threat_entries = [{"url": url} for url in urls]
            
            payload = {
                "client": {
                    "clientId": "cyberconfiance",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": self.threat_types,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": threat_entries
                }
            }
            
            response = requests.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                
                threats_by_url = {}
                
                if 'matches' in result:
                    for match in result['matches']:
                        matched_url = match.get('threat', {}).get('url', '')
                        if matched_url not in threats_by_url:
                            threats_by_url[matched_url] = []
                        threats_by_url[matched_url].append({
                            'type': match.get('threatType', 'UNKNOWN'),
                            'platform': match.get('platformType', 'UNKNOWN')
                        })
                
                return {
                    'error': False,
                    'source': 'google_safe_browsing',
                    'urls_checked': len(urls),
                    'threats_found': len(threats_by_url),
                    'threats_by_url': threats_by_url
                }
            else:
                return {
                    'error': True,
                    'source': 'google_safe_browsing',
                    'message': f'Erreur API: {response.status_code}'
                }
                
        except Exception as e:
            return {
                'error': True,
                'source': 'google_safe_browsing',
                'message': f'Erreur: {str(e)}'
            }
    
    def _calculate_threat_level(self, threat_types: set) -> str:
        """Calculate threat level based on detected threat types"""
        if 'MALWARE' in threat_types or 'POTENTIALLY_HARMFUL_APPLICATION' in threat_types:
            return 'critique'
        elif 'SOCIAL_ENGINEERING' in threat_types:
            return 'élevé'
        elif 'UNWANTED_SOFTWARE' in threat_types:
            return 'modéré'
        else:
            return 'modéré'
    
    def get_threat_description(self, threat_type: str) -> str:
        """Get human-readable description for threat type"""
        descriptions = {
            'MALWARE': 'Logiciel malveillant (virus, trojan, etc.)',
            'SOCIAL_ENGINEERING': 'Ingénierie sociale / Phishing',
            'UNWANTED_SOFTWARE': 'Logiciel indésirable',
            'POTENTIALLY_HARMFUL_APPLICATION': 'Application potentiellement dangereuse'
        }
        return descriptions.get(threat_type, 'Menace inconnue')
