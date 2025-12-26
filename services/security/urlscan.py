"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Client API URLScan.io pour analyse comportementale.
"""

import os
import requests
import time
from typing import Dict, Optional
from urllib.parse import urlparse


class URLScanService:
    """Service for analyzing URLs using URLScan.io API"""
    
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY_3')
        self.base_url = "https://urlscan.io/api/v1"
        self.scan_timeout = 60
        self.poll_interval = 3
    
    def is_available(self) -> bool:
        return self.api_key is not None and len(self.api_key) > 0
    
    def scan_url(self, url: str, visibility: str = "unlisted") -> Dict:
        """
        Submit a URL for scanning and wait for results
        
        Args:
            url: URL to scan
            visibility: public, unlisted, or private
            
        Returns:
            dict: Scan results with threat information
        """
        if not self.is_available():
            return {
                'error': True,
                'source': 'urlscan',
                'message': 'URLScan.io API non configurée'
            }
        
        try:
            submit_result = self._submit_scan(url, visibility)
            if submit_result.get('error'):
                return submit_result
            
            uuid = submit_result.get('uuid')
            if not uuid:
                return {
                    'error': True,
                    'source': 'urlscan',
                    'message': 'UUID de scan non reçu'
                }
            
            result = self._wait_for_result(uuid)
            return result
            
        except Exception as e:
            return {
                'error': True,
                'source': 'urlscan',
                'message': f'Erreur URLScan: {str(e)}'
            }
    
    def _submit_scan(self, url: str, visibility: str = "unlisted") -> Dict:
        """Submit URL for scanning"""
        headers = {
            'Content-Type': 'application/json',
            'API-Key': self.api_key
        }
        
        data = {
            'url': url,
            'visibility': visibility,
            'tags': ['cyberconfiance', 'security-check']
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/scan/",
                headers=headers,
                json=data,
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'error': False,
                    'uuid': result.get('uuid'),
                    'api_url': result.get('api'),
                    'visibility': result.get('visibility'),
                    'result_url': result.get('result')
                }
            elif response.status_code == 400:
                return {
                    'error': True,
                    'source': 'urlscan',
                    'message': 'URL invalide ou bloquée par URLScan'
                }
            elif response.status_code == 429:
                return {
                    'error': True,
                    'source': 'urlscan',
                    'message': 'Limite de requêtes atteinte'
                }
            else:
                return {
                    'error': True,
                    'source': 'urlscan',
                    'message': f'Erreur API: HTTP {response.status_code}'
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'error': True,
                'source': 'urlscan',
                'message': f'Erreur de connexion: {str(e)}'
            }
    
    def _wait_for_result(self, uuid: str) -> Dict:
        """Wait for scan result with polling"""
        start_time = time.time()
        
        while time.time() - start_time < self.scan_timeout:
            try:
                response = requests.get(
                    f"{self.base_url}/result/{uuid}/",
                    timeout=10
                )
                
                if response.status_code == 200:
                    return self._parse_result(response.json(), uuid)
                elif response.status_code == 404:
                    time.sleep(self.poll_interval)
                    continue
                else:
                    return {
                        'error': True,
                        'source': 'urlscan',
                        'message': f'Erreur récupération résultat: HTTP {response.status_code}'
                    }
                    
            except requests.exceptions.RequestException:
                time.sleep(self.poll_interval)
                continue
        
        return {
            'error': True,
            'source': 'urlscan',
            'message': 'Timeout: analyse trop longue',
            'uuid': uuid,
            'result_url': f'https://urlscan.io/result/{uuid}/'
        }
    
    def _parse_result(self, data: Dict, uuid: str) -> Dict:
        """Parse URLScan result into structured format"""
        try:
            verdicts = data.get('verdicts', {})
            overall = verdicts.get('overall', {})
            urlscan_verdict = verdicts.get('urlscan', {})
            community_verdict = verdicts.get('community', {})
            
            is_malicious = overall.get('malicious', False)
            threat_score = overall.get('score', 0)
            
            page = data.get('page', {})
            stats = data.get('stats', {})
            lists = data.get('lists', {})
            
            brands = []
            if verdicts.get('brands'):
                brands = [b.get('name', '') for b in verdicts.get('brands', [])]
            
            trackers_detected = []
            tracker_domains = lists.get('urls', [])
            requests_list = data.get('data', {}).get('requests', [])
            
            known_tracker_patterns = [
                'doubleclick', 'google-analytics', 'googleadservices',
                'facebook.com/tr', 'analytics', 'tracking', 'pixel',
                'adservice', 'adsystem', 'advertising'
            ]
            
            for req in requests_list[:100]:
                req_url = req.get('request', {}).get('request', {}).get('url', '')
                for pattern in known_tracker_patterns:
                    if pattern in req_url.lower():
                        trackers_detected.append({
                            'url': req_url[:100],
                            'type': 'tracker'
                        })
                        break
            
            ip_logger_indicators = []
            suspicious_requests = 0
            
            for req in requests_list[:50]:
                req_url = req.get('request', {}).get('request', {}).get('url', '')
                if any(logger in req_url.lower() for logger in ['grabify', 'iplogger', '2no.co', 'blasze']):
                    ip_logger_indicators.append(req_url)
                    suspicious_requests += 1
            
            certificates = data.get('data', {}).get('requests', [{}])[0].get('response', {}).get('response', {}).get('securityDetails', {})
            
            threat_level = 'safe'
            if is_malicious or threat_score >= 75:
                threat_level = 'critical'
            elif threat_score >= 50 or brands:
                threat_level = 'high'
            elif threat_score >= 25 or suspicious_requests > 0:
                threat_level = 'medium'
            elif trackers_detected:
                threat_level = 'low'
            
            return {
                'error': False,
                'source': 'urlscan',
                'uuid': uuid,
                'result_url': f'https://urlscan.io/result/{uuid}/',
                'screenshot_url': f'https://urlscan.io/screenshots/{uuid}.png',
                
                'threat_detected': is_malicious or threat_score > 0,
                'threat_level': threat_level,
                'threat_score': threat_score,
                'is_malicious': is_malicious,
                
                'page': {
                    'url': page.get('url', ''),
                    'domain': page.get('domain', ''),
                    'ip': page.get('ip', ''),
                    'country': page.get('country', ''),
                    'server': page.get('server', ''),
                    'title': page.get('title', ''),
                    'status': page.get('status', 0)
                },
                
                'stats': {
                    'total_requests': stats.get('requests', 0),
                    'unique_ips': stats.get('uniqIPs', 0),
                    'unique_countries': stats.get('uniqCountries', 0),
                    'data_length': stats.get('dataLength', 0),
                    'malicious_requests': stats.get('malicious', 0),
                    'ads_blocked': stats.get('adBlocked', 0)
                },
                
                'verdicts': {
                    'overall_malicious': is_malicious,
                    'overall_score': threat_score,
                    'urlscan_malicious': urlscan_verdict.get('malicious', False),
                    'urlscan_score': urlscan_verdict.get('score', 0),
                    'community_score': community_verdict.get('score', 0),
                    'community_votes_malicious': community_verdict.get('votesMalicious', 0),
                    'community_votes_benign': community_verdict.get('votesBenign', 0)
                },
                
                'brands_detected': brands,
                'trackers_detected': trackers_detected[:10],
                'ip_logger_indicators': ip_logger_indicators,
                
                'security': {
                    'https': page.get('url', '').startswith('https'),
                    'certificate_issuer': certificates.get('issuer', ''),
                    'certificate_valid': certificates.get('validFrom', 0) > 0
                }
            }
            
        except Exception as e:
            return {
                'error': True,
                'source': 'urlscan',
                'message': f'Erreur parsing résultat: {str(e)}',
                'uuid': uuid,
                'result_url': f'https://urlscan.io/result/{uuid}/'
            }
    
    def quick_search(self, domain: str) -> Dict:
        """Search for existing scans of a domain"""
        try:
            response = requests.get(
                f"{self.base_url}/search/",
                params={'q': f'domain:{domain}', 'size': 5},
                timeout=10
            )
            
            if response.status_code == 200:
                results = response.json().get('results', [])
                if results:
                    latest = results[0]
                    return {
                        'error': False,
                        'found': True,
                        'uuid': latest.get('_id'),
                        'url': latest.get('page', {}).get('url'),
                        'domain': latest.get('page', {}).get('domain'),
                        'malicious': latest.get('verdicts', {}).get('overall', {}).get('malicious', False),
                        'score': latest.get('verdicts', {}).get('overall', {}).get('score', 0),
                        'scan_date': latest.get('task', {}).get('time')
                    }
                return {
                    'error': False,
                    'found': False,
                    'message': 'Aucun scan existant trouvé'
                }
            return {
                'error': True,
                'message': f'Erreur recherche: HTTP {response.status_code}'
            }
            
        except Exception as e:
            return {
                'error': True,
                'message': f'Erreur recherche: {str(e)}'
            }
    
    def get_threat_description(self, threat_level: str) -> str:
        """Get human-readable threat description"""
        descriptions = {
            'safe': 'Aucune menace détectée',
            'low': 'Risque faible - Trackers détectés',
            'medium': 'Risque modéré - Éléments suspects',
            'high': 'Risque élevé - Menace potentielle',
            'critical': 'Danger - Contenu malveillant confirmé'
        }
        return descriptions.get(threat_level, 'Niveau de risque inconnu')
