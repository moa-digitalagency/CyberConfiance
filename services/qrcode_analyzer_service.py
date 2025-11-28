import os
import re
import io
import requests
from urllib.parse import urlparse, urljoin
import tempfile
from PIL import Image
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False
    pyzbar_decode = None

class QRCodeAnalyzerService:
    
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY') or os.environ.get('VT_API_KEY')
        self.max_redirects = 15
        self.request_timeout = 10
        
        self.phishing_keywords = [
            'login', 'signin', 'verify', 'account', 'secure', 'update',
            'confirm', 'password', 'banking', 'paypal', 'amazon', 'microsoft',
            'apple', 'google', 'facebook', 'instagram', 'whatsapp',
            'verification', 'suspended', 'locked', 'urgent', 'immediately',
            'wallet', 'crypto', 'bitcoin', 'coinbase', 'binance'
        ]
        
        self.suspicious_tlds = [
            '.xyz', '.top', '.club', '.online', '.site', '.work', '.click',
            '.link', '.info', '.buzz', '.win', '.loan', '.gq', '.ml', '.cf',
            '.tk', '.ga', '.pw', '.cc', '.ws'
        ]
        
        self.js_redirect_patterns = [
            r'window\.location\s*=',
            r'window\.location\.href\s*=',
            r'window\.location\.replace\s*\(',
            r'window\.location\.assign\s*\(',
            r'document\.location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'meta\s+http-equiv\s*=\s*["\']refresh["\']',
            r'<meta[^>]+url\s*=',
            r'setTimeout\s*\([^)]*location',
            r'\.redirect\s*\(',
        ]
        
        self.dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'data:text/html',
            r'vbscript:',
            r'on\w+\s*=\s*["\']',
        ]
    
    def decode_qr_from_image(self, image_data):
        if not PYZBAR_AVAILABLE:
            return None, "Bibliothèque de décodage QR non disponible"
        
        try:
            if isinstance(image_data, bytes):
                image = Image.open(io.BytesIO(image_data))
            else:
                image = Image.open(image_data)
            
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            decoded_objects = pyzbar_decode(image)
            
            if not decoded_objects:
                gray = image.convert('L')
                decoded_objects = pyzbar_decode(gray)
            
            if decoded_objects:
                for obj in decoded_objects:
                    if obj.type == 'QRCODE':
                        return obj.data.decode('utf-8'), None
                return decoded_objects[0].data.decode('utf-8'), None
            
            return None, "Aucun QR code détecté dans l'image"
            
        except Exception as e:
            return None, f"Erreur lors du décodage: {str(e)}"
    
    def is_safe_url(self, url):
        try:
            import socket
            import ipaddress
            
            parsed = urlparse(url)
            if parsed.scheme not in ['http', 'https']:
                return False, "Schema non autorise"
            
            hostname = parsed.hostname
            if not hostname:
                return False, "Nom d'hote manquant"
            
            dangerous_hostnames = [
                'localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]',
                'metadata.google.internal', '169.254.169.254',
                'metadata', 'kubernetes.default'
            ]
            if hostname.lower() in dangerous_hostnames:
                return False, "Adresse locale non autorisee"
            
            try:
                ip_addresses = socket.getaddrinfo(hostname, None)
                for family, type_, proto, canonname, sockaddr in ip_addresses:
                    ip_str = sockaddr[0]
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                            return False, "Adresse IP privee ou locale non autorisee"
                        if ip_obj.is_reserved or ip_obj.is_multicast:
                            return False, "Adresse IP reservee non autorisee"
                    except ValueError:
                        continue
            except socket.gaierror:
                pass
            
            return True, None
        except Exception as e:
            return False, str(e)
    
    def follow_redirects_safely(self, url):
        redirect_chain = []
        js_redirects = []
        final_url = url
        
        is_safe, error = self.is_safe_url(url)
        if not is_safe:
            redirect_chain.append({
                'url': url,
                'status': 'blocked',
                'error': error
            })
            return {
                'redirect_chain': redirect_chain,
                'final_url': url,
                'redirect_count': 0,
                'js_redirects': []
            }
        
        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=self.request_timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8'
                },
                verify=True,
                stream=True
            )
            
            for i, resp in enumerate(response.history):
                redirect_info = {
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'content_type': resp.headers.get('Content-Type', 'unknown'),
                    'redirect_type': 'http'
                }
                if resp.headers.get('Location'):
                    redirect_info['redirect_to'] = resp.headers.get('Location')
                redirect_chain.append(redirect_info)
            
            redirect_chain.append({
                'url': response.url,
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', 'unknown'),
            })
            
            final_url = response.url
            
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > 5 * 1024 * 1024:
                redirect_chain[-1]['warning'] = 'Contenu volumineux (> 5 MB)'
            else:
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' in content_type:
                        try:
                            content = response.text[:50000]
                            js_redirect = self.detect_js_redirects(content, response.url)
                            if js_redirect:
                                redirect_chain[-1]['js_redirect_detected'] = True
                                redirect_chain[-1]['js_redirect_url'] = js_redirect
                                js_redirects.append({
                                    'from': response.url,
                                    'to': js_redirect,
                                    'type': 'javascript'
                                })
                                
                                js_safe, js_error = self.is_safe_url(js_redirect)
                                if js_safe:
                                    try:
                                        js_response = requests.head(
                                            js_redirect,
                                            allow_redirects=True,
                                            timeout=5,
                                            headers={'User-Agent': 'Mozilla/5.0'}
                                        )
                                        final_url = js_response.url
                                        redirect_chain.append({
                                            'url': js_response.url,
                                            'status_code': js_response.status_code,
                                            'redirect_type': 'javascript_follow'
                                        })
                                    except:
                                        pass
                        except Exception as e:
                            redirect_chain[-1]['content_error'] = str(e)
                            
        except requests.exceptions.Timeout:
            redirect_chain.append({
                'url': url,
                'status': 'timeout',
                'error': 'Délai d\'attente dépassé (10s)'
            })
        except requests.exceptions.SSLError as e:
            redirect_chain.append({
                'url': url,
                'status': 'ssl_error',
                'error': f'Erreur de certificat SSL: {str(e)[:100]}'
            })
        except requests.exceptions.ConnectionError as e:
            redirect_chain.append({
                'url': url,
                'status': 'connection_error',
                'error': 'Impossible de se connecter au serveur'
            })
        except requests.exceptions.RequestException as e:
            redirect_chain.append({
                'url': url,
                'status': 'error',
                'error': str(e)[:200]
            })
        
        return {
            'redirect_chain': redirect_chain,
            'final_url': final_url,
            'redirect_count': len(redirect_chain) - 1 if redirect_chain else 0,
            'js_redirects': js_redirects
        }
    
    def detect_js_redirects(self, html_content, base_url):
        for pattern in self.js_redirect_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                context = html_content[match.start():match.end() + 200]
                url_match = re.search(r'["\']((https?://[^"\']+)|(/[^"\']+))["\']', context)
                if url_match:
                    found_url = url_match.group(1)
                    if not found_url.startswith('http'):
                        found_url = urljoin(base_url, found_url)
                    return found_url
        
        meta_refresh = re.search(
            r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+content\s*=\s*["\'][^"\']*url\s*=\s*([^"\'>\s]+)',
            html_content, re.IGNORECASE
        )
        if meta_refresh:
            return meta_refresh.group(1)
        
        return None
    
    def analyze_url_patterns(self, url):
        issues = []
        parsed = urlparse(url)
        
        for tld in self.suspicious_tlds:
            if parsed.netloc.endswith(tld):
                issues.append({
                    'type': 'suspicious_tld',
                    'severity': 'medium',
                    'message': f'Extension de domaine suspecte: {tld}'
                })
                break
        
        url_lower = url.lower()
        found_keywords = []
        for keyword in self.phishing_keywords:
            if keyword in url_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            issues.append({
                'type': 'phishing_keywords',
                'severity': 'high' if len(found_keywords) > 2 else 'medium',
                'message': f'Mots-clés suspects détectés: {", ".join(found_keywords[:5])}'
            })
        
        if len(url) > 200:
            issues.append({
                'type': 'long_url',
                'severity': 'low',
                'message': 'URL anormalement longue'
            })
        
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
            issues.append({
                'type': 'ip_address',
                'severity': 'high',
                'message': 'URL utilisant une adresse IP au lieu d\'un nom de domaine'
            })
        
        if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
            issues.append({
                'type': 'unusual_port',
                'severity': 'medium',
                'message': f'Port inhabituel: {parsed.port}'
            })
        
        if parsed.scheme == 'http':
            issues.append({
                'type': 'no_https',
                'severity': 'medium',
                'message': 'Connexion non sécurisée (HTTP au lieu de HTTPS)'
            })
        
        subdomain_count = len(parsed.netloc.split('.')) - 2
        if subdomain_count > 3:
            issues.append({
                'type': 'many_subdomains',
                'severity': 'medium',
                'message': f'Nombre inhabituel de sous-domaines ({subdomain_count})'
            })
        
        return issues
    
    def check_blacklist(self, url):
        if not self.api_key:
            return None, "API de vérification non configurée"
        
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                'x-apikey': self.api_key,
                'Accept': 'application/json'
            }
            
            vt_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            response = requests.get(vt_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                harmless_count = stats.get('harmless', 0)
                undetected_count = stats.get('undetected', 0)
                
                return {
                    'checked': True,
                    'malicious': malicious_count,
                    'suspicious': suspicious_count,
                    'harmless': harmless_count,
                    'undetected': undetected_count,
                    'total': malicious_count + suspicious_count + harmless_count + undetected_count,
                    'is_blacklisted': malicious_count > 0,
                    'scan_date': data.get('data', {}).get('attributes', {}).get('last_analysis_date'),
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0)
                }, None
                
            elif response.status_code == 404:
                scan_url = 'https://www.virustotal.com/api/v3/urls'
                scan_response = requests.post(
                    scan_url,
                    headers=headers,
                    data={'url': url},
                    timeout=10
                )
                
                if scan_response.status_code in [200, 201]:
                    return {
                        'checked': True,
                        'malicious': 0,
                        'suspicious': 0,
                        'harmless': 0,
                        'undetected': 0,
                        'is_blacklisted': False,
                        'message': 'URL soumise pour analyse - pas encore dans la base de données'
                    }, None
                else:
                    return {
                        'checked': True,
                        'malicious': 0,
                        'suspicious': 0,
                        'is_blacklisted': False,
                        'message': 'URL non répertoriée dans la base de données'
                    }, None
                    
            elif response.status_code == 401:
                return None, "Clé API VirusTotal invalide"
            elif response.status_code == 429:
                return None, "Limite de requêtes API dépassée"
            else:
                return None, f"Erreur API VirusTotal: {response.status_code}"
                
        except requests.exceptions.Timeout:
            return None, "Délai d'attente API VirusTotal dépassé"
        except requests.exceptions.RequestException as e:
            return None, f"Erreur de connexion à VirusTotal: {str(e)[:100]}"
        except Exception as e:
            return None, f"Erreur inattendue: {str(e)[:100]}"
    
    def analyze_qr_image(self, image_data, filename=None):
        result = {
            'success': False,
            'extracted_url': None,
            'final_url': None,
            'redirect_chain': [],
            'redirect_count': 0,
            'threat_detected': False,
            'threat_level': 'safe',
            'issues': [],
            'blacklist_result': None,
            'js_redirects': [],
            'original_filename': filename
        }
        
        extracted_data, error = self.decode_qr_from_image(image_data)
        
        if error:
            result['error'] = error
            return result
        
        if not extracted_data:
            result['error'] = "Aucune donnée extraite du QR code"
            return result
        
        result['extracted_data'] = extracted_data
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        url_match = re.search(url_pattern, extracted_data)
        
        if not url_match:
            if extracted_data.startswith('www.'):
                extracted_data = 'https://' + extracted_data
                url_match = re.search(url_pattern, extracted_data)
        
        if not url_match:
            result['success'] = True
            result['data_type'] = 'text'
            result['message'] = "QR code contient du texte (pas une URL)"
            return result
        
        url = url_match.group(0)
        result['extracted_url'] = url
        result['data_type'] = 'url'
        result['success'] = True
        
        url_issues = self.analyze_url_patterns(url)
        result['issues'].extend(url_issues)
        
        redirect_result = self.follow_redirects_safely(url)
        result['redirect_chain'] = redirect_result['redirect_chain']
        result['final_url'] = redirect_result['final_url']
        result['redirect_count'] = redirect_result['redirect_count']
        result['js_redirects'] = redirect_result['js_redirects']
        
        if result['final_url'] and result['final_url'] != url:
            final_issues = self.analyze_url_patterns(result['final_url'])
            for issue in final_issues:
                issue['location'] = 'final_url'
                result['issues'].append(issue)
        
        blacklist_result, bl_error = self.check_blacklist(url)
        if blacklist_result:
            result['blacklist_result'] = blacklist_result
            if blacklist_result.get('is_blacklisted'):
                result['issues'].append({
                    'type': 'blacklisted',
                    'severity': 'critical',
                    'message': f"URL détectée comme malveillante par {blacklist_result.get('malicious', 0)} sources"
                })
        
        if result['final_url'] and result['final_url'] != url:
            final_bl_result, _ = self.check_blacklist(result['final_url'])
            if final_bl_result and final_bl_result.get('is_blacklisted'):
                result['issues'].append({
                    'type': 'final_url_blacklisted',
                    'severity': 'critical',
                    'message': f"URL finale détectée comme malveillante"
                })
        
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_severity = 0
        for issue in result['issues']:
            score = severity_scores.get(issue.get('severity', 'low'), 1)
            max_severity = max(max_severity, score)
        
        if max_severity >= 4:
            result['threat_level'] = 'critical'
            result['threat_detected'] = True
        elif max_severity >= 3:
            result['threat_level'] = 'high'
            result['threat_detected'] = True
        elif max_severity >= 2:
            result['threat_level'] = 'medium'
            result['threat_detected'] = len(result['issues']) > 2
        else:
            result['threat_level'] = 'low' if result['issues'] else 'safe'
        
        return result
