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
        current_url = url
        visited = set()
        js_redirects = []
        
        for i in range(self.max_redirects):
            if current_url in visited:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'loop_detected',
                    'error': 'Boucle de redirection détectée'
                })
                break
            
            visited.add(current_url)
            
            is_safe, error = self.is_safe_url(current_url)
            if not is_safe:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'blocked',
                    'error': error
                })
                break
            
            try:
                response = requests.get(
                    current_url,
                    allow_redirects=False,
                    timeout=self.request_timeout,
                    headers={
                        'User-Agent': 'CyberConfiance-QRAnalyzer/1.0',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    },
                    verify=True,
                    stream=True
                )
                
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > 5 * 1024 * 1024:
                    redirect_chain.append({
                        'url': current_url,
                        'status': 'too_large',
                        'error': 'Contenu trop volumineux (> 5 MB)'
                    })
                    response.close()
                    break
                
                redirect_info = {
                    'url': current_url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', 'unknown'),
                }
                
                if 300 <= response.status_code < 400:
                    next_url = response.headers.get('Location')
                    if next_url:
                        if not next_url.startswith('http'):
                            next_url = urljoin(current_url, next_url)
                        redirect_info['redirect_to'] = next_url
                        redirect_info['redirect_type'] = 'http'
                        redirect_chain.append(redirect_info)
                        current_url = next_url
                        continue
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' in content_type:
                        content = response.text[:50000]
                        js_redirect = self.detect_js_redirects(content, current_url)
                        if js_redirect:
                            redirect_info['js_redirect_detected'] = True
                            redirect_info['js_redirect_url'] = js_redirect
                            js_redirects.append({
                                'from': current_url,
                                'to': js_redirect,
                                'type': 'javascript'
                            })
                
                redirect_chain.append(redirect_info)
                break
                
            except requests.exceptions.Timeout:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'timeout',
                    'error': 'Délai d\'attente dépassé'
                })
                break
            except requests.exceptions.SSLError:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'ssl_error',
                    'error': 'Erreur de certificat SSL'
                })
                break
            except requests.exceptions.RequestException as e:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'error',
                    'error': str(e)
                })
                break
        
        final_url = redirect_chain[-1]['url'] if redirect_chain else url
        
        return {
            'redirect_chain': redirect_chain,
            'final_url': final_url,
            'redirect_count': len(redirect_chain) - 1,
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
            import vt
            with vt.Client(self.api_key) as client:
                url_id = vt.url_id(url)
                try:
                    url_object = client.get_object(f"/urls/{url_id}")
                    stats = url_object.last_analysis_stats
                    
                    return {
                        'checked': True,
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'harmless': stats.get('harmless', 0),
                        'undetected': stats.get('undetected', 0),
                        'total': sum(stats.values()),
                        'is_blacklisted': stats.get('malicious', 0) > 0
                    }, None
                except vt.APIError as e:
                    if 'NotFoundError' in str(e):
                        return {
                            'checked': True,
                            'malicious': 0,
                            'suspicious': 0,
                            'is_blacklisted': False,
                            'message': 'URL non répertoriée dans la base de données'
                        }, None
                    return None, str(e)
        except Exception as e:
            return None, str(e)
    
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
