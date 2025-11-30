import os
import re
import io
import requests
from urllib.parse import urlparse, urljoin, parse_qs, unquote
import tempfile
from PIL import Image
from bs4 import BeautifulSoup
from ctypes import cdll
import ctypes.util
from services.url_shortener_service import URLShortenerService

ZBAR_LIB_PATH = "/nix/store/lcjf0hd46s7b16vr94q3bcas7yg05c3c-zbar-0.23.93-lib/lib/libzbar.so.0"

_original_find_library = ctypes.util.find_library

def _patched_find_library(name):
    if name == 'zbar':
        return ZBAR_LIB_PATH
    return _original_find_library(name)

ctypes.util.find_library = _patched_find_library

try:
    cdll.LoadLibrary(ZBAR_LIB_PATH)
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except (ImportError, OSError) as e:
    PYZBAR_AVAILABLE = False
    pyzbar_decode = None
    print(f"Warning: pyzbar not available: {e}")


class QRCodeAnalyzerService:
    
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY') or os.environ.get('VT_API_KEY')
        self.max_redirects = 20
        self.request_timeout = 15
        self.url_shortener = URLShortenerService()
        self._security_analyzer = None
        
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
            (r'window\.location\s*=\s*["\']([^"\']+)["\']', 'window.location'),
            (r'window\.location\.href\s*=\s*["\']([^"\']+)["\']', 'window.location.href'),
            (r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']', 'window.location.replace'),
            (r'window\.location\.assign\s*\(\s*["\']([^"\']+)["\']', 'window.location.assign'),
            (r'document\.location\s*=\s*["\']([^"\']+)["\']', 'document.location'),
            (r'document\.location\.href\s*=\s*["\']([^"\']+)["\']', 'document.location.href'),
            (r'location\.href\s*=\s*["\']([^"\']+)["\']', 'location.href'),
            (r'location\.replace\s*\(\s*["\']([^"\']+)["\']', 'location.replace'),
            (r'location\.assign\s*\(\s*["\']([^"\']+)["\']', 'location.assign'),
            (r'(?<![\.\w])location\s*=\s*["\']([^"\']+)["\']', 'location'),
            (r'self\.location\s*=\s*["\']([^"\']+)["\']', 'self.location'),
            (r'top\.location\s*=\s*["\']([^"\']+)["\']', 'top.location'),
            (r'parent\.location\s*=\s*["\']([^"\']+)["\']', 'parent.location'),
            (r'window\.open\s*\(\s*["\']([^"\']+)["\']', 'window.open'),
            (r'\.redirect\s*\(\s*["\']([^"\']+)["\']', '.redirect()'),
            (r'window\.navigate\s*\(\s*["\']([^"\']+)["\']', 'window.navigate'),
            (r'history\.pushState\s*\([^,]*,\s*[^,]*,\s*["\']([^"\']+)["\']', 'history.pushState'),
            (r'history\.replaceState\s*\([^,]*,\s*[^,]*,\s*["\']([^"\']+)["\']', 'history.replaceState'),
            (r'document\.write\s*\([^)]*<meta[^>]*refresh[^>]*url\s*=\s*([^"\'>\s]+)', 'document.write+meta'),
        ]
        
        self.js_timeout_redirect_patterns = [
            (r'setTimeout\s*\(\s*(?:function\s*\(\)\s*\{[^}]*location[^}]*\}|[^,]*location[^,]*)\s*,\s*(\d+)', 'setTimeout+location'),
            (r'setInterval\s*\(\s*(?:function\s*\(\)\s*\{[^}]*location[^}]*\}|[^,]*location[^,]*)\s*,', 'setInterval+location'),
            (r'setTimeout\s*\([^)]*(?:window\.location|document\.location|location\.href)[^)]*,\s*\d+\)', 'setTimeout+redirect'),
            (r'requestAnimationFrame\s*\([^)]*(?:location|redirect)[^)]*\)', 'raf+redirect'),
        ]
        
        self.meta_refresh_patterns = [
            r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d*;?\s*url\s*=\s*["\']?(https?://[^"\'>\s;]+)',
            r'<meta[^>]*content\s*=\s*["\']?\d*;?\s*url\s*=\s*["\']?(https?://[^"\'>\s;]+)[^>]*http-equiv\s*=\s*["\']?refresh',
        ]
        
        self.link_redirect_patterns = [
            r'<a[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*(?:onclick|rel\s*=\s*["\']?noopener)',
            r'<link[^>]*rel\s*=\s*["\']?canonical["\']?[^>]*href\s*=\s*["\']([^"\']+)',
            r'<base[^>]*href\s*=\s*["\']([^"\']+)',
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
            return None, "Bibliotheque de decodage QR non disponible"
        
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
            
            return None, "Aucun QR code detecte dans l'image"
            
        except Exception as e:
            return None, f"Erreur lors du decodage: {str(e)}"
    
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
    
    def _create_session(self):
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        })
        return session
    
    def _parse_meta_refresh(self, soup, base_url):
        redirects = []
        found_urls = set()
        
        for meta in soup.find_all('meta'):
            http_equiv = meta.get('http-equiv', '').lower()
            if http_equiv == 'refresh':
                content = meta.get('content', '')
                url_match = re.search(r'url\s*=\s*["\']?([^"\'>\s;]+)', content, re.IGNORECASE)
                if url_match:
                    redirect_url = url_match.group(1).strip().strip('"\'')
                    if not redirect_url.startswith('http'):
                        redirect_url = urljoin(base_url, redirect_url)
                    if redirect_url not in found_urls:
                        found_urls.add(redirect_url)
                        delay_match = re.search(r'^(\d+)', content)
                        delay = int(delay_match.group(1)) if delay_match else 0
                        redirects.append({
                            'url': redirect_url,
                            'type': 'meta_refresh',
                            'delay': delay
                        })
                else:
                    simple_match = re.search(r'^(\d+);\s*([^\s"\']+)', content)
                    if simple_match:
                        redirect_url = simple_match.group(2).strip().strip('"\'')
                        if not redirect_url.startswith('http'):
                            redirect_url = urljoin(base_url, redirect_url)
                        if redirect_url not in found_urls:
                            found_urls.add(redirect_url)
                            redirects.append({
                                'url': redirect_url,
                                'type': 'meta_refresh',
                                'delay': int(simple_match.group(1))
                            })
        
        html_content = str(soup) if soup else ''
        for pattern in self.meta_refresh_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                try:
                    redirect_url = match.group(1).strip().strip('"\'')
                    if not redirect_url.startswith('http'):
                        redirect_url = urljoin(base_url, redirect_url)
                    if redirect_url not in found_urls:
                        found_urls.add(redirect_url)
                        redirects.append({
                            'url': redirect_url,
                            'type': 'meta_refresh_pattern',
                            'delay': 0
                        })
                except:
                    pass
        
        return redirects
    
    def _parse_js_redirects(self, soup, html_content, base_url):
        redirects = []
        found_urls = set()
        
        all_script_content = []
        scripts = soup.find_all('script')
        for script in scripts:
            script_content = script.string or ''
            all_script_content.append(script_content)
            
            for pattern, redirect_type in self.js_redirect_patterns:
                matches = re.finditer(pattern, script_content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    try:
                        raw_url = match.group(1)
                        if raw_url and not raw_url.startswith('#'):
                            url = self._normalize_url(raw_url, base_url)
                            if url and url not in found_urls and self._is_valid_url(url):
                                found_urls.add(url)
                                redirects.append({
                                    'url': url,
                                    'type': f'javascript_{redirect_type}',
                                    'method': redirect_type
                                })
                    except:
                        pass
            
            for pattern, redirect_type in self.js_timeout_redirect_patterns:
                matches = re.finditer(pattern, script_content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    for js_pattern, js_type in self.js_redirect_patterns:
                        url_match = re.search(js_pattern, script_content, re.IGNORECASE)
                        if url_match:
                            try:
                                raw_url = url_match.group(1)
                                if raw_url:
                                    url = self._normalize_url(raw_url, base_url)
                                    if url and url not in found_urls and self._is_valid_url(url):
                                        found_urls.add(url)
                                        redirects.append({
                                            'url': url,
                                            'type': f'javascript_{redirect_type}',
                                            'method': redirect_type,
                                            'delayed': True
                                        })
                            except:
                                pass
        
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.IGNORECASE | re.DOTALL)
        for script_content in inline_scripts:
            all_script_content.append(script_content)
            for pattern, redirect_type in self.js_redirect_patterns:
                matches = re.finditer(pattern, script_content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    try:
                        raw_url = match.group(1)
                        if raw_url and not raw_url.startswith('#'):
                            url = self._normalize_url(raw_url, base_url)
                            if url and url not in found_urls and self._is_valid_url(url):
                                found_urls.add(url)
                                redirects.append({
                                    'url': url,
                                    'type': f'javascript_{redirect_type}',
                                    'method': redirect_type
                                })
                    except:
                        pass
        
        full_script_text = '\n'.join(all_script_content)
        
        var_redirect_patterns = [
            r'(?:var|let|const)\s+\w+\s*=\s*["\']([^"\']+)["\'].*?(?:window\.location|location\.href|location\s*=)',
            r'(?:redirect|next|url|goto|target|link)(?:Url|URL|_url)?\s*[=:]\s*["\']([^"\']+)["\']',
            r'data-redirect\s*=\s*["\']([^"\']+)["\']',
            r'data-url\s*=\s*["\']([^"\']+)["\']',
            r'data-href\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in var_redirect_patterns:
            matches = re.finditer(pattern, full_script_text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                try:
                    url = match.group(1)
                    if url and url not in found_urls and url.startswith('http'):
                        if self._is_valid_url(url):
                            found_urls.add(url)
                            redirects.append({
                                'url': url,
                                'type': 'javascript_variable',
                                'method': 'variable_assignment'
                            })
                except:
                    pass
        
        encoded_url_patterns = [
            r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']',
            r'decodeURIComponent\s*\(\s*["\']([^"\']+)["\']',
            r'unescape\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in encoded_url_patterns:
            matches = re.finditer(pattern, full_script_text, re.IGNORECASE)
            for match in matches:
                try:
                    encoded = match.group(1)
                    if 'atob' in pattern:
                        import base64
                        decoded = base64.b64decode(encoded).decode('utf-8')
                    else:
                        decoded = unquote(encoded)
                    
                    if decoded.startswith('http') and decoded not in found_urls:
                        if self._is_valid_url(decoded):
                            found_urls.add(decoded)
                            redirects.append({
                                'url': decoded,
                                'type': 'javascript_encoded',
                                'method': 'encoded_url'
                            })
                except:
                    pass
        
        return redirects
    
    def _normalize_url(self, url, base_url):
        """Normalize a URL - only return valid absolute HTTP/HTTPS URLs"""
        if not url:
            return None
        
        url = url.strip().strip('"\'')
        
        code_indicators = ['${', '`', '=>', '&&', '||', 'function', 'return ', 'var ', 'let ', 'const ']
        if any(c in url for c in code_indicators):
            return None
        
        if '(' in url and ')' in url:
            return None
        
        if url.startswith('#') or url.startswith('javascript:') or url.startswith('data:') or url.startswith('mailto:') or url.startswith('tel:'):
            return None
        
        if url.startswith('//'):
            parsed_base = urlparse(base_url)
            url = f"{parsed_base.scheme}:{url}"
        elif url.startswith('http://') or url.startswith('https://'):
            pass
        elif url.startswith('/') or url.startswith('../') or url.startswith('./'):
            url = urljoin(base_url, url)
        elif re.match(r'^[\w\-./]+(?:\?[\w\-=&%]+)?$', url):
            url = urljoin(base_url, url)
        else:
            return None
        
        if self._is_valid_url(url):
            return url
        return None
    
    def _is_valid_url(self, url):
        """Check if URL is a valid absolute HTTP/HTTPS URL"""
        if not url:
            return False
        
        lower_url = url.lower()
        
        invalid_prefixes = ['javascript:', 'data:', 'vbscript:', 'about:', 'blob:', '#', 'mailto:', 'tel:']
        for prefix in invalid_prefixes:
            if lower_url.startswith(prefix):
                return False
        
        if not (lower_url.startswith('http://') or lower_url.startswith('https://')):
            return False
        
        invalid_substrings = ['.replace(', '.href.', 'function(', '=>', '${', '`']
        for sub in invalid_substrings:
            if sub in url:
                return False
        
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ['http', 'https']:
                return False
            if not parsed.netloc:
                return False
            if not '.' in parsed.netloc and parsed.netloc != 'localhost':
                return False
            return True
        except:
            return False
    
    def _parse_link_redirects(self, soup, base_url):
        redirects = []
        
        canonical = soup.find('link', rel='canonical')
        if canonical and canonical.get('href'):
            canonical_url = canonical['href']
            if not canonical_url.startswith('http'):
                canonical_url = urljoin(base_url, canonical_url)
            parsed_base = urlparse(base_url)
            parsed_canonical = urlparse(canonical_url)
            if parsed_base.netloc != parsed_canonical.netloc or parsed_base.path != parsed_canonical.path:
                redirects.append({
                    'url': canonical_url,
                    'type': 'link_canonical',
                    'note': 'URL canonique differente'
                })
        
        return redirects
    
    def _parse_frame_redirects(self, soup, base_url):
        redirects = []
        
        for frame in soup.find_all(['iframe', 'frame']):
            src = frame.get('src', '')
            if src and not src.startswith('about:') and not src.startswith('javascript:'):
                if not src.startswith('http'):
                    src = urljoin(base_url, src)
                
                style = frame.get('style', '')
                width = frame.get('width', '')
                height = frame.get('height', '')
                
                is_fullpage = False
                if '100%' in str(width) or '100%' in str(height):
                    is_fullpage = True
                if 'width: 100%' in style or 'height: 100%' in style:
                    is_fullpage = True
                if width == '0' or height == '0' or 'display:none' in style.replace(' ', ''):
                    continue
                
                if is_fullpage:
                    redirects.append({
                        'url': src,
                        'type': 'iframe_fullpage',
                        'note': 'iframe pleine page detecte'
                    })
        
        return redirects
    
    def _check_header_redirects(self, response, base_url):
        redirects = []
        
        refresh = response.headers.get('Refresh', '')
        if refresh:
            url_match = re.search(r'url\s*=\s*["\']?([^"\'>\s;]+)', refresh, re.IGNORECASE)
            if url_match:
                redirect_url = url_match.group(1)
                if not redirect_url.startswith('http'):
                    redirect_url = urljoin(base_url, redirect_url)
                redirects.append({
                    'url': redirect_url,
                    'type': 'header_refresh'
                })
        
        content_location = response.headers.get('Content-Location', '')
        if content_location:
            if not content_location.startswith('http'):
                content_location = urljoin(base_url, content_location)
            if content_location != base_url:
                redirects.append({
                    'url': content_location,
                    'type': 'header_content_location'
                })
        
        link_header = response.headers.get('Link', '')
        if link_header:
            canonical_match = re.search(r'<([^>]+)>\s*;\s*rel\s*=\s*["\']?canonical', link_header)
            if canonical_match:
                canonical_url = canonical_match.group(1)
                if not canonical_url.startswith('http'):
                    canonical_url = urljoin(base_url, canonical_url)
                redirects.append({
                    'url': canonical_url,
                    'type': 'header_link_canonical'
                })
        
        return redirects
    
    def _parse_url_params_redirect(self, url):
        redirects = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        redirect_params = ['url', 'redirect', 'redirect_uri', 'redirect_url', 'next', 'return', 
                          'return_url', 'returnUrl', 'goto', 'target', 'destination', 'continue',
                          'link', 'href', 'to', 'out', 'redir', 'u', 'q']
        
        for param in redirect_params:
            if param in params:
                potential_url = params[param][0]
                try:
                    potential_url = unquote(potential_url)
                except:
                    pass
                
                if potential_url.startswith('http://') or potential_url.startswith('https://'):
                    redirects.append({
                        'url': potential_url,
                        'type': 'url_parameter',
                        'param': param
                    })
        
        return redirects
    
    def follow_redirects_safely(self, url):
        redirect_chain = []
        all_redirects_found = []
        current_url = url
        visited = set()
        js_redirects = []
        final_url = url
        session = self._create_session()
        
        param_redirects = self._parse_url_params_redirect(url)
        for pr in param_redirects:
            all_redirects_found.append({
                'from': url,
                'to': pr['url'],
                'type': pr['type'],
                'param': pr.get('param', '')
            })
        
        for iteration in range(self.max_redirects):
            if current_url in visited:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'loop_detected',
                    'error': 'Boucle de redirection detectee',
                    'redirect_type': 'loop'
                })
                break
            
            visited.add(current_url)
            
            is_safe, error = self.is_safe_url(current_url)
            if not is_safe:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'blocked',
                    'error': error,
                    'redirect_type': 'blocked'
                })
                break
            
            try:
                try:
                    response = session.head(
                        current_url,
                        allow_redirects=False,
                        timeout=self.request_timeout,
                        verify=True
                    )
                except requests.exceptions.RequestException:
                    response = session.get(
                        current_url,
                        allow_redirects=False,
                        timeout=self.request_timeout,
                        verify=True,
                        stream=True
                    )
                
                redirect_info = {
                    'url': current_url,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', 'unknown'),
                    'server': response.headers.get('Server', 'unknown'),
                }
                
                if 300 <= response.status_code < 400:
                    next_url = response.headers.get('Location')
                    if next_url:
                        if not next_url.startswith('http'):
                            next_url = urljoin(current_url, next_url)
                        
                        redirect_info['redirect_to'] = next_url
                        redirect_info['redirect_type'] = f'http_{response.status_code}'
                        redirect_chain.append(redirect_info)
                        
                        all_redirects_found.append({
                            'from': current_url,
                            'to': next_url,
                            'type': f'http_{response.status_code}',
                            'status_code': response.status_code
                        })
                        
                        current_url = next_url
                        continue
                
                header_redirects = self._check_header_redirects(response, current_url)
                for hr in header_redirects:
                    all_redirects_found.append({
                        'from': current_url,
                        'to': hr['url'],
                        'type': hr['type']
                    })
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    if 'text/html' in content_type:
                        try:
                            if hasattr(response, 'text'):
                                content = response.text[:100000]
                            else:
                                get_response = session.get(
                                    current_url,
                                    allow_redirects=False,
                                    timeout=self.request_timeout,
                                    verify=True
                                )
                                content = get_response.text[:100000]
                                get_response.close()
                            
                            soup = BeautifulSoup(content, 'html.parser')
                            
                            meta_redirects = self._parse_meta_refresh(soup, current_url)
                            for mr in meta_redirects:
                                redirect_info['meta_refresh_detected'] = True
                                redirect_info['meta_refresh_url'] = mr['url']
                                redirect_info['meta_refresh_delay'] = mr.get('delay', 0)
                                all_redirects_found.append({
                                    'from': current_url,
                                    'to': mr['url'],
                                    'type': 'meta_refresh',
                                    'delay': mr.get('delay', 0)
                                })
                            
                            js_found = self._parse_js_redirects(soup, content, current_url)
                            for js in js_found:
                                redirect_info['js_redirect_detected'] = True
                                redirect_info['js_redirect_url'] = js['url']
                                redirect_info['js_redirect_method'] = js.get('method', 'unknown')
                                js_redirects.append({
                                    'from': current_url,
                                    'to': js['url'],
                                    'type': js['type'],
                                    'method': js.get('method', 'unknown')
                                })
                                all_redirects_found.append({
                                    'from': current_url,
                                    'to': js['url'],
                                    'type': js['type'],
                                    'method': js.get('method', 'unknown')
                                })
                            
                            link_redirects = self._parse_link_redirects(soup, current_url)
                            for lr in link_redirects:
                                all_redirects_found.append({
                                    'from': current_url,
                                    'to': lr['url'],
                                    'type': lr['type']
                                })
                            
                            frame_redirects = self._parse_frame_redirects(soup, current_url)
                            for fr in frame_redirects:
                                redirect_info['iframe_detected'] = True
                                redirect_info['iframe_url'] = fr['url']
                                all_redirects_found.append({
                                    'from': current_url,
                                    'to': fr['url'],
                                    'type': fr['type']
                                })
                            
                            next_redirect = None
                            if meta_redirects:
                                next_redirect = meta_redirects[0]['url']
                                redirect_info['redirect_to'] = next_redirect
                                redirect_info['redirect_type'] = 'meta_refresh'
                            elif js_found:
                                next_redirect = js_found[0]['url']
                                redirect_info['redirect_to'] = next_redirect
                                redirect_info['redirect_type'] = js_found[0]['type']
                            elif header_redirects:
                                next_redirect = header_redirects[0]['url']
                                redirect_info['redirect_to'] = next_redirect
                                redirect_info['redirect_type'] = header_redirects[0]['type']
                            
                            redirect_chain.append(redirect_info)
                            
                            if next_redirect and next_redirect not in visited:
                                is_next_safe, _ = self.is_safe_url(next_redirect)
                                if is_next_safe:
                                    current_url = next_redirect
                                    continue
                            
                            final_url = current_url
                            break
                            
                        except Exception as e:
                            redirect_info['content_error'] = str(e)[:100]
                            redirect_chain.append(redirect_info)
                            final_url = current_url
                            break
                    else:
                        redirect_chain.append(redirect_info)
                        final_url = current_url
                        break
                else:
                    redirect_chain.append(redirect_info)
                    final_url = current_url
                    break
                    
            except requests.exceptions.Timeout:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'timeout',
                    'error': 'Delai d\'attente depasse (15s)',
                    'redirect_type': 'error'
                })
                break
            except requests.exceptions.SSLError as e:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'ssl_error',
                    'error': f'Erreur de certificat SSL: {str(e)[:100]}',
                    'redirect_type': 'error'
                })
                break
            except requests.exceptions.ConnectionError:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'connection_error',
                    'error': 'Impossible de se connecter au serveur',
                    'redirect_type': 'error'
                })
                break
            except requests.exceptions.RequestException as e:
                redirect_chain.append({
                    'url': current_url,
                    'status': 'error',
                    'error': str(e)[:200],
                    'redirect_type': 'error'
                })
                break
        
        session.close()
        
        redirect_count = 0
        for item in redirect_chain:
            if item.get('redirect_to') or item.get('status_code') in [301, 302, 303, 307, 308]:
                redirect_count += 1
        
        return {
            'redirect_chain': redirect_chain,
            'final_url': final_url,
            'redirect_count': redirect_count,
            'js_redirects': js_redirects,
            'all_redirects_found': all_redirects_found,
            'total_urls_visited': len(visited)
        }
    
    def detect_js_redirects(self, html_content, base_url):
        for pattern, redirect_type in self.js_redirect_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                url = match.group(1)
                if url and not url.startswith('#'):
                    if not url.startswith('http'):
                        url = urljoin(base_url, url)
                    return url
        
        meta_refresh = re.search(
            r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+content\s*=\s*["\'][^"\']*url\s*=\s*([^"\'>\s;]+)',
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
                'message': f'Mots-cles suspects detectes: {", ".join(found_keywords[:5])}'
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
                'message': 'Connexion non securisee (HTTP au lieu de HTTPS)'
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
            return None, "API de verification non configuree"
        
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
                        'message': 'URL soumise pour analyse - pas encore dans la base de donnees'
                    }, None
                else:
                    return {
                        'checked': True,
                        'malicious': 0,
                        'suspicious': 0,
                        'is_blacklisted': False,
                        'message': 'URL non repertoriee dans la base de donnees'
                    }, None
                    
            elif response.status_code == 401:
                return None, "Cle API VirusTotal invalide"
            elif response.status_code == 429:
                return None, "Limite de requetes API depassee"
            else:
                return None, f"Erreur API VirusTotal: {response.status_code}"
                
        except requests.exceptions.Timeout:
            return None, "Delai d'attente API VirusTotal depasse"
        except requests.exceptions.RequestException as e:
            return None, f"Erreur de connexion a VirusTotal: {str(e)[:100]}"
        except Exception as e:
            return None, f"Erreur inattendue: {str(e)[:100]}"
    
    def _get_security_analyzer(self):
        if self._security_analyzer is None:
            from services.security_analyzer import SecurityAnalyzerService
            self._security_analyzer = SecurityAnalyzerService()
        return self._security_analyzer
    
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
            'all_redirects_found': [],
            'original_filename': filename,
            'url_shortener': {'detected': False},
            'multi_api_analysis': None
        }
        
        extracted_data, error = self.decode_qr_from_image(image_data)
        
        if error:
            result['error'] = error
            return result
        
        if not extracted_data:
            result['error'] = "Aucune donnee extraite du QR code"
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
        
        is_shortened, shortener_service = self.url_shortener.is_shortened_url(url)
        if is_shortened:
            print(f"[QR] URL raccourcie detectee: {url} (service: {shortener_service})")
            result['url_shortener'] = {
                'detected': True,
                'service': shortener_service,
                'service_details': self.url_shortener.get_shortener_info(shortener_service),
                'original_url': url
            }
            result['issues'].append({
                'type': 'url_shortener',
                'severity': 'medium',
                'message': f"URL raccourcie detectee ({shortener_service}) - destination masquee"
            })
        
        url_issues = self.analyze_url_patterns(url)
        result['issues'].extend(url_issues)
        
        redirect_result = self.follow_redirects_safely(url)
        result['redirect_chain'] = redirect_result['redirect_chain']
        result['final_url'] = redirect_result['final_url']
        result['redirect_count'] = redirect_result['redirect_count']
        result['js_redirects'] = redirect_result['js_redirects']
        result['all_redirects_found'] = redirect_result.get('all_redirects_found', [])
        
        if is_shortened:
            result['url_shortener']['final_url'] = result['final_url']
            result['url_shortener']['redirect_count'] = result['redirect_count']
            
            shorteners_in_chain = []
            for redirect in result['redirect_chain']:
                redirect_url = redirect.get('url', '')
                is_short, service = self.url_shortener.is_shortened_url(redirect_url)
                if is_short:
                    shorteners_in_chain.append({'url': redirect_url, 'service': service})
            
            if len(shorteners_in_chain) > 1:
                result['url_shortener']['multiple_shorteners'] = True
                result['url_shortener']['shorteners_found'] = shorteners_in_chain
                result['issues'].append({
                    'type': 'multiple_shorteners',
                    'severity': 'high',
                    'message': f"Plusieurs raccourcisseurs detectes ({len(shorteners_in_chain)}) - technique d'obfuscation"
                })
        
        if result['js_redirects']:
            result['issues'].append({
                'type': 'js_redirect',
                'severity': 'medium',
                'message': f'{len(result["js_redirects"])} redirection(s) JavaScript detectee(s)'
            })
        
        if result['redirect_count'] > 3:
            result['issues'].append({
                'type': 'many_redirects',
                'severity': 'medium',
                'message': f'Nombre eleve de redirections: {result["redirect_count"]}'
            })
        
        if result['final_url'] and result['final_url'] != url:
            final_issues = self.analyze_url_patterns(result['final_url'])
            for issue in final_issues:
                issue['location'] = 'final_url'
                result['issues'].append(issue)
        
        try:
            security_analyzer = self._get_security_analyzer()
            url_to_analyze = result['final_url'] if result['final_url'] else url
            
            print(f"[QR] Analyse multi-API de l'URL: {url_to_analyze}")
            multi_api_result = security_analyzer.analyze(url_to_analyze, 'url')
            
            if not multi_api_result.get('error'):
                result['multi_api_analysis'] = {
                    'url_analyzed': url_to_analyze,
                    'threat_detected': multi_api_result.get('threat_detected', False),
                    'threat_level': multi_api_result.get('threat_level', 'inconnu'),
                    'sources_checked': multi_api_result.get('sources_checked', 0),
                    'sources_with_threat': multi_api_result.get('sources_with_threat', 0),
                    'all_threats': multi_api_result.get('all_threats', []),
                    'source_results': multi_api_result.get('source_results', {})
                }
                
                if multi_api_result.get('threat_detected'):
                    threat_level = multi_api_result.get('threat_level', 'modéré')
                    severity_map = {'critique': 'critical', 'élevé': 'high', 'modéré': 'medium', 'sûr': 'low'}
                    severity = severity_map.get(threat_level, 'medium')
                    
                    result['issues'].append({
                        'type': 'multi_api_threat',
                        'severity': severity,
                        'message': f"Menace detectee par {multi_api_result.get('sources_with_threat', 0)} source(s) de securite"
                    })
                    
                    for threat in multi_api_result.get('all_threats', []):
                        result['issues'].append({
                            'type': f"threat_{threat.get('source', 'unknown').lower().replace(' ', '_')}",
                            'severity': severity,
                            'message': f"{threat.get('source')}: {threat.get('type')} - {threat.get('details', '')}"
                        })
                
                if url != url_to_analyze:
                    print(f"[QR] Analyse multi-API de l'URL originale: {url}")
                    original_api_result = security_analyzer.analyze(url, 'url')
                    if not original_api_result.get('error') and original_api_result.get('threat_detected'):
                        result['multi_api_analysis']['original_url_threat'] = True
                        result['issues'].append({
                            'type': 'original_url_threat',
                            'severity': 'high',
                            'message': f"L'URL originale (raccourcie) est aussi detectee comme menace"
                        })
            else:
                result['multi_api_analysis'] = {
                    'error': True,
                    'message': multi_api_result.get('message', 'Erreur lors de l\'analyse multi-API')
                }
        except Exception as e:
            print(f"[QR] Erreur analyse multi-API: {e}")
            result['multi_api_analysis'] = {
                'error': True,
                'message': str(e)[:100]
            }
        
        blacklist_result, bl_error = self.check_blacklist(url)
        if blacklist_result:
            result['blacklist_result'] = blacklist_result
            if blacklist_result.get('is_blacklisted'):
                result['issues'].append({
                    'type': 'blacklisted',
                    'severity': 'critical',
                    'message': f"URL detectee comme malveillante par {blacklist_result.get('malicious', 0)} sources"
                })
        
        if result['final_url'] and result['final_url'] != url:
            final_bl_result, _ = self.check_blacklist(result['final_url'])
            if final_bl_result and final_bl_result.get('is_blacklisted'):
                result['issues'].append({
                    'type': 'final_url_blacklisted',
                    'severity': 'critical',
                    'message': f"URL finale detectee comme malveillante"
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
