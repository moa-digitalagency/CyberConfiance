"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier url_shortener.py du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com

"""

"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Service d'expansion d'URLs raccourcies.
"""

import os
import re
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


class URLShortenerService:
    
    def __init__(self):
        self.request_timeout = 10
        self.max_redirects = 15
        
        self.shortener_domains = [
            'bit.ly', 'bitly.com', 'j.mp',
            'tinyurl.com', 'tiny.cc', 'tiny.one',
            't.co',
            'goo.gl', 'g.co',
            'ow.ly', 'ht.ly',
            'buff.ly',
            'is.gd', 'v.gd',
            'lnkd.in', 'linkedin.com/slink',
            'youtu.be',
            'fb.me', 'fb.watch',
            'bit.do',
            'cutt.ly', 'cutt.us',
            'shorturl.at', 'shorturl.asia',
            'rb.gy', 'rebrand.ly',
            'short.io', 'short.link',
            'cli.re', 'clicky.me',
            's.id', 'rotf.lol',
            'adf.ly', 'adfoc.us', 'bc.vc', 'ouo.io', 'sh.st',
            'linktr.ee',
            'smarturl.it',
            'amzn.to', 'amzn.eu',
            'spoti.fi',
            'lnk.to',
            'soo.gd', 'qr.ae',
            'po.st',
            'mcaf.ee',
            'snip.ly', 'sniply.io',
            'dlvr.it',
            'flip.it',
            'zpr.io',
            'reurl.cc',
            'pse.is',
            'redd.it',
            'forms.gle', 'docs.google.com/forms',
            'trib.al',
            'aka.ms',
            'apple.co',
            'git.io',
            'npr.org/s',
            'nyti.ms', 'nytimes.com/s',
            'wapo.st',
            'cnn.it',
            'bbc.in',
            'reut.rs',
            'cbsn.ws',
            'abcn.ws',
            'fxn.ws',
            'huffp.st',
            'econ.st',
            'bloom.bg',
            'on.ft.com',
            'gu.com', 'theguardian.com/p',
            'zurl.co',
            'qps.ru',
            'u.to',
            'url.ie',
            '0rz.tw', '4sq.com',
            '7.ly', '1url.com',
            'han.gl', 'hoy.kr',
            'me2.kr', 'durl.me',
            'vo.la', 'vrl.to',
            'x.co', 'xrl.us',
            'chilp.it', 'clck.ru',
            'dfrcdn.net', 'murl.kz',
            'prettylinkpro.com',
            'scrnch.me', 'filoops.info',
            'vzturl.com', 'qr.net',
            'golinks.io', 'go.ly',
            'fur.ly', 'tinu.be',
            'shortener.link', 'short.cm',
            'bl.ink', 'ity.im',
            'shorte.st', 'adbull.me',
            'zzb.bz', 'hyperurl.co',
            'urlz.fr', 'u.nu',
            'clic.ly', '2ya.com',
            'tr.im', 'su.pr',
            'twurl.nl', 'tweez.me',
            't.ly', 'tgf.one',
            'urlify.io', 'urls.fr',
        ]
        
        self.shortener_patterns = [
            r'^[a-z0-9]{1,3}\.[a-z]{2,3}/[a-zA-Z0-9]+$',
            r'/s/[a-zA-Z0-9]+$',
            r'/l/[a-zA-Z0-9]+$',
            r'/r/[a-zA-Z0-9]+$',
        ]
    
    def is_shortened_url(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace('www.', '')
            
            for shortener in self.shortener_domains:
                if domain == shortener or domain.endswith('.' + shortener):
                    return True, shortener
            
            path = parsed.path
            if len(path) > 1 and len(path) < 20:
                path_part = path.split('/')[-1] if '/' in path else path[1:]
                if len(path_part) > 0 and len(path_part) < 15:
                    if re.match(r'^[a-zA-Z0-9_-]+$', path_part):
                        tld = domain.split('.')[-1] if '.' in domain else ''
                        if len(tld) <= 3 and len(domain.split('.')[0]) <= 6:
                            return True, domain
            
            return False, None
            
        except Exception as e:
            return False, None
    
    def expand_url(self, url, follow_all=True):
        result = {
            'original_url': url,
            'is_shortened': False,
            'shortener_service': None,
            'final_url': url,
            'redirect_chain': [],
            'redirect_count': 0,
            'expansion_error': None,
            'all_urls': [url]
        }
        
        is_short, service = self.is_shortened_url(url)
        result['is_shortened'] = is_short
        result['shortener_service'] = service
        
        if not is_short and not follow_all:
            return result
        
        try:
            session = self._create_session()
            current_url = url
            visited = set()
            redirect_chain = []
            
            for _ in range(self.max_redirects):
                if current_url in visited:
                    result['expansion_error'] = 'Boucle de redirection detectee'
                    break
                
                visited.add(current_url)
                
                try:
                    response = session.head(
                        current_url,
                        allow_redirects=False,
                        timeout=self.request_timeout
                    )
                except requests.exceptions.RequestException:
                    try:
                        response = session.get(
                            current_url,
                            allow_redirects=False,
                            timeout=self.request_timeout,
                            stream=True
                        )
                    except requests.exceptions.RequestException as e:
                        result['expansion_error'] = f'Erreur de connexion: {str(e)[:100]}'
                        break
                
                redirect_info = {
                    'url': current_url,
                    'status_code': response.status_code,
                    'is_shortener': self.is_shortened_url(current_url)[0]
                }
                
                if 300 <= response.status_code < 400:
                    next_url = response.headers.get('Location')
                    if next_url:
                        if not next_url.startswith('http'):
                            next_url = urljoin(current_url, next_url)
                        
                        redirect_info['redirects_to'] = next_url
                        redirect_info['redirect_type'] = f'HTTP {response.status_code}'
                        redirect_chain.append(redirect_info)
                        
                        if next_url not in result['all_urls']:
                            result['all_urls'].append(next_url)
                        
                        current_url = next_url
                        continue
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' in content_type:
                        try:
                            if hasattr(response, 'text'):
                                content = response.text[:50000]
                            else:
                                get_response = session.get(
                                    current_url,
                                    timeout=self.request_timeout
                                )
                                content = get_response.text[:50000]
                                get_response.close()
                            
                            meta_redirect = self._find_meta_redirect(content, current_url)
                            if meta_redirect:
                                redirect_info['redirects_to'] = meta_redirect
                                redirect_info['redirect_type'] = 'Meta Refresh'
                                redirect_chain.append(redirect_info)
                                
                                if meta_redirect not in result['all_urls']:
                                    result['all_urls'].append(meta_redirect)
                                
                                current_url = meta_redirect
                                continue
                            
                            js_redirect = self._find_js_redirect(content, current_url)
                            if js_redirect:
                                redirect_info['redirects_to'] = js_redirect
                                redirect_info['redirect_type'] = 'JavaScript'
                                redirect_chain.append(redirect_info)
                                
                                if js_redirect not in result['all_urls']:
                                    result['all_urls'].append(js_redirect)
                                
                                current_url = js_redirect
                                continue
                        except Exception:
                            pass
                
                redirect_chain.append(redirect_info)
                result['final_url'] = current_url
                break
            
            session.close()
            
            result['redirect_chain'] = redirect_chain
            result['redirect_count'] = len([r for r in redirect_chain if r.get('redirects_to')])
            
            shorteners_in_chain = [
                r['url'] for r in redirect_chain 
                if r.get('is_shortener')
            ]
            result['shorteners_found'] = shorteners_in_chain
            result['multiple_shorteners'] = len(shorteners_in_chain) > 1
            
        except Exception as e:
            result['expansion_error'] = f'Erreur inattendue: {str(e)[:100]}'
        
        return result
    
    def _create_session(self):
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
        })
        return session
    
    def _find_meta_redirect(self, html_content, base_url):
        patterns = [
            r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d*;?\s*url\s*=\s*["\']?([^"\'>\s;]+)',
            r'<meta[^>]*content\s*=\s*["\']?\d*;?\s*url\s*=\s*["\']?([^"\'>\s;]+)[^>]*http-equiv\s*=\s*["\']?refresh',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
            if match:
                url = match.group(1).strip().strip('"\'')
                if not url.startswith('http'):
                    url = urljoin(base_url, url)
                return url
        return None
    
    def _find_js_redirect(self, html_content, base_url):
        patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html_content, re.IGNORECASE)
            if match:
                url = match.group(1).strip()
                if url.startswith('http'):
                    return url
                elif url.startswith('/'):
                    return urljoin(base_url, url)
        return None
    
    def analyze_with_security_apis(self, url_or_expansion_result, security_analyzer=None):
        if isinstance(url_or_expansion_result, str):
            expansion = self.expand_url(url_or_expansion_result)
        else:
            expansion = url_or_expansion_result
        
        result = {
            'expansion': expansion,
            'security_analysis': {
                'original_url': None,
                'final_url': None,
                'intermediate_urls': []
            },
            'overall_threat_detected': False,
            'highest_threat_level': 'sûr',
            'threats_found': []
        }
        
        if not security_analyzer:
            from services.security.analyzer import SecurityAnalyzerService
            security_analyzer = SecurityAnalyzerService()
        
        threat_levels_priority = {'sûr': 0, 'inconnu': 1, 'modéré': 2, 'élevé': 3, 'critique': 4}
        
        urls_to_check = []
        
        original_url = expansion['original_url']
        final_url = expansion['final_url']
        
        urls_to_check.append(('original', original_url))
        
        if final_url and final_url != original_url:
            urls_to_check.append(('final', final_url))
        
        for redirect in expansion.get('redirect_chain', []):
            url = redirect.get('url')
            if url and url not in [original_url, final_url]:
                urls_to_check.append(('intermediate', url))
        
        def analyze_single_url(url_type, url):
            try:
                analysis = security_analyzer.analyze(url, 'url')
                return url_type, url, analysis
            except Exception as e:
                return url_type, url, {'error': True, 'message': str(e)}
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(analyze_single_url, url_type, url): (url_type, url)
                for url_type, url in urls_to_check
            }
            
            for future in as_completed(futures):
                url_type, url, analysis = future.result()
                
                if url_type == 'original':
                    result['security_analysis']['original_url'] = {
                        'url': url,
                        'analysis': analysis
                    }
                elif url_type == 'final':
                    result['security_analysis']['final_url'] = {
                        'url': url,
                        'analysis': analysis
                    }
                else:
                    result['security_analysis']['intermediate_urls'].append({
                        'url': url,
                        'analysis': analysis
                    })
                
                if not analysis.get('error') and analysis.get('threat_detected'):
                    result['overall_threat_detected'] = True
                    
                    threat_level = analysis.get('threat_level', 'inconnu')
                    if threat_levels_priority.get(threat_level, 0) > threat_levels_priority.get(result['highest_threat_level'], 0):
                        result['highest_threat_level'] = threat_level
                    
                    result['threats_found'].append({
                        'url': url,
                        'url_type': url_type,
                        'threat_level': threat_level,
                        'sources': analysis.get('source_results', {})
                    })
        
        return result
    
    def get_shortener_info(self, domain):
        shortener_info = {
            'bit.ly': {'name': 'Bitly', 'type': 'general', 'risk': 'low'},
            'tinyurl.com': {'name': 'TinyURL', 'type': 'general', 'risk': 'low'},
            't.co': {'name': 'Twitter/X', 'type': 'social', 'risk': 'low'},
            'goo.gl': {'name': 'Google', 'type': 'general', 'risk': 'low'},
            'ow.ly': {'name': 'Hootsuite', 'type': 'social', 'risk': 'low'},
            'buff.ly': {'name': 'Buffer', 'type': 'social', 'risk': 'low'},
            'adf.ly': {'name': 'AdFly', 'type': 'monetized', 'risk': 'medium'},
            'ouo.io': {'name': 'Ouo.io', 'type': 'monetized', 'risk': 'medium'},
            'bc.vc': {'name': 'bc.vc', 'type': 'monetized', 'risk': 'medium'},
            'sh.st': {'name': 'Shorte.st', 'type': 'monetized', 'risk': 'medium'},
            'youtu.be': {'name': 'YouTube', 'type': 'media', 'risk': 'low'},
            'amzn.to': {'name': 'Amazon', 'type': 'commerce', 'risk': 'low'},
            'linktr.ee': {'name': 'Linktree', 'type': 'aggregator', 'risk': 'low'},
        }
        
        domain_lower = domain.lower() if domain else ''
        return shortener_info.get(domain_lower, {
            'name': domain,
            'type': 'unknown',
            'risk': 'unknown'
        })
