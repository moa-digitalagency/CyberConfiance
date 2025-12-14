import vt
import os
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse
from services.security.google_safe_browsing import GoogleSafeBrowsingService
from services.security.urlhaus import URLhausService
from services.security.url_shortener import URLShortenerService
from services.security.urlscan import URLScanService
from services.security.tracker_detector import TrackerDetectorService

class SecurityAnalyzerService:
    """Service for analyzing security threats using multiple sources"""
    
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY') or os.environ.get('VT_API_KEY')
        self.google_safe_browsing = GoogleSafeBrowsingService()
        self.urlhaus = URLhausService()
        self.url_shortener = URLShortenerService()
        self.urlscan = URLScanService()
        self.tracker_detector = TrackerDetectorService()
        
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
        """Analyze a URL using multiple sources (VirusTotal, Google Safe Browsing, URLhaus)"""
        import time
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        shortener_info = {
            'is_shortened': False,
            'shortener_service': None,
            'original_url': url,
            'final_url': url,
            'redirect_chain': [],
            'redirect_count': 0,
            'all_urls_analyzed': []
        }
        
        is_shortened, shortener_service = self.url_shortener.is_shortened_url(url)
        if is_shortened:
            print(f"[INFO] URL raccourcie detectee: {url} (service: {shortener_service})")
            expansion = self.url_shortener.expand_url(url)
            shortener_info['is_shortened'] = True
            shortener_info['shortener_service'] = shortener_service
            shortener_info['shortener_details'] = self.url_shortener.get_shortener_info(shortener_service)
            shortener_info['final_url'] = expansion.get('final_url', url)
            shortener_info['redirect_chain'] = expansion.get('redirect_chain', [])
            shortener_info['redirect_count'] = expansion.get('redirect_count', 0)
            shortener_info['all_urls'] = expansion.get('all_urls', [url])
            shortener_info['multiple_shorteners'] = expansion.get('multiple_shorteners', False)
            shortener_info['expansion_error'] = expansion.get('expansion_error')
            
            if shortener_info['final_url'] != url:
                print(f"[INFO] URL finale apres expansion: {shortener_info['final_url']}")
        
        url_to_analyze = shortener_info['final_url'] if is_shortened else url
        
        multi_source_results = {
            'virustotal': None,
            'google_safe_browsing': None,
            'urlhaus': None,
            'urlscan': None,
            'tracker_detector': None
        }
        
        def check_google_safe_browsing():
            try:
                return self.google_safe_browsing.check_url(url_to_analyze)
            except Exception as e:
                print(f"[ERROR] Google Safe Browsing check failed: {e}")
                return {'error': True, 'source': 'google_safe_browsing', 'message': str(e)}
        
        def check_urlhaus():
            try:
                return self.urlhaus.check_url(url_to_analyze)
            except Exception as e:
                print(f"[ERROR] URLhaus check failed: {e}")
                return {'error': True, 'source': 'urlhaus', 'message': str(e)}
        
        def check_urlscan():
            try:
                if self.urlscan.is_available():
                    return self.urlscan.scan_url(url_to_analyze)
                return {'error': True, 'source': 'urlscan', 'message': 'URLScan.io non configuré'}
            except Exception as e:
                print(f"[ERROR] URLScan check failed: {e}")
                return {'error': True, 'source': 'urlscan', 'message': str(e)}
        
        def check_tracker_detector():
            try:
                result = self.tracker_detector.analyze_url(url_to_analyze)
                if shortener_info.get('redirect_chain'):
                    chain_analysis = self.tracker_detector.analyze_redirect_chain(shortener_info['redirect_chain'])
                    result['chain_analysis'] = chain_analysis
                return result
            except Exception as e:
                print(f"[ERROR] Tracker detector check failed: {e}")
                return {'error': True, 'source': 'tracker_detector', 'message': str(e)}
        
        multi_source_results['tracker_detector'] = check_tracker_detector()
        print(f"[INFO] tracker_detector result: is_ip_logger={multi_source_results['tracker_detector'].get('is_ip_logger', False)}")
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(check_google_safe_browsing): 'google_safe_browsing',
                executor.submit(check_urlhaus): 'urlhaus',
                executor.submit(check_urlscan): 'urlscan'
            }
            for future in as_completed(futures):
                source = futures[future]
                try:
                    multi_source_results[source] = future.result()
                    if source == 'urlscan':
                        print(f"[INFO] {source} result: threat_score={multi_source_results[source].get('threat_score', 0)}")
                    else:
                        print(f"[INFO] {source} result: threat_detected={multi_source_results[source].get('threat_detected', False)}")
                except Exception as e:
                    print(f"[ERROR] {source} future failed: {e}")
                    multi_source_results[source] = {'error': True, 'source': source, 'message': str(e)}
        
        try:
            url_id = vt.url_id(url_to_analyze)
            url_obj = None
            stats = None
            
            try:
                url_obj = client.get_object(f"/urls/{url_id}")
                stats = url_obj.last_analysis_stats
                print(f"[INFO] URL found in VirusTotal database: {url_to_analyze}")
            except vt.APIError as e:
                if 'NotFoundError' in str(e):
                    print(f"[INFO] URL not in VirusTotal database, submitting for scan: {url_to_analyze}")
                    try:
                        analysis = client.scan_url(url_to_analyze)
                        analysis_id = analysis.id
                        print(f"[INFO] URL scan submitted, analysis ID: {analysis_id}")
                        
                        max_attempts = 12
                        for attempt in range(max_attempts):
                            time.sleep(5)
                            try:
                                analysis_obj = client.get_object(f"/analyses/{analysis_id}")
                                status = analysis_obj.status
                                print(f"[INFO] Analysis status (attempt {attempt+1}): {status}")
                                
                                if status == "completed":
                                    url_obj = client.get_object(f"/urls/{url_id}")
                                    stats = url_obj.last_analysis_stats
                                    break
                            except Exception as poll_error:
                                print(f"[WARN] Polling error: {str(poll_error)}")
                                continue
                    except Exception as scan_error:
                        print(f"[ERROR] VirusTotal URL scan failed: {str(scan_error)}")
                else:
                    raise e
            
            if stats:
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values())
                
                multi_source_results['virustotal'] = {
                    'error': False,
                    'source': 'virustotal',
                    'found': True,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'total': total,
                    'clean': stats.get('harmless', 0) + stats.get('undetected', 0),
                    'stats': stats,
                    'categories': url_obj.get('categories', {}) if url_obj else {},
                    'times_submitted': url_obj.get('times_submitted', 0) if url_obj else 0,
                    'threat_detected': malicious > 0 or suspicious > 0,
                    'threat_level': self._calculate_threat_level(malicious, suspicious, total)
                }
            else:
                multi_source_results['virustotal'] = {
                    'error': False,
                    'source': 'virustotal',
                    'found': False,
                    'threat_detected': False,
                    'threat_level': 'inconnu',
                    'message': 'Analyse en cours ou URL non trouvée'
                }
            
        except Exception as e:
            print(f"[ERROR] VirusTotal analysis failed: {e}")
            multi_source_results['virustotal'] = {
                'error': True,
                'source': 'virustotal',
                'message': str(e)
            }
        
        combined_result = self._combine_url_results(url, multi_source_results, shortener_info)
        return combined_result
    
    def _combine_url_results(self, url, multi_source_results, shortener_info=None):
        """Combine results from all security analysis sources"""
        
        sources_checked = 0
        sources_with_threat = 0
        all_threats = []
        highest_threat_level = 'sûr'
        threat_levels_priority = {'sûr': 0, 'inconnu': 1, 'modéré': 2, 'élevé': 3, 'critique': 4}
        
        if shortener_info is None:
            shortener_info = {'is_shortened': False}
        
        vt_result = multi_source_results.get('virustotal', {})
        vt_malicious = 0
        vt_suspicious = 0
        vt_total = 0
        vt_stats = {}
        vt_categories = {}
        
        if vt_result and not vt_result.get('error'):
            sources_checked += 1
            if vt_result.get('threat_detected'):
                sources_with_threat += 1
                all_threats.append({
                    'source': 'VirusTotal',
                    'type': 'malware/phishing',
                    'details': f"{vt_result.get('malicious', 0)} malveillants, {vt_result.get('suspicious', 0)} suspects"
                })
            vt_malicious = vt_result.get('malicious', 0)
            vt_suspicious = vt_result.get('suspicious', 0)
            vt_total = vt_result.get('total', 0)
            vt_stats = vt_result.get('stats', {})
            vt_categories = vt_result.get('categories', {})
            
            vt_level = vt_result.get('threat_level', 'sûr')
            if threat_levels_priority.get(vt_level, 0) > threat_levels_priority.get(highest_threat_level, 0):
                highest_threat_level = vt_level
        
        gsb_result = multi_source_results.get('google_safe_browsing', {})
        gsb_threats = []
        
        if gsb_result and not gsb_result.get('error'):
            sources_checked += 1
            if gsb_result.get('threat_detected'):
                sources_with_threat += 1
                gsb_threats = gsb_result.get('threats', [])
                threat_types = gsb_result.get('threat_types', [])
                for threat_type in threat_types:
                    all_threats.append({
                        'source': 'Google Safe Browsing',
                        'type': self.google_safe_browsing.get_threat_description(threat_type),
                        'details': threat_type
                    })
                
                gsb_level = gsb_result.get('threat_level', 'sûr')
                if threat_levels_priority.get(gsb_level, 0) > threat_levels_priority.get(highest_threat_level, 0):
                    highest_threat_level = gsb_level
        
        urlhaus_result = multi_source_results.get('urlhaus', {})
        urlhaus_info = {}
        
        if urlhaus_result and not urlhaus_result.get('error'):
            sources_checked += 1
            if urlhaus_result.get('threat_detected'):
                sources_with_threat += 1
                urlhaus_info = {
                    'threat_type': urlhaus_result.get('threat_type', ''),
                    'url_status': urlhaus_result.get('url_status', ''),
                    'tags': urlhaus_result.get('tags', []),
                    'payloads': urlhaus_result.get('payloads', [])
                }
                all_threats.append({
                    'source': 'URLhaus',
                    'type': self.urlhaus.get_threat_description(urlhaus_result.get('threat_type', '')),
                    'details': f"Status: {urlhaus_result.get('url_status', 'unknown')}"
                })
                
                urlhaus_level = urlhaus_result.get('threat_level', 'sûr')
                if threat_levels_priority.get(urlhaus_level, 0) > threat_levels_priority.get(highest_threat_level, 0):
                    highest_threat_level = urlhaus_level
        
        urlscan_result = multi_source_results.get('urlscan', {})
        urlscan_info = {}
        
        if urlscan_result and not urlscan_result.get('error'):
            sources_checked += 1
            urlscan_info = {
                'uuid': urlscan_result.get('uuid', ''),
                'result_url': urlscan_result.get('result_url', ''),
                'screenshot_url': urlscan_result.get('screenshot_url', ''),
                'threat_score': urlscan_result.get('threat_score', 0),
                'page': urlscan_result.get('page', {}),
                'stats': urlscan_result.get('stats', {}),
                'verdicts': urlscan_result.get('verdicts', {}),
                'brands_detected': urlscan_result.get('brands_detected', []),
                'trackers_detected': urlscan_result.get('trackers_detected', []),
                'ip_logger_indicators': urlscan_result.get('ip_logger_indicators', [])
            }
            
            if urlscan_result.get('threat_detected') or urlscan_result.get('threat_score', 0) > 25:
                sources_with_threat += 1
                all_threats.append({
                    'source': 'URLScan.io',
                    'type': 'Analyse comportementale',
                    'details': f"Score: {urlscan_result.get('threat_score', 0)}/100"
                })
                
                urlscan_level = urlscan_result.get('threat_level', 'sûr')
                urlscan_level_map = {'safe': 'sûr', 'low': 'modéré', 'medium': 'modéré', 'high': 'élevé', 'critical': 'critique'}
                urlscan_level = urlscan_level_map.get(urlscan_level, 'sûr')
                if threat_levels_priority.get(urlscan_level, 0) > threat_levels_priority.get(highest_threat_level, 0):
                    highest_threat_level = urlscan_level
            
            if urlscan_result.get('brands_detected'):
                all_threats.append({
                    'source': 'URLScan.io',
                    'type': 'Usurpation de marque',
                    'details': f"Marques: {', '.join(urlscan_result.get('brands_detected', [])[:3])}"
                })
        
        tracker_result = multi_source_results.get('tracker_detector', {})
        tracker_info = {}
        
        if tracker_result and not tracker_result.get('error'):
            sources_checked += 1
            tracker_info = {
                'is_ip_logger': tracker_result.get('is_ip_logger', False),
                'is_tracker': tracker_result.get('is_tracker', False),
                'is_ad_network': tracker_result.get('is_ad_network', False),
                'has_fingerprinting': tracker_result.get('has_fingerprinting', False),
                'has_tracking_params': tracker_result.get('has_tracking_params', False),
                'threat_score': tracker_result.get('threat_score', 0),
                'detections': tracker_result.get('detections', []),
                'tracking_params_found': tracker_result.get('tracking_params_found', []),
                'recommendations': tracker_result.get('recommendations', []),
                'chain_analysis': tracker_result.get('chain_analysis', {})
            }
            
            if tracker_result.get('is_ip_logger'):
                sources_with_threat += 1
                all_threats.append({
                    'source': 'Détecteur de Trackers',
                    'type': 'IP Logger détecté',
                    'details': 'Ce lien capture votre adresse IP et localisation'
                })
                highest_threat_level = 'critique'
            elif tracker_result.get('has_fingerprinting'):
                sources_with_threat += 1
                all_threats.append({
                    'source': 'Détecteur de Trackers',
                    'type': 'Fingerprinting détecté',
                    'details': 'Ce site identifie votre appareil de manière unique'
                })
                if threat_levels_priority.get('élevé', 0) > threat_levels_priority.get(highest_threat_level, 0):
                    highest_threat_level = 'élevé'
            elif tracker_result.get('is_tracker'):
                all_threats.append({
                    'source': 'Détecteur de Trackers',
                    'type': 'Trackers détectés',
                    'details': f"{len(tracker_result.get('detections', []))} élément(s) de suivi"
                })
            
            chain_analysis = tracker_result.get('chain_analysis', {})
            if chain_analysis.get('ip_loggers_found'):
                for logger in chain_analysis.get('ip_loggers_found', []):
                    all_threats.append({
                        'source': 'Analyse chaîne redirection',
                        'type': 'IP Logger dans redirection',
                        'details': f"Étape {logger.get('step', '?')}: IP logger détecté"
                    })
                highest_threat_level = 'critique'
        
        overall_threat_detected = sources_with_threat > 0
        
        confidence_score = 0
        if sources_checked > 0:
            if sources_with_threat == 0:
                confidence_score = min(100, sources_checked * 33)
            else:
                confidence_score = min(100, (sources_with_threat / sources_checked) * 100)
        
        result = {
            'error': False,
            'found': True,
            'type': 'url',
            'url': url,
            'malicious': vt_malicious,
            'suspicious': vt_suspicious,
            'total': vt_total,
            'clean': vt_stats.get('harmless', 0) + vt_stats.get('undetected', 0),
            'stats': vt_stats,
            'categories': vt_categories,
            'times_submitted': vt_result.get('times_submitted', 0) if vt_result else 0,
            'threat_detected': overall_threat_detected,
            'threat_level': highest_threat_level,
            'multi_source': True,
            'sources_checked': sources_checked,
            'sources_with_threat': sources_with_threat,
            'all_threats': all_threats,
            'confidence_score': confidence_score,
            'source_results': {
                'virustotal': {
                    'available': vt_result and not vt_result.get('error'),
                    'threat_detected': vt_result.get('threat_detected', False) if vt_result else False,
                    'malicious': vt_malicious,
                    'suspicious': vt_suspicious,
                    'total': vt_total
                },
                'google_safe_browsing': {
                    'available': gsb_result and not gsb_result.get('error'),
                    'threat_detected': gsb_result.get('threat_detected', False) if gsb_result else False,
                    'threats': gsb_threats
                },
                'urlhaus': {
                    'available': urlhaus_result and not urlhaus_result.get('error'),
                    'threat_detected': urlhaus_result.get('threat_detected', False) if urlhaus_result else False,
                    'info': urlhaus_info
                },
                'urlscan': {
                    'available': urlscan_result and not urlscan_result.get('error'),
                    'threat_detected': urlscan_result.get('threat_detected', False) if urlscan_result else False,
                    'threat_score': urlscan_info.get('threat_score', 0),
                    'info': urlscan_info
                },
                'tracker_detector': {
                    'available': tracker_result and not tracker_result.get('error'),
                    'is_ip_logger': tracker_info.get('is_ip_logger', False),
                    'is_tracker': tracker_info.get('is_tracker', False),
                    'has_fingerprinting': tracker_info.get('has_fingerprinting', False),
                    'threat_score': tracker_info.get('threat_score', 0),
                    'info': tracker_info
                }
            }
        }
        
        if shortener_info.get('is_shortened'):
            result['url_shortener'] = {
                'detected': True,
                'service': shortener_info.get('shortener_service'),
                'service_details': shortener_info.get('shortener_details', {}),
                'original_url': shortener_info.get('original_url'),
                'final_url': shortener_info.get('final_url'),
                'redirect_chain': shortener_info.get('redirect_chain', []),
                'redirect_count': shortener_info.get('redirect_count', 0),
                'multiple_shorteners': shortener_info.get('multiple_shorteners', False),
                'expansion_error': shortener_info.get('expansion_error')
            }
            if shortener_info.get('multiple_shorteners'):
                all_threats.append({
                    'source': 'URL Shortener Detection',
                    'type': 'Raccourcisseurs multiples',
                    'details': 'Plusieurs services de raccourcissement detectes dans la chaine de redirection'
                })
        else:
            result['url_shortener'] = {'detected': False}
        
        return result
    
    def _calculate_threat_level(self, malicious, suspicious, total):
        """Calculate threat level based on detection ratios
        
        Business rule: ANY detection (malicious or suspicious > 0) must be at least 'modéré'
        """
        if total == 0:
            return 'inconnu'
        
        if malicious > 0 or suspicious > 0:
            malicious_ratio = malicious / total
            suspicious_ratio = suspicious / total
            combined_ratio = malicious_ratio + (suspicious_ratio * 0.5)
            
            if combined_ratio >= 0.5:
                return 'critique'
            elif combined_ratio >= 0.25:
                return 'élevé'
            else:
                return 'modéré'
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
