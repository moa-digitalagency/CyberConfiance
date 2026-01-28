"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier tracker_detector.py du projet CyberConfiance
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

Detecteur de trackers et IP loggers.
"""

import os
import re
import requests
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime


class TrackerDetectorService:
    """
    Service de détection exhaustive des trackers, IP loggers et liens de suivi.
    Combine analyse de patterns, liste noire de domaines et heuristiques avancées.
    """
    
    def __init__(self):
        self.ip_logger_domains = [
            'grabify.link', 'grabify.org', 'grabify.icu',
            'iplogger.org', 'iplogger.com', 'iplogger.co', 'iplogger.info',
            '2no.co', '02444.link',
            'blasze.com', 'blasze.tk',
            'yip.su',
            'ps3cfw.com', 'ps3cfw.xyz',
            'lovebird.guru',
            'iptrackeronline.com',
            'ipgrabber.ru',
            'iplis.ru', 'ipclick.info',
            'tracker.gg',
            'goo.by',
            'shorturl.gg',
            'webresolver.nl',
            'resolveme.host',
            'ipsnoop.com',
            'grabtheip.com',
            'whatstheirip.com',
            'ip-logger.com',
            'ip-trap.com',
            'ip-grabber.com',
            'ezstat.ru',
            'statclick.ru',
            'yourmy.de',
            'myiptest.com',
            'iplink.nl'
        ]
        
        self.tracker_domains = [
            'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
            'google-analytics.com', 'analytics.google.com',
            'facebook.com/tr', 'pixel.facebook.com', 'connect.facebook.net',
            'analytics.twitter.com', 't.co/i',
            'ads.linkedin.com', 'px.ads.linkedin.com',
            'bat.bing.com', 'clarity.ms',
            'hotjar.com', 'static.hotjar.com',
            'mixpanel.com', 'api.mixpanel.com',
            'amplitude.com', 'api.amplitude.com',
            'segment.com', 'api.segment.io',
            'hubspot.com', 'tracking.hubspot.com',
            'marketo.com', 'mktoresp.com',
            'pardot.com',
            'intercom.io', 'widget.intercom.io',
            'drift.com', 'js.driftt.com',
            'crisp.chat',
            'zendesk.com',
            'freshdesk.com',
            'tawk.to',
            'livechatinc.com',
            'olark.com',
            'mouseflow.com',
            'fullstory.com',
            'logrocket.com', 'cdn.lr-ingest.io',
            'heap.io', 'heapanalytics.com',
            'crazyegg.com',
            'luckyorange.com',
            'clicktale.net',
            'optimizely.com',
            'quantserve.com', 'quantcast.com',
            'scorecardresearch.com',
            'comscore.com',
            'newrelic.com',
            'nr-data.net',
            'datadoghq.com',
            'bugsnag.com',
            'sentry.io',
            'rollbar.com',
            'raygun.io',
            'appsflyer.com',
            'adjust.com',
            'branch.io',
            'kochava.com',
            'singular.net',
            'tenjin.io'
        ]
        
        self.ad_network_domains = [
            'adnxs.com', 'adsrvr.org', 'adform.net',
            'criteo.com', 'criteo.net',
            'taboola.com', 'outbrain.com',
            'amazon-adsystem.com',
            'pubmatic.com', 'rubiconproject.com',
            'openx.net', 'casalemedia.com',
            'advertising.com', 'aol.com/ads',
            'adroll.com',
            'mediamath.com',
            'thetradedesk.com',
            'liveramp.com',
            'tapad.com',
            'lotame.com',
            'bluekai.com', 'oraclecloud.com/ad',
            'exelator.com',
            'eyeota.net',
            'rlcdn.com',
            'crwdcntrl.net'
        ]
        
        self.fingerprinting_indicators = [
            'fingerprintjs', 'fpjs.io', 'fp.js',
            'canvas-fingerprint', 'webgl-fingerprint',
            'audio-fingerprint', 'font-fingerprint',
            'browserleaks', 'deviceinfo',
            'bot-detection', 'anti-fraud',
            'clientjs', 'evercookie',
            'supercookie', 'zombie-cookie'
        ]
        
        self.suspicious_params = [
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'gclid', 'fbclid', 'msclkid', 'twclid', 'li_fat_id',
            'mc_cid', 'mc_eid',
            '_ga', '_gid', '_gac',
            'ref', 'referrer', 'source', 'affiliate',
            'click_id', 'clickid', 'clid',
            'tracking_id', 'track', 'tracker',
            'campaign_id', 'cmp', 'promo',
            'session_id', 'sid', 'uid', 'uuid',
            'visitor_id', 'vid',
            'token', 'auth', 'key'
        ]
        
        self.pixel_patterns = [
            r'\.gif\?.*tracking',
            r'\.png\?.*pixel',
            r'pixel\..*\?',
            r'track\..*\?',
            r'beacon\.',
            r'1x1\.',
            r'transparent\.(gif|png)',
            r'spacer\.(gif|png)',
            r'/pixel/',
            r'/beacon/',
            r'/track/',
            r'__utm\.gif',
            r'collect\?.*tid=',
            r'tr\?.*ev=',
            r'bat\.bing\.com/action'
        ]
    
    def analyze_url(self, url: str) -> Dict:
        """
        Analyse complète d'une URL pour détecter les trackers et IP loggers
        
        Args:
            url: URL à analyser
            
        Returns:
            dict: Résultats d'analyse avec tous les indicateurs
        """
        result = {
            'url': url,
            'is_ip_logger': False,
            'is_tracker': False,
            'is_ad_network': False,
            'has_fingerprinting': False,
            'has_tracking_params': False,
            'has_pixel_tracking': False,
            'threat_level': 'safe',
            'threat_score': 0,
            'detections': [],
            'tracking_params_found': [],
            'recommendations': []
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            full_url_lower = url.lower()
            
            ip_logger_check = self._check_ip_logger(domain, full_url_lower)
            if ip_logger_check['detected']:
                result['is_ip_logger'] = True
                result['threat_score'] += 80
                result['detections'].extend(ip_logger_check['matches'])
            
            tracker_check = self._check_trackers(domain, full_url_lower)
            if tracker_check['detected']:
                result['is_tracker'] = True
                result['threat_score'] += 30
                result['detections'].extend(tracker_check['matches'])
            
            ad_check = self._check_ad_networks(domain, full_url_lower)
            if ad_check['detected']:
                result['is_ad_network'] = True
                result['threat_score'] += 20
                result['detections'].extend(ad_check['matches'])
            
            fingerprint_check = self._check_fingerprinting(full_url_lower)
            if fingerprint_check['detected']:
                result['has_fingerprinting'] = True
                result['threat_score'] += 50
                result['detections'].extend(fingerprint_check['matches'])
            
            params_check = self._check_tracking_params(parsed.query)
            if params_check['detected']:
                result['has_tracking_params'] = True
                result['threat_score'] += 10
                result['tracking_params_found'] = params_check['params']
            
            pixel_check = self._check_pixel_tracking(full_url_lower)
            if pixel_check['detected']:
                result['has_pixel_tracking'] = True
                result['threat_score'] += 25
                result['detections'].extend(pixel_check['matches'])
            
            result['threat_level'] = self._calculate_threat_level(result['threat_score'])
            result['recommendations'] = self._generate_recommendations(result)
            
        except Exception as e:
            result['error'] = f'Erreur analyse: {str(e)}'
        
        return result
    
    def analyze_redirect_chain(self, redirect_chain: List[Dict]) -> Dict:
        """
        Analyse une chaîne de redirection complète pour les trackers
        
        Args:
            redirect_chain: Liste des URLs dans la chaîne de redirection
            
        Returns:
            dict: Analyse globale de la chaîne
        """
        result = {
            'total_urls': len(redirect_chain),
            'ip_loggers_found': [],
            'trackers_found': [],
            'tracking_params_all': [],
            'suspicious_redirects': [],
            'threat_level': 'safe',
            'threat_score': 0,
            'summary': []
        }
        
        for idx, redirect in enumerate(redirect_chain):
            url = redirect.get('url', '')
            analysis = self.analyze_url(url)
            
            if analysis.get('is_ip_logger'):
                result['ip_loggers_found'].append({
                    'step': idx + 1,
                    'url': url,
                    'detections': analysis.get('detections', [])
                })
                result['threat_score'] += 80
            
            if analysis.get('is_tracker'):
                result['trackers_found'].append({
                    'step': idx + 1,
                    'url': url,
                    'detections': analysis.get('detections', [])
                })
                result['threat_score'] += 20
            
            if analysis.get('tracking_params_found'):
                result['tracking_params_all'].extend(analysis['tracking_params_found'])
            
            if analysis.get('threat_score', 0) > 30:
                result['suspicious_redirects'].append({
                    'step': idx + 1,
                    'url': url,
                    'score': analysis.get('threat_score', 0),
                    'level': analysis.get('threat_level', 'unknown')
                })
        
        result['threat_level'] = self._calculate_threat_level(result['threat_score'])
        result['summary'] = self._generate_chain_summary(result)
        
        return result
    
    def analyze_html_content(self, html_content: str, base_url: str = '') -> Dict:
        """
        Analyse le contenu HTML pour détecter les trackers intégrés
        
        Args:
            html_content: Contenu HTML de la page
            base_url: URL de base pour contexte
            
        Returns:
            dict: Trackers et pixels détectés dans le HTML
        """
        result = {
            'tracking_scripts': [],
            'tracking_pixels': [],
            'fingerprinting_scripts': [],
            'hidden_iframes': [],
            'suspicious_forms': [],
            'threat_score': 0
        }
        
        try:
            script_pattern = r'<script[^>]*src\s*=\s*["\']([^"\']+)["\'][^>]*>'
            scripts = re.findall(script_pattern, html_content, re.IGNORECASE)
            
            for script_url in scripts:
                script_lower = script_url.lower()
                
                for tracker in self.tracker_domains:
                    if tracker in script_lower:
                        result['tracking_scripts'].append({
                            'url': script_url,
                            'type': 'tracker',
                            'service': tracker
                        })
                        result['threat_score'] += 15
                        break
                
                for indicator in self.fingerprinting_indicators:
                    if indicator in script_lower:
                        result['fingerprinting_scripts'].append({
                            'url': script_url,
                            'indicator': indicator
                        })
                        result['threat_score'] += 40
                        break
            
            img_pattern = r'<img[^>]*src\s*=\s*["\']([^"\']+)["\'][^>]*(?:width\s*=\s*["\']?1|height\s*=\s*["\']?1|style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden))'
            tracking_pixels = re.findall(img_pattern, html_content, re.IGNORECASE)
            
            for pixel_url in tracking_pixels:
                result['tracking_pixels'].append({
                    'url': pixel_url,
                    'type': 'invisible_pixel'
                })
                result['threat_score'] += 20
            
            iframe_pattern = r'<iframe[^>]*(?:width\s*=\s*["\']?[01]|height\s*=\s*["\']?[01]|style\s*=\s*["\'][^"\']*display\s*:\s*none)[^>]*src\s*=\s*["\']([^"\']+)["\']'
            hidden_iframes = re.findall(iframe_pattern, html_content, re.IGNORECASE)
            
            for iframe_url in hidden_iframes:
                result['hidden_iframes'].append({
                    'url': iframe_url,
                    'type': 'hidden_iframe'
                })
                result['threat_score'] += 30
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _check_ip_logger(self, domain: str, url: str) -> Dict:
        """Vérifie si l'URL est un IP logger connu"""
        matches = []
        
        for logger_domain in self.ip_logger_domains:
            if logger_domain in domain or logger_domain in url:
                matches.append({
                    'type': 'ip_logger',
                    'severity': 'critical',
                    'domain': logger_domain,
                    'message': f'IP Logger détecté: {logger_domain}'
                })
        
        return {
            'detected': len(matches) > 0,
            'matches': matches
        }
    
    def _check_trackers(self, domain: str, url: str) -> Dict:
        """Vérifie la présence de trackers connus"""
        matches = []
        
        for tracker in self.tracker_domains:
            if tracker in domain or tracker in url:
                matches.append({
                    'type': 'tracker',
                    'severity': 'medium',
                    'domain': tracker,
                    'message': f'Tracker détecté: {tracker}'
                })
        
        return {
            'detected': len(matches) > 0,
            'matches': matches
        }
    
    def _check_ad_networks(self, domain: str, url: str) -> Dict:
        """Vérifie la présence de réseaux publicitaires"""
        matches = []
        
        for ad_domain in self.ad_network_domains:
            if ad_domain in domain or ad_domain in url:
                matches.append({
                    'type': 'ad_network',
                    'severity': 'low',
                    'domain': ad_domain,
                    'message': f'Réseau publicitaire: {ad_domain}'
                })
        
        return {
            'detected': len(matches) > 0,
            'matches': matches
        }
    
    def _check_fingerprinting(self, url: str) -> Dict:
        """Vérifie les indicateurs de fingerprinting"""
        matches = []
        
        for indicator in self.fingerprinting_indicators:
            if indicator in url:
                matches.append({
                    'type': 'fingerprinting',
                    'severity': 'high',
                    'indicator': indicator,
                    'message': f'Fingerprinting détecté: {indicator}'
                })
        
        return {
            'detected': len(matches) > 0,
            'matches': matches
        }
    
    def _check_tracking_params(self, query_string: str) -> Dict:
        """Vérifie les paramètres de tracking dans l'URL"""
        params_found = []
        
        if not query_string:
            return {'detected': False, 'params': []}
        
        try:
            params = parse_qs(query_string)
            for param_name in params.keys():
                param_lower = param_name.lower()
                for suspicious in self.suspicious_params:
                    if suspicious in param_lower:
                        params_found.append({
                            'name': param_name,
                            'type': suspicious,
                            'value_length': len(str(params[param_name]))
                        })
                        break
        except:
            pass
        
        return {
            'detected': len(params_found) > 0,
            'params': params_found
        }
    
    def _check_pixel_tracking(self, url: str) -> Dict:
        """Vérifie les patterns de pixel tracking"""
        matches = []
        
        for pattern in self.pixel_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                matches.append({
                    'type': 'pixel_tracking',
                    'severity': 'medium',
                    'pattern': pattern,
                    'message': 'Pixel de tracking détecté'
                })
        
        return {
            'detected': len(matches) > 0,
            'matches': matches
        }
    
    def _calculate_threat_level(self, score: int) -> str:
        """Calcule le niveau de menace basé sur le score"""
        if score >= 80:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 30:
            return 'medium'
        elif score >= 10:
            return 'low'
        return 'safe'
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Génère des recommandations basées sur l'analyse"""
        recommendations = []
        
        if analysis.get('is_ip_logger'):
            recommendations.append("DANGER: Ne cliquez pas sur ce lien - votre adresse IP sera enregistrée")
            recommendations.append("Ce lien provient d'un service de tracking d'IP connu")
            recommendations.append("Ne partagez pas ce lien avec d'autres personnes")
        
        if analysis.get('is_tracker'):
            recommendations.append("Ce lien contient des trackers qui collectent vos données")
            recommendations.append("Utilisez un bloqueur de trackers ou un VPN")
        
        if analysis.get('has_fingerprinting'):
            recommendations.append("Ce site utilise des techniques d'empreinte numérique")
            recommendations.append("Votre navigateur peut être identifié de manière unique")
        
        if analysis.get('has_tracking_params'):
            recommendations.append("L'URL contient des paramètres de suivi marketing")
            recommendations.append("Vous pouvez supprimer ces paramètres pour plus de confidentialité")
        
        if not recommendations:
            recommendations.append("Aucun tracker majeur détecté dans cette URL")
        
        return recommendations
    
    def _generate_chain_summary(self, chain_result: Dict) -> List[str]:
        """Génère un résumé de l'analyse de chaîne de redirection"""
        summary = []
        
        if chain_result['ip_loggers_found']:
            summary.append(f"🚨 {len(chain_result['ip_loggers_found'])} IP logger(s) détecté(s) dans la chaîne")
        
        if chain_result['trackers_found']:
            summary.append(f"⚠️ {len(chain_result['trackers_found'])} tracker(s) détecté(s)")
        
        if chain_result['suspicious_redirects']:
            summary.append(f"🔍 {len(chain_result['suspicious_redirects'])} redirection(s) suspecte(s)")
        
        if chain_result['tracking_params_all']:
            unique_params = list(set([p.get('type', '') for p in chain_result['tracking_params_all']]))
            summary.append(f"📊 Paramètres de tracking: {', '.join(unique_params[:5])}")
        
        if not summary:
            summary.append("✅ Aucun tracker détecté dans la chaîne de redirection")
        
        return summary
    
    def get_ip_logger_info(self, domain: str) -> Optional[Dict]:
        """Obtient les informations sur un IP logger connu"""
        ip_logger_info = {
            'grabify.link': {
                'name': 'Grabify',
                'risk': 'critical',
                'description': 'Service populaire de tracking d\'IP, capture IP, localisation, user-agent',
                'data_collected': ['IP', 'Localisation', 'Navigateur', 'OS', 'Résolution écran']
            },
            'grabify.org': {
                'name': 'Grabify',
                'risk': 'critical',
                'description': 'Service populaire de tracking d\'IP',
                'data_collected': ['IP', 'Localisation', 'Navigateur', 'OS']
            },
            'iplogger.org': {
                'name': 'IPLogger',
                'risk': 'critical',
                'description': 'Service de logging d\'IP avec raccourcisseur d\'URL',
                'data_collected': ['IP', 'Localisation', 'FAI', 'Navigateur']
            },
            '2no.co': {
                'name': 'Grabify (alias)',
                'risk': 'critical',
                'description': 'Domaine alternatif de Grabify',
                'data_collected': ['IP', 'Localisation', 'Navigateur']
            },
            'blasze.tk': {
                'name': 'Blasze',
                'risk': 'high',
                'description': 'Service de tracking d\'IP',
                'data_collected': ['IP', 'Localisation']
            },
            'yip.su': {
                'name': 'YIP.SU',
                'risk': 'high',
                'description': 'Raccourcisseur d\'URL avec tracking',
                'data_collected': ['IP', 'Référent']
            }
        }
        
        domain_lower = domain.lower()
        for logger_domain, info in ip_logger_info.items():
            if logger_domain in domain_lower:
                return info
        
        return None
