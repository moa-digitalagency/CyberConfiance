"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier virustotal.py du projet CyberConfiance
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

Client API VirusTotal pour analyse de menaces.
"""

import os
import vt
import hashlib
import re
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from utils.logger import get_logger

logger = get_logger(__name__)

class VirusTotalService:
    def __init__(self):
        self.api_key = os.environ.get('SECURITY_ANALYSIS_API_KEY') or os.environ.get('VT_API_KEY')
        self.client = None
        if self.api_key:
            try:
                self.client = vt.Client(self.api_key)
            except Exception as e:
                logger.error(f"Security analysis client initialization failed: {e}")
    
    def is_available(self) -> bool:
        return self.client is not None
    
    def scan_url(self, url: str) -> Tuple[bool, Dict]:
        if not self.is_available():
            return False, {"error": "Security analysis API not configured"}
        
        try:
            url_id = vt.url_id(url)
            url_object = self.client.get_object(f"/urls/{url_id}")
            
            stats = url_object.last_analysis_stats
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            threat_detected = malicious_count > 0 or suspicious_count > 2
            
            return threat_detected, {
                'malicious': malicious_count,
                'suspicious': suspicious_count,
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total': total,
                'permalink': f"https://www.virustotal.com/gui/url/{url_id}"
            }
        except vt.error.APIError as e:
            if e.code == 'NotFoundError':
                analysis = self.client.scan_url(url)
                return False, {
                    'status': 'queued',
                    'analysis_id': analysis.id,
                    'message': 'URL queued for analysis'
                }
            return False, {"error": str(e)}
        except Exception as e:
            return False, {"error": str(e)}
    
    def scan_file(self, file_path: str) -> Tuple[bool, Dict]:
        if not self.is_available():
            return False, {"error": "Security analysis API not configured"}
        
        try:
            file_hash = self._get_file_hash(file_path)
            
            try:
                file_object = self.client.get_object(f"/files/{file_hash}")
            except vt.error.APIError as e:
                if e.code == 'NotFoundError':
                    with open(file_path, 'rb') as f:
                        analysis = self.client.scan_file(f)
                    return False, {
                        'status': 'queued',
                        'analysis_id': analysis.id,
                        'message': 'File queued for analysis'
                    }
                raise
            
            stats = file_object.last_analysis_stats
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            total = sum(stats.values())
            
            threat_detected = malicious_count > 0 or suspicious_count > 2
            
            return threat_detected, {
                'malicious': malicious_count,
                'suspicious': suspicious_count,
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'total': total,
                'hash': file_hash,
                'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        except Exception as e:
            return False, {"error": str(e)}
    
    def scan_text(self, text: str) -> Tuple[bool, List[str]]:
        if not self.is_available():
            return False, []
        
        threats = []
        urls = self._extract_urls(text)
        
        def safe_scan(target_url):
            try:
                detected, _ = self.scan_url(target_url)
                return target_url if detected else None
            except:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(urls) or 1)) as executor:
            futures = [executor.submit(safe_scan, url) for url in urls]
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        threats.append(result)
                except:
                    pass
        
        suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onload\s*=',
            r'eval\(',
            r'document\.write',
            r'innerHTML\s*=',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                threats.append(f"Suspicious pattern detected: {pattern}")
        
        return len(threats) > 0, threats
    
    def _get_file_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _extract_urls(self, text: str) -> List[str]:
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def __del__(self):
        if self.client:
            self.client.close()
