"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier patterns.py du projet CyberConfiance
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

Patterns de detection pour l'analyseur QR code.
"""

phishing_keywords = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'password', 'banking', 'paypal', 'amazon', 'microsoft',
    'apple', 'google', 'facebook', 'instagram', 'whatsapp',
    'verification', 'suspended', 'locked', 'urgent', 'immediately',
    'wallet', 'crypto', 'bitcoin', 'coinbase', 'binance'
]

suspicious_tlds = [
    '.xyz', '.top', '.club', '.online', '.site', '.work', '.click',
    '.link', '.info', '.buzz', '.win', '.loan', '.gq', '.ml', '.cf',
    '.tk', '.ga', '.pw', '.cc', '.ws'
]

js_redirect_patterns = [
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

js_timeout_redirect_patterns = [
    (r'setTimeout\s*\(\s*(?:function\s*\(\)\s*\{[^}]*location[^}]*\}|[^,]*location[^,]*)\s*,\s*(\d+)', 'setTimeout+location'),
    (r'setInterval\s*\(\s*(?:function\s*\(\)\s*\{[^}]*location[^}]*\}|[^,]*location[^,]*)\s*,', 'setInterval+location'),
    (r'setTimeout\s*\([^)]*(?:window\.location|document\.location|location\.href)[^)]*,\s*\d+\)', 'setTimeout+redirect'),
    (r'requestAnimationFrame\s*\([^)]*(?:location|redirect)[^)]*\)', 'raf+redirect'),
]

meta_refresh_patterns = [
    r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d*;?\s*url\s*=\s*["\']?(https?://[^"\'>\s;]+)',
    r'<meta[^>]*content\s*=\s*["\']?\d*;?\s*url\s*=\s*["\']?(https?://[^"\'>\s;]+)[^>]*http-equiv\s*=\s*["\']?refresh',
]

link_redirect_patterns = [
    r'<a[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*(?:onclick|rel\s*=\s*["\']?noopener)',
    r'<link[^>]*rel\s*=\s*["\']?canonical["\']?[^>]*href\s*=\s*["\']([^"\']+)',
    r'<base[^>]*href\s*=\s*["\']([^"\']+)',
]

dangerous_patterns = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'data:text/html',
    r'vbscript:',
    r'on\w+\s*=\s*["\']',
]
