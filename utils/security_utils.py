"""
 * Nom de l'application : CyberConfiance
 * Description : Utilitaires de sécurité pour la validation et l'assainissement.
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com
"""

import socket
import ipaddress
from urllib.parse import urlparse

def is_safe_url_strict(check_url):
    """
    Strictly validates a URL to prevent SSRF and DNS Rebinding.
    Resolves the hostname and checks if it points to a private/reserved IP.
    """
    try:
        parsed = urlparse(check_url)
        if parsed.scheme not in ['http', 'https']:
            return False

        if parsed.username or parsed.password:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Block localhost and obvious internal names
        if hostname.lower() in ['localhost', '127.0.0.1', '0.0.0.0', '::1', '0:0:0:0:0:0:0:1']:
            return False

        if hostname == '169.254.169.254': # Cloud metadata
            return False

        if hostname.endswith('.local') or hostname.endswith('.internal'):
            return False

        # DNS Resolution and IP Check
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for info in addr_info:
                resolved_ip_str = info[4][0]
                # Remove scope ID if present (IPv6)
                if '%' in resolved_ip_str:
                    resolved_ip_str = resolved_ip_str.split('%')[0]

                ip = ipaddress.ip_address(resolved_ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    return False
        except (socket.gaierror, ValueError, OSError):
            return False

        return True
    except Exception:
        return False
