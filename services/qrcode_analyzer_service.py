"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier qrcode_analyzer_service.py du projet CyberConfiance
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

Re-export du service QRCodeAnalyzerService pour compatibilite.
"""

from services.qrcode.analyzer import QRCodeAnalyzerService

__all__ = ['QRCodeAnalyzerService']
