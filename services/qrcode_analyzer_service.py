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

Wrapper sécurisé pour le service QRCodeAnalyzerService.
Assure que les erreurs de bas niveau (ex: cv2/pyzbar) ne font pas crasher l'application.
"""

from services.qrcode.analyzer import QRCodeAnalyzerService as _BaseQRCodeAnalyzerService
from utils.logger import get_logger

logger = get_logger(__name__)

class QRCodeAnalyzerService(_BaseQRCodeAnalyzerService):
    """
    Wrapper pour QRCodeAnalyzerService qui assure une gestion robuste des erreurs
    et empeche les exceptions de remonter jusqu'au controlleur.
    """

    def analyze_qr_image(self, image_data, filename=None):
        try:
            # Appel de la methode parente
            result = super().analyze_qr_image(image_data, filename)

            # Si le resultat est None (ce qui ne devrait pas arriver mais sait-on jamais)
            if result is None:
                logger.error("QRCodeAnalyzerService: analyze_qr_image returned None")
                return {
                    'success': False,
                    'error': "Erreur interne: aucun resultat retourne par le service d'analyse",
                    'issues': []
                }

            return result

        except Exception as e:
            # Catch global des exceptions (y compris celles lancees par cv2/pyzbar wrappees par Python)
            logger.error(f"Erreur critique dans le wrapper QRCodeAnalyzerService (cv2/PIL/pyzbar): {e}")
            return {
                'success': False,
                'error': f"Erreur lors de l'analyse QR code (fichier corrompu ou illisible): {e}",
                'issues': []
            }

__all__ = ['QRCodeAnalyzerService']
