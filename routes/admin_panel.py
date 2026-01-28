"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier admin_panel.py du projet CyberConfiance
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

Re-export du module admin pour compatibilite.
"""

from routes.admin import bp, admin_required, moderator_required
