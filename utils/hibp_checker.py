"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier hibp_checker.py du projet CyberConfiance
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

Module pour verifier les mots de passe et emails compromis via Have I Been Pwned API.
Documentation: https://haveibeenpwned.com/API/v3
"""

import hashlib
import os
import requests
from typing import Tuple, Optional


class HIBPChecker:
    """Vérificateur de mots de passe et emails compromis via Have I Been Pwned."""
    
    PWNED_PASSWORDS_API = "https://api.pwnedpasswords.com/range/"
    BREACH_API = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialise le vérificateur HIBP.
        
        Args:
            api_key: Clé API HIBP (optionnelle, requise uniquement pour la vérification d'emails)
        """
        self.api_key = api_key or os.environ.get('HIBP_API_KEY')
    
    def check_password(self, password: str) -> Tuple[bool, int]:
        """
        Vérifie si un mot de passe a été compromis dans des fuites de données.
        Utilise l'API Pwned Passwords (GRATUITE, anonyme, k-anonymity).
        
        Args:
            password: Le mot de passe à vérifier
            
        Returns:
            Tuple (is_pwned: bool, count: int)
            - is_pwned: True si le mot de passe a été trouvé dans des fuites
            - count: Nombre de fois que le mot de passe a été vu dans les fuites
        
        Exemple:
            >>> checker = HIBPChecker()
            >>> is_pwned, count = checker.check_password("password123")
            >>> if is_pwned:
            ...     print(f"[!] Ce mot de passe a été trouvé {count} fois dans des fuites!")
        """
        try:
            # Hacher le mot de passe en SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Utiliser k-anonymity: envoyer seulement les 5 premiers caractères
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Requête à l'API Pwned Passwords (pas besoin de clé API)
            response = requests.get(
                f"{self.PWNED_PASSWORDS_API}{prefix}",
                headers={'User-Agent': 'CyberConfiance-Password-Checker'},
                timeout=5
            )
            
            if response.status_code == 200:
                # Chercher le suffixe dans la réponse
                hashes = response.text.splitlines()
                for line in hashes:
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return True, int(count)
                
                # Mot de passe non trouvé dans les fuites
                return False, 0
            else:
                print(f"[!] Erreur API HIBP: {response.status_code}")
                return False, 0
                
        except Exception as e:
            print(f"[!] Erreur lors de la vérification du mot de passe: {e}")
            return False, 0
    
    def check_email(self, email: str) -> Tuple[bool, list]:
        """
        Vérifie si un email a été compromis dans des fuites de données.
        ATTENTION: Nécessite une clé API HIBP payante (~$3.50/mois).
        
        Args:
            email: L'adresse email à vérifier
            
        Returns:
            Tuple (is_pwned: bool, breaches: list)
            - is_pwned: True si l'email a été trouvé dans des fuites
            - breaches: Liste des noms de fuites où l'email a été trouvé
        
        Exemple:
            >>> checker = HIBPChecker(api_key="votre_cle_api")
            >>> is_pwned, breaches = checker.check_email("test@example.com")
            >>> if is_pwned:
            ...     print(f"[!] Email trouvé dans {len(breaches)} fuites: {breaches}")
        """
        if not self.api_key:
            print("[!] Clé API HIBP non configurée. Vérification d'email impossible.")
            print("   Pour obtenir une clé: https://haveibeenpwned.com/API/Key")
            return False, []
        
        try:
            headers = {
                'hibp-api-key': self.api_key,
                'User-Agent': 'CyberConfiance-Email-Checker'
            }
            
            response = requests.get(
                f"{self.BREACH_API}{email}",
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                breaches_data = response.json()
                breach_names = [breach['Name'] for breach in breaches_data]
                return True, breach_names
            elif response.status_code == 404:
                # Aucune fuite trouvée pour cet email
                return False, []
            else:
                print(f"[!] Erreur API HIBP: {response.status_code}")
                return False, []
                
        except Exception as e:
            print(f"[!] Erreur lors de la vérification de l'email: {e}")
            return False, []
    
    def get_password_strength_message(self, password: str) -> dict:
        """
        Évalue la force d'un mot de passe et retourne un message détaillé.
        
        Args:
            password: Le mot de passe à évaluer
            
        Returns:
            dict avec 'is_safe', 'level', 'message', 'suggestions'
        """
        is_pwned, count = self.check_password(password)
        
        # Critères de base
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        suggestions = []
        
        if is_pwned:
            return {
                'is_safe': False,
                'level': 'danger',
                'message': f'DANGER: Ce mot de passe a été trouvé {count:,} fois dans des fuites de données!',
                'suggestions': ['Choisissez un mot de passe complètement différent', 
                               'Ne réutilisez jamais un mot de passe compromis']
            }
        
        if length < 8:
            suggestions.append('Utilisez au moins 12 caractères')
        if not has_upper:
            suggestions.append('Ajoutez des lettres majuscules')
        if not has_lower:
            suggestions.append('Ajoutez des lettres minuscules')
        if not has_digit:
            suggestions.append('Ajoutez des chiffres')
        if not has_special:
            suggestions.append('Ajoutez des caractères spéciaux (!@#$%^&*)')
        
        # Évaluer la force
        criteria_met = sum([has_upper, has_lower, has_digit, has_special])
        
        if length >= 12 and criteria_met >= 3:
            return {
                'is_safe': True,
                'level': 'success',
                'message': 'Excellent! Ce mot de passe est fort et n\'a pas été compromis.',
                'suggestions': []
            }
        elif length >= 8 and criteria_met >= 2:
            return {
                'is_safe': True,
                'level': 'warning',
                'message': 'Bon mot de passe, mais peut être amélioré.',
                'suggestions': suggestions
            }
        else:
            return {
                'is_safe': False,
                'level': 'danger',
                'message': 'Mot de passe faible. Améliorez-le pour votre sécurité.',
                'suggestions': suggestions
            }


# Fonction helper pour usage rapide
def check_password_safety(password: str) -> dict:
    """
    Fonction utilitaire pour vérifier rapidement un mot de passe.
    
    Args:
        password: Le mot de passe à vérifier
        
    Returns:
        dict avec les informations de sécurité
    """
    checker = HIBPChecker()
    return checker.get_password_strength_message(password)
