"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier config.py du projet CyberConfiance
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

Configuration de l'application Flask.
Charge les variables d'environnement et definit les parametres.
"""

import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Force PostgreSQL usage
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if not SQLALCHEMY_DATABASE_URI:
        raise ValueError("DATABASE_URL is not set. PostgreSQL is required.")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Admin settings
    FLASK_ADMIN_SWATCH = 'cerulean'
    
    # Application settings
    APP_NAME = 'CyberConfiance'
    APP_DESCRIPTION = 'Plateforme de sensibilisation à la cybersécurité'

    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
