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
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Admin settings
    FLASK_ADMIN_SWATCH = 'cerulean'
    
    # Application settings
    APP_NAME = 'CyberConfiance'
    APP_DESCRIPTION = 'Plateforme de sensibilisation à la cybersécurité'
