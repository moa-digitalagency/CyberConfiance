#!/usr/bin/env python3
"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Verification des variables d'environnement requises au demarrage.
S'assure que toutes les variables critiques sont configurees.
"""

import os
import sys

# Liste des variables d'environnement requises pour le déploiement
REQUIRED_ENV_VARS = {
    'ADMIN_PASSWORD': 'Mot de passe administrateur (requis en production)',
    'DATABASE_URL': 'URL de la base de données PostgreSQL',
}

# APIs de sécurité - vérifiées séparément avec indication du service
SECURITY_API_VARS = {
    'SECURITY_ANALYSIS_API_KEY': {
        'service': 'VirusTotal',
        'description': 'Analyse de fichiers/URLs avec 70+ moteurs antivirus',
        'url': 'https://www.virustotal.com/gui/join-us',
        'required': True
    },
    'SECURITY_ANALYSIS_API_KEY_1': {
        'service': 'Google Safe Browsing',
        'description': 'Detection de phishing et malware en temps reel',
        'url': 'https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com',
        'required': False
    },
    'SECURITY_ANALYSIS_API_KEY_2': {
        'service': 'URLhaus (abuse.ch)',
        'description': 'Base de donnees de distribution de malware',
        'url': 'https://urlhaus.abuse.ch/',
        'required': False
    },
    'SECURITY_ANALYSIS_API_KEY_3': {
        'service': 'URLScan.io',
        'description': 'Analyse comportementale avec screenshot et detection de trackers',
        'url': 'https://urlscan.io/user/signup',
        'required': False
    },
    'HIBP_API_KEY': {
        'service': 'Have I Been Pwned',
        'description': 'Verification des fuites de donnees par email',
        'url': 'https://haveibeenpwned.com/API/Key',
        'required': False
    },
}

# Variables optionnelles mais recommandées
RECOMMENDED_ENV_VARS = {
    'FLASK_DEBUG': 'Mode debug Flask (False en production)',
}

# Variables optionnelles pour fonctionnalités avancées
OPTIONAL_ENV_VARS = {
    'SECRET_KEY': 'Clé secrète Flask pour les sessions (générée automatiquement si absente)',
}

def check_environment_variables():
    """Vérifie que toutes les variables d'environnement requises sont définies."""
    missing_vars = []
    missing_recommended = []
    missing_required_apis = []
    missing_optional_apis = []
    configured_apis = []
    
    is_deployment = os.environ.get('REPLIT_DEPLOYMENT') == '1'
    
    print("=" * 80)
    print("VERIFICATION DES VARIABLES D'ENVIRONNEMENT - CYBERCONFIANCE")
    print(f"Mode: {'PRODUCTION (Deploiement)' if is_deployment else 'DEVELOPPEMENT'}")
    print("=" * 80)
    
    print("\n[SECTION 1] Variables systeme requises:")
    print("-" * 50)
    for var_name, description in REQUIRED_ENV_VARS.items():
        value = os.environ.get(var_name)
        if not value:
            if is_deployment:
                missing_vars.append((var_name, description))
                print(f"  [X] {var_name}: MANQUANT")
                print(f"      -> {description}")
            else:
                print(f"  [!] {var_name}: Non defini (OK en dev)")
        else:
            print(f"  [OK] {var_name}: Configure")
    
    print("\n[SECTION 2] APIs de securite:")
    print("-" * 50)
    for var_name, config in SECURITY_API_VARS.items():
        value = os.environ.get(var_name)
        service = config['service']
        description = config['description']
        is_required = config['required']
        api_url = config['url']
        
        if value:
            configured_apis.append((var_name, service))
            print(f"  [OK] {service}")
            print(f"      Variable: {var_name}")
            print(f"      Fonction: {description}")
        else:
            if is_required:
                missing_required_apis.append((var_name, service, description, api_url))
                status = "[X] REQUIS - MANQUANT" if is_deployment else "[!] REQUIS - Non defini"
            else:
                missing_optional_apis.append((var_name, service, description, api_url))
                status = "[~] Optionnel - Non configure"
            
            print(f"  {status}: {service}")
            print(f"      Variable: {var_name}")
            print(f"      Fonction: {description}")
    
    print("\n[SECTION 3] Variables recommandees:")
    print("-" * 50)
    for var_name, description in RECOMMENDED_ENV_VARS.items():
        value = os.environ.get(var_name)
        if not value:
            missing_recommended.append((var_name, description))
            print(f"  [!] {var_name}: Non defini - {description}")
        else:
            print(f"  [OK] {var_name}: Configure")
    
    print("\n[SECTION 4] Variables optionnelles:")
    print("-" * 50)
    for var_name, description in OPTIONAL_ENV_VARS.items():
        value = os.environ.get(var_name)
        if not value:
            print(f"  [i] {var_name}: Non defini (generation auto)")
        else:
            print(f"  [OK] {var_name}: Configure")
    
    print("\n" + "=" * 80)
    print("RESUME DE LA CONFIGURATION")
    print("=" * 80)
    
    total_apis = len(SECURITY_API_VARS)
    configured_count = len(configured_apis)
    print(f"\n  APIs configurees: {configured_count}/{total_apis}")
    
    if configured_apis:
        print("  Services actifs:")
        for var_name, service in configured_apis:
            print(f"    - {service}")
    
    if missing_optional_apis:
        print(f"\n  APIs optionnelles non configurees ({len(missing_optional_apis)}):")
        for var_name, service, desc, url in missing_optional_apis:
            print(f"    - {service}: {desc}")
            print(f"      Obtenir: {url}")
    
    if is_deployment and (missing_vars or missing_required_apis):
        print("\n" + "=" * 80)
        print("[ERREUR CRITIQUE] Configuration incomplete pour la production!")
        print("=" * 80)
        
        if missing_vars:
            print("\nVariables systeme manquantes:")
            for var_name, description in missing_vars:
                print(f"  - {var_name}: {description}")
        
        if missing_required_apis:
            print("\nAPIs de securite requises manquantes:")
            for var_name, service, desc, url in missing_required_apis:
                print(f"  - {var_name} ({service})")
                print(f"    Obtenir la cle: {url}")
        
        print("\nPour configurer:")
        print("1. Onglet 'Deployments' > 'Add deployment secret'")
        print("2. Ajoutez chaque variable manquante")
        print("\n" + "=" * 80)
        sys.exit(1)
    
    if configured_count == 0 and is_deployment:
        print("\n[AVERTISSEMENT] Aucune API de securite configuree!")
        print("L'application fonctionnera avec des fonctionnalites limitees.")
    
    print("\n[OK] Verification terminee avec succes!")
    print("=" * 80 + "\n")
    return True

if __name__ == '__main__':
    check_environment_variables()
