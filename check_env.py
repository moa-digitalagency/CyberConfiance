#!/usr/bin/env python3
"""
Script de vérification des variables d'environnement requises.
Ce script s'exécute au démarrage pour s'assurer que toutes les variables
d'environnement critiques sont configurées avant le lancement de l'application.
"""
import os
import sys

# Liste des variables d'environnement requises pour le déploiement
REQUIRED_ENV_VARS = {
    'ADMIN_PASSWORD': 'Mot de passe administrateur (requis en production)',
    'HIBP_API_KEY': 'Clé API Have I Been Pwned pour vérifier les emails compromis (~$3.50/mois - https://haveibeenpwned.com/API/Key)',
}

# Variables optionnelles mais recommandées
RECOMMENDED_ENV_VARS = {
    'FLASK_DEBUG': 'Mode debug Flask (False en production)',
    'DATABASE_URL': 'URL de la base de données PostgreSQL',
}

# Variables optionnelles pour fonctionnalités avancées
OPTIONAL_ENV_VARS = {
    'SECRET_KEY': 'Clé secrète Flask pour les sessions (générée automatiquement si absente)',
}

def check_environment_variables():
    """Vérifie que toutes les variables d'environnement requises sont définies."""
    missing_vars = []
    missing_recommended = []
    
    # Vérifier si on est en mode déploiement
    is_deployment = os.environ.get('REPLIT_DEPLOYMENT') == '1'
    
    print("=" * 80)
    print("🔍 Vérification des variables d'environnement...")
    print(f"Mode: {'PRODUCTION (Déploiement)' if is_deployment else 'DÉVELOPPEMENT'}")
    print("=" * 80)
    
    # Vérifier les variables requises
    for var_name, description in REQUIRED_ENV_VARS.items():
        value = os.environ.get(var_name)
        if not value:
            if is_deployment:
                missing_vars.append((var_name, description))
                print(f"❌ {var_name}: MANQUANT - {description}")
            else:
                print(f"⚠️  {var_name}: Non défini (OK en dev) - {description}")
        else:
            print(f"✅ {var_name}: Configuré")
    
    # Vérifier les variables recommandées
    print("\nVariables recommandées:")
    for var_name, description in RECOMMENDED_ENV_VARS.items():
        value = os.environ.get(var_name)
        if not value:
            missing_recommended.append((var_name, description))
            print(f"⚠️  {var_name}: Non défini - {description}")
        else:
            print(f"✅ {var_name}: Configuré")
    
    # Vérifier les variables optionnelles
    print("\nVariables optionnelles (fonctionnalités avancées):")
    for var_name, description in OPTIONAL_ENV_VARS.items():
        value = os.environ.get(var_name)
        if not value:
            print(f"ℹ️  {var_name}: Non défini - {description}")
        else:
            print(f"✅ {var_name}: Configuré")
    
    print("=" * 80)
    
    # En mode production/déploiement, les variables requises doivent être présentes
    if is_deployment and missing_vars:
        print("\n🚨 ERREUR CRITIQUE: Variables d'environnement manquantes en production!")
        print("\nPour configurer les secrets de déploiement:")
        print("1. Allez dans l'onglet 'Deployments' de votre Repl")
        print("2. Cliquez sur 'Add deployment secret'")
        print("3. Ajoutez les variables suivantes:")
        print()
        for var_name, description in missing_vars:
            print(f"   - {var_name}: {description}")
        print("\n" + "=" * 80)
        sys.exit(1)
    
    if missing_recommended:
        print("\n💡 Recommandation: Configurez les variables suivantes pour un meilleur contrôle:")
        for var_name, description in missing_recommended:
            print(f"   - {var_name}: {description}")
    
    print("\n✅ Vérification terminée avec succès!")
    print("=" * 80 + "\n")
    return True

if __name__ == '__main__':
    check_environment_variables()
