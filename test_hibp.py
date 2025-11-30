#!/usr/bin/env python3
"""
Script de test pour vérifier le fonctionnement de l'API Have I Been Pwned.
"""
from utils.hibp_checker import HIBPChecker, check_password_safety

def test_password_checker():
    """Test de la vérification de mots de passe."""
    print("=" * 80)
    print("🔍 Test de l'API Have I Been Pwned - Vérification de mots de passe")
    print("=" * 80)
    
    checker = HIBPChecker()
    
    # Test avec des mots de passe connus comme compromis
    test_passwords = [
        ("password123", "Très commun"),
        ("qwerty", "Clavier simple"),
        ("MyS3cur3P@ssw0rd!2024", "Fort et unique"),
        ("admin", "Trop simple"),
    ]
    
    for password, description in test_passwords:
        print(f"\n🔐 Test: ({description})")
        print("-" * 80)
        
        # Vérification simple
        is_pwned, count = checker.check_password(password)
        
        if is_pwned:
            print(f"   ❌ COMPROMIS: Trouvé {count:,} fois dans des fuites de données")
        else:
            print(f"   ✅ SÉCURISÉ: Pas trouvé dans les fuites connues")
        
        # Analyse complète
        result = check_password_safety(password)
        print(f"   📊 Niveau: {result['level'].upper()}")
        print(f"   💬 {result['message']}")
        
        if result['suggestions']:
            print(f"   💡 Suggestions:")
            for suggestion in result['suggestions']:
                print(f"      - {suggestion}")
    
    print("\n" + "=" * 80)
    print("✅ Tests terminés!")
    print("\nℹ️  Note: La vérification de mots de passe via HIBP est 100% gratuite")
    print("   et utilise k-anonymity (votre mot de passe n'est jamais envoyé)")
    print("=" * 80)

def test_email_checker():
    """Test de la vérification d'emails (nécessite une clé API)."""
    import os
    
    print("\n" + "=" * 80)
    print("📧 Test de vérification d'emails")
    print("=" * 80)
    
    api_key = os.environ.get('HIBP_API_KEY')
    
    if not api_key:
        print("⚠️  Clé API HIBP non configurée")
        print("   Pour tester la vérification d'emails:")
        print("   1. Obtenez une clé sur: https://haveibeenpwned.com/API/Key")
        print("   2. Configurez: export HIBP_API_KEY='votre_cle'")
        print("   3. Relancez ce script")
        return
    
    checker = HIBPChecker(api_key)
    test_email = "test@example.com"
    
    print(f"\n🔍 Vérification de: {test_email}")
    is_pwned, breaches = checker.check_email(test_email)
    
    if is_pwned:
        print(f"   ❌ Email trouvé dans {len(breaches)} fuite(s):")
        for breach in breaches[:5]:  # Afficher max 5
            print(f"      - {breach}")
        if len(breaches) > 5:
            print(f"      ... et {len(breaches) - 5} autre(s)")
    else:
        print("   ✅ Email non trouvé dans les fuites connues")
    
    print("=" * 80)

if __name__ == '__main__':
    test_password_checker()
    test_email_checker()
