# Guide de Sécurité - CyberConfiance

## 🔒 Vérification des mots de passe compromis

CyberConfiance intègre l'API **Have I Been Pwned** pour protéger vos utilisateurs contre les mots de passe compromis.

### Fonctionnalités disponibles

#### ✅ Vérification de mots de passe (GRATUIT)
- **Coût**: Totalement gratuit
- **Fonctionnement**: Utilise k-anonymity (votre mot de passe n'est jamais envoyé à l'API)
- **Base de données**: Plus de 800 millions de mots de passe compromis
- **Mise à jour**: Régulièrement mise à jour avec de nouvelles fuites

#### 📧 Vérification d'emails (OPTIONNEL - Payant)
- **Coût**: ~$3.50/mois
- **Fonctionnalité**: Vérifie si une adresse email a été compromise dans des fuites
- **Configuration**: Nécessite une clé API HIBP_API_KEY
- **Obtenir une clé**: https://haveibeenpwned.com/API/Key

---

## 📚 Comment utiliser

### Exemple 1: Vérifier un mot de passe

```python
from utils.hibp_checker import HIBPChecker, check_password_safety

# Méthode simple (recommandée)
result = check_password_safety("MonMotDePasse123")

if result['is_safe']:
    print(f"✅ {result['message']}")
else:
    print(f"❌ {result['message']}")
    for suggestion in result['suggestions']:
        print(f"   💡 {suggestion}")
```

### Exemple 2: Vérification basique

```python
from utils.hibp_checker import HIBPChecker

checker = HIBPChecker()

# Vérifier si un mot de passe a été compromis
is_pwned, count = checker.check_password("password123")

if is_pwned:
    print(f"⚠️ Ce mot de passe a été vu {count:,} fois dans des fuites!")
else:
    print("✅ Mot de passe non compromis")
```

### Exemple 3: Vérifier un email (nécessite clé API)

```python
from utils.hibp_checker import HIBPChecker
import os

# Initialiser avec la clé API
api_key = os.environ.get('HIBP_API_KEY')
checker = HIBPChecker(api_key)

# Vérifier un email
is_pwned, breaches = checker.check_email("test@example.com")

if is_pwned:
    print(f"⚠️ Email trouvé dans {len(breaches)} fuite(s):")
    for breach in breaches:
        print(f"   - {breach}")
else:
    print("✅ Email non compromis")
```

---

## 🎯 Intégration dans l'application

### Lors de l'inscription d'un utilisateur

```python
from utils.hibp_checker import check_password_safety

@app.route('/register', methods=['POST'])
def register():
    password = request.form.get('password')
    
    # Vérifier le mot de passe
    password_check = check_password_safety(password)
    
    if not password_check['is_safe']:
        return render_template('register.html', 
            error=password_check['message'],
            suggestions=password_check['suggestions']
        )
    
    # Créer l'utilisateur...
```

### Lors du changement de mot de passe

```python
from utils.hibp_checker import HIBPChecker

@app.route('/change-password', methods=['POST'])
def change_password():
    new_password = request.form.get('new_password')
    
    checker = HIBPChecker()
    is_pwned, count = checker.check_password(new_password)
    
    if is_pwned:
        return jsonify({
            'error': f'Ce mot de passe a été compromis {count:,} fois. Choisissez-en un autre.',
            'pwned': True
        }), 400
    
    # Mettre à jour le mot de passe...
```

---

## 🔐 Bonnes pratiques de sécurité

### 1. Mots de passe

✅ **À FAIRE**:
- Utiliser au moins 12 caractères
- Mélanger majuscules, minuscules, chiffres et symboles
- Créer un mot de passe unique pour chaque service
- Utiliser un gestionnaire de mots de passe
- Vérifier avec Have I Been Pwned

❌ **À ÉVITER**:
- Mots du dictionnaire
- Informations personnelles (date de naissance, nom, etc.)
- Séquences simples (123456, azerty, qwerty)
- Réutiliser un mot de passe compromis
- Partager vos mots de passe

### 2. Configuration en production

**Variables d'environnement obligatoires**:
```bash
ADMIN_PASSWORD=VotreMotDePasseSecurisé123!
```

**Variables recommandées**:
```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname
FLASK_DEBUG=False
SECRET_KEY=VotreCléSecrèteAléatoire
```

**Variables optionnelles**:
```bash
HIBP_API_KEY=votre_clé_api_hibp  # Pour vérification d'emails
```

### 3. Tests avant déploiement

Testez la sécurité de votre configuration:

```bash
# Tester la vérification de mots de passe
python test_hibp.py

# Vérifier les variables d'environnement
python check_env.py
```

---

## 📊 Statistiques des tests

D'après nos tests avec l'API Have I Been Pwned:

| Mot de passe | Fois compromis | Sécurité |
|--------------|----------------|----------|
| password123  | 2,031,380      | ❌ DANGER |
| qwerty       | 21,969,901     | ❌ DANGER |
| admin        | 41,213,657     | ❌ DANGER |
| MyS3cur3P@ssw0rd!2024 | 0     | ✅ SÛR    |

**Conclusion**: Un mot de passe fort et unique est essentiel!

---

## 🛡️ Comment ça marche (k-anonymity)

Have I Been Pwned utilise une technique appelée **k-anonymity** pour protéger votre vie privée:

1. Votre mot de passe est haché en SHA-1 (ex: `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`)
2. Seuls les **5 premiers caractères** sont envoyés à l'API (ex: `5BAA6`)
3. L'API retourne tous les hashs commençant par ces 5 caractères
4. Votre application vérifie localement si le hash complet est dans la liste

**Résultat**: Votre mot de passe n'est jamais transmis sur Internet!

---

## 📞 Support et ressources

- **Documentation HIBP**: https://haveibeenpwned.com/API/v3
- **Obtenir une clé API**: https://haveibeenpwned.com/API/Key
- **FAQ**: https://support.haveibeenpwned.com
- **Test de mot de passe**: https://haveibeenpwned.com/Passwords

---

## ⚖️ Attribution

Conformément à la licence Creative Commons Attribution 4.0:

> Les données de fuites proviennent de **Have I Been Pwned** (haveibeenpwned.com)
> Créé par Troy Hunt

L'API Pwned Passwords n'a pas d'obligation d'attribution, mais elle est appréciée.
