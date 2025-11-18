# ✅ Checklist de Déploiement - CyberConfiance

## 🚨 Variables OBLIGATOIRES (bloquent le déploiement si absentes)

### 1. ADMIN_PASSWORD
- **Statut**: ❌ OBLIGATOIRE EN PRODUCTION
- **Comportement**: 
  - En développement: Avertissement affiché, utilise "admin123" par défaut
  - En production: ❌ **L'APPLICATION REFUSE DE DÉMARRER**
- **Comment configurer**:
  ```
  Deployments → Add deployment secret
  Nom: ADMIN_PASSWORD
  Valeur: VotreMotDePasseSécurisé123!
  ```

### 2. HIBP_API_KEY
- **Statut**: ❌ OBLIGATOIRE EN PRODUCTION
- **Raison**: La page d'accueil utilise cette fonctionnalité avec le champ "Vérifiez si votre email a été compromis"
- **Comportement**:
  - En développement: Avertissement affiché, la fonction retourne une erreur "Clé API non configurée"
  - En production: ❌ **L'APPLICATION REFUSE DE DÉMARRER**
- **Comment obtenir**:
  1. Allez sur https://haveibeenpwned.com/API/Key
  2. Entrez votre email et vérifiez-le
  3. Payez ~$3.50/mois pour l'abonnement
  4. Recevez la clé par email
- **Comment configurer**:
  ```
  Deployments → Add deployment secret
  Nom: HIBP_API_KEY
  Valeur: votre_clé_reçue_par_email
  ```

---

## ⚠️ Variables RECOMMANDÉES

### 3. FLASK_DEBUG
- **Recommandation**: Configurez à `False` en production
- **Par défaut**: False (sécurisé)
- **Comportement**: Si True en production, affiche des informations sensibles en cas d'erreur

### 4. DATABASE_URL
- **Recommandation**: Utilisez PostgreSQL en production
- **Par défaut**: SQLite local (non recommandé pour production)
- **Format**: `postgresql://user:password@host:port/database`

---

## ℹ️ Variables OPTIONNELLES

### 5. SECRET_KEY
- **Description**: Clé secrète pour signer les sessions Flask
- **Par défaut**: Générée automatiquement à chaque démarrage
- **Recommandation**: Définissez une clé fixe en production pour que les sessions persistent après redémarrage

---

## 🎯 Simulation du comportement

### En DÉVELOPPEMENT (maintenant):
```
================================================================================
🔍 Vérification des variables d'environnement...
Mode: DÉVELOPPEMENT
================================================================================
⚠️  ADMIN_PASSWORD: Non défini (OK en dev)
⚠️  HIBP_API_KEY: Non défini (OK en dev)
Variables recommandées:
⚠️  FLASK_DEBUG: Non défini
✅ DATABASE_URL: Configuré
Variables optionnelles:
ℹ️  SECRET_KEY: Non défini
================================================================================
✅ Vérification terminée avec succès!
```
→ L'application démarre normalement avec des avertissements

### En PRODUCTION (sans les clés):
```
================================================================================
🔍 Vérification des variables d'environnement...
Mode: PRODUCTION (Déploiement)
================================================================================
❌ ADMIN_PASSWORD: MANQUANT - Mot de passe administrateur (requis en production)
❌ HIBP_API_KEY: MANQUANT - Clé API Have I Been Pwned pour vérifier les emails compromis
================================================================================

🚨 ERREUR CRITIQUE: Variables d'environnement manquantes en production!

Pour configurer les secrets de déploiement:
1. Allez dans l'onglet 'Deployments' de votre Repl
2. Cliquez sur 'Add deployment secret'
3. Ajoutez les variables suivantes:

   - ADMIN_PASSWORD: Mot de passe administrateur (requis en production)
   - HIBP_API_KEY: Clé API Have I Been Pwned pour vérifier les emails compromis

================================================================================
```
→ ❌ **L'APPLICATION REFUSE DE DÉMARRER** (exit code 1)

### En PRODUCTION (avec les clés):
```
================================================================================
🔍 Vérification des variables d'environnement...
Mode: PRODUCTION (Déploiement)
================================================================================
✅ ADMIN_PASSWORD: Configuré
✅ HIBP_API_KEY: Configuré
Variables recommandées:
✅ FLASK_DEBUG: Configuré
✅ DATABASE_URL: Configuré
Variables optionnelles:
✅ SECRET_KEY: Configuré
================================================================================
✅ Vérification terminée avec succès!
```
→ ✅ L'application démarre normalement

---

## 📋 Instructions de déploiement

1. **Obtenir une clé HIBP** (si pas déjà fait)
   - Visitez: https://haveibeenpwned.com/API/Key
   - Coût: ~$3.50/mois
   - Temps: ~5 minutes

2. **Configurer les secrets dans Replit**
   - Allez dans "Deployments"
   - Cliquez "Add deployment secret" pour chaque variable:
     - `ADMIN_PASSWORD` = votre mot de passe sécurisé
     - `HIBP_API_KEY` = votre clé HIBP

3. **Déployer**
   - Cliquez sur "Deploy"
   - Le script check_env.py vérifiera automatiquement
   - Si tout est OK: ✅ Déploiement réussi
   - Si manquant: ❌ Erreur explicite avec instructions

---

## 🔒 Sécurité

✅ **Ce qui est protégé**:
- Impossible de déployer sans mot de passe admin sécurisé
- Impossible de déployer sans clé HIBP (fonction critique sur la page d'accueil)
- Messages d'erreur clairs avec instructions

❌ **Ce qui n'est PAS envoyé sur Internet**:
- Votre ADMIN_PASSWORD reste dans Replit Secrets
- Votre HIBP_API_KEY reste dans Replit Secrets
- Ces valeurs ne sont jamais commitées dans le code

---

## 📞 Support

Si vous rencontrez des problèmes:
1. Vérifiez que les secrets sont bien configurés dans l'onglet Deployments
2. Vérifiez que les noms correspondent exactement (sensible à la casse)
3. Relancez le déploiement après avoir ajouté les secrets
4. Consultez les logs de déploiement pour voir les messages d'erreur détaillés
