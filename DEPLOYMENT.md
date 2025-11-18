# Guide de Déploiement CyberConfiance

## Variables d'environnement requises

### Variables obligatoires pour le déploiement

Avant de déployer l'application en production, vous **devez** configurer les secrets suivants dans Replit:

1. **ADMIN_PASSWORD** (OBLIGATOIRE)
   - Description: Mot de passe de l'administrateur
   - Importance: Critique pour la sécurité
   - Comment configurer:
     1. Allez dans l'onglet "Deployments"
     2. Cliquez sur "Add deployment secret"
     3. Nom: `ADMIN_PASSWORD`
     4. Valeur: Votre mot de passe sécurisé (minimum 12 caractères recommandés)

2. **HIBP_API_KEY** (OBLIGATOIRE)
   - Description: Clé API Have I Been Pwned pour la fonctionnalité "Vérifiez si votre email a été compromis"
   - Importance: Essentielle - cette fonctionnalité est utilisée sur la page d'accueil
   - Coût: ~$3.50/mois
   - Comment obtenir:
     1. Allez sur https://haveibeenpwned.com/API/Key
     2. Entrez votre email et vérifiez-le
     3. Achetez une clé API (commence à $3.50/mois)
     4. Copiez la clé reçue par email
   - Comment configurer dans Replit:
     1. Allez dans l'onglet "Deployments"
     2. Cliquez sur "Add deployment secret"
     3. Nom: `HIBP_API_KEY`
     4. Valeur: Votre clé API reçue par email

### Variables recommandées

2. **DATABASE_URL**
   - Description: URL de connexion PostgreSQL
   - Par défaut: SQLite local (non recommandé en production)
   - Format: `postgresql://user:password@host:port/database`

3. **FLASK_DEBUG**
   - Description: Mode debug (doit être `False` en production)
   - Par défaut: False
   - Valeurs possibles: `True` ou `False`

### Variables optionnelles (fonctionnalités avancées)

4. **SECRET_KEY**
   - Description: Clé secrète Flask pour signer les sessions
   - Par défaut: Générée automatiquement si absente
   - Recommandation: Définir une clé fixe en production pour persistance des sessions

## Vérification automatique

L'application vérifie automatiquement les variables d'environnement au démarrage:

- ✅ En **développement**: Les variables manquantes génèrent des avertissements
- 🚨 En **production**: Les variables obligatoires manquantes empêchent le démarrage

## Comment déployer

1. Configurez tous les secrets requis (voir ci-dessus)
2. Cliquez sur le bouton "Deploy" dans Replit
3. L'application vérifiera automatiquement les variables
4. Si tout est correct, le déploiement se lancera
5. Si des variables manquent, vous verrez un message d'erreur explicite

## Sécurité

⚠️ **IMPORTANT**: Ne jamais commiter de mots de passe ou secrets dans le code source!

- Utilisez toujours les "Deployment secrets" de Replit
- Changez le mot de passe admin par défaut avant le déploiement
- Utilisez des mots de passe forts (minimum 12 caractères, mélangeant majuscules, minuscules, chiffres et symboles)

## Configuration de production

Le fichier de configuration du déploiement est déjà configuré pour utiliser:
- Gunicorn comme serveur WSGI (production-ready)
- 2 workers pour gérer les requêtes parallèles
- Binding sur 0.0.0.0:5000
- Option --reuse-port pour les performances

## Vérification post-déploiement

Après le déploiement, vérifiez:
1. L'application démarre sans erreur
2. Vous pouvez vous connecter avec les identifiants admin
3. Les fonctionnalités principales fonctionnent
4. Aucun message de sécurité n'apparaît dans les logs
