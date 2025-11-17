# CyberConfiance

Plateforme de sensibilisation à la cybersécurité avec backend Flask, panel admin, et base de données PostgreSQL.

## Fonctionnalités

- Architecture modulaire (models, routes, services, utils)
- Panel admin sécurisé pour la gestion du contenu
- Base de données PostgreSQL
- Pages publiques: Accueil, À propos, Règles d'or, Scénarios, Outils, Glossaire, Ressources, Actualités, Contact
- Interface responsive et moderne
- Authentification sécurisée avec Flask-Login

## Installation

1. Les dépendances sont déjà installées via `requirements.txt`
2. La base de données PostgreSQL est configurée automatiquement

## Configuration

### Variables d'environnement

- `DATABASE_URL`: URL de connexion PostgreSQL (configurée automatiquement)
- `FLASK_DEBUG`: Mode debug (True/False, défaut: False)
- `ADMIN_PASSWORD`: **REQUIS en production** - Mot de passe de l'administrateur
- `SECRET_KEY`: Clé secrète Flask (optionnel, une valeur par défaut existe)

### Mode Développement

En mode développement (FLASK_DEBUG=True), un utilisateur admin par défaut est créé:
- **Username**: `admin`
- **Password**: `admin123`

```bash
export FLASK_DEBUG=True
python main.py
```

### Mode Production

⚠️ **IMPORTANT - SÉCURITÉ**: En production, définissez toujours un mot de passe sécurisé via la variable d'environnement `ADMIN_PASSWORD`.

**Déploiement sur Replit:**
1. Allez dans "Secrets" (icône 🔒 dans la barre latérale)
2. Ajoutez une nouvelle secret:
   - Clé: `ADMIN_PASSWORD`
   - Valeur: votre mot de passe sécurisé
3. Cliquez sur "Deploy" pour publier votre site

**Déploiement manuel avec gunicorn:**
```bash
export ADMIN_PASSWORD="votre_mot_de_passe_tres_securise"
gunicorn --bind=0.0.0.0:5000 --reuse-port main:app
```

**Sans ADMIN_PASSWORD**, le mot de passe par défaut sera `admin123` - **NE JAMAIS utiliser en production!**

## Accès au Panel Admin

1. Démarrez l'application
2. Accédez à `/login` pour vous connecter
3. Une fois connecté, accédez à `/admin` pour gérer le contenu

## Structure du Projet

```
├── app/
│   ├── __init__.py           # Initialisation Flask
│   ├── models/               # Modèles de base de données
│   ├── routes/               # Routes et contrôleurs
│   ├── services/             # Logique métier
│   ├── utils/                # Utilitaires
│   ├── static/               # CSS, JS, images
│   └── templates/            # Templates HTML
├── main.py                   # Point d'entrée
├── config.py                 # Configuration
└── requirements.txt          # Dépendances Python
```

## Sécurité

- Authentification requise pour accéder au panel admin
- Mots de passe hashés avec Werkzeug
- Protection CSRF pour les formulaires
- Mode debug désactivé par défaut
- Variables d'environnement pour les secrets

## Développement

Pour ajouter du contenu:

1. Connectez-vous au panel admin (`/login`)
2. Ajoutez des articles, règles, outils, scénarios, etc.
3. Le contenu apparaîtra automatiquement sur les pages publiques

## Support

Pour toute question, utilisez le formulaire de contact sur le site.
