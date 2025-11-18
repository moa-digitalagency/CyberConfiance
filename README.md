# CyberConfiance

Plateforme de sensibilisation et de prévention en cybersécurité pour l'Afrique francophone. Initiative créée par Aisance KALONJI pour démocratiser les bonnes pratiques de sécurité numérique.

## Fonctionnalités

- **20 Règles d'Or de Cybersécurité** : Guide pratique des bonnes pratiques essentielles
- **Scénarios de Cybermenaces** : Exemples concrets et solutions adaptées
- **Outils Essentiels** : Catalogue d'outils de sécurité avec filtres avancés
- **Méthodologie OSINT** : Techniques d'investigation en sources ouvertes
- **Services** : Sensibilisation, Fact-checking et Cyberconsultation
- **Glossaire** : Termes techniques expliqués simplement
- **Panel Admin** : Gestion complète du contenu via interface sécurisée
- **Architecture Moderne** : Flask, PostgreSQL, interface responsive
- **Authentification Sécurisée** : Protection par Flask-Login

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
├── __init__.py              # Initialisation Flask et configuration app
├── models/                  # Modèles de base de données (User, Rule, Tool, etc.)
├── routes/                  # Routes et contrôleurs (main, admin_routes)
├── services/                # Logique métier
├── utils/                   # Utilitaires et seed data
├── data/                    # Données JSON pour seed (rules, tools, scenarios, glossary)
├── static/                  # Ressources statiques
│   ├── css/                 # Styles CSS
│   ├── js/                  # JavaScript
│   └── img/                 # Images
├── templates/               # Templates HTML (Jinja2)
│   ├── services/            # Pages de services
│   └── outils/              # Pages d'outils spécialisés
├── main.py                  # Point d'entrée de l'application
├── config.py                # Configuration et variables d'environnement
└── requirements.txt         # Dépendances Python
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
