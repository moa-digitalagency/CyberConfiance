# 🛡️ CyberConfiance

**Un bouclier numérique pour l'Afrique francophone**

CyberConfiance est une plateforme de sensibilisation, fact-checking et accompagnement en cybersécurité destinée aux dirigeants d'entreprise, décideurs publics et citoyens soucieux de leur sécurité numérique.

Initiative créée par **Aisance KALONJI** pour démocratiser les bonnes pratiques de sécurité numérique.

---

## 🌟 Fonctionnalités principales

### 🔍 Vérification d'emails compromis
- Analyse en temps réel via l'API Have I Been Pwned
- Détection des fuites de données personnelles
- **Scénarios d'attaque détaillés** pour chaque type de donnée compromise (16+ types)
- **Recommandations personnalisées** condensées et groupées par catégorie
- **Mentions conditionnelles** (ex: banque seulement si pertinent)
- Analyse approfondie des menaces avec niveaux de risque: Critique, Élevé, Moyen, Faible

### 📚 Ressources éducatives
- **20 règles d'or** de la cybersécurité
- **11 scénarios** d'attaques courantes avec solutions
- **Glossaire** de 40+ termes techniques expliqués simplement
- **24 outils** recommandés pour la protection
- Actualités et news cyber régulières

### ✅ Fact-Checking
- Vérification des informations et fake news
- Lutte contre la désinformation numérique
- Sources fiables et vérifiées

### 🔧 Méthodologie OSINT
- Techniques d'investigation en sources ouvertes
- Guides pratiques pour analyser les menaces
- Outils professionnels

### 💼 Cyberconsultation
- Accompagnement des organisations
- Sécurisation des systèmes d'information
- Expertise professionnelle

### 🛠️ Panel Admin Professionnel
- **Interface moderne avec design glassmorphism** - Style cohérent et élégant
- **Profil utilisateur dans la sidebar** - Avatar, nom, rôle et déconnexion
- **Gestion complète du contenu** via interface sécurisée :
  - **Articles de blog** - Créer, modifier, supprimer avec filtres et recherche
  - **Messages de contact** - Répondre, archiver, filtrer par statut
  - **Newsletter** - Gérer les abonnés
  - **Contenu des pages** - Éditer home, about, services, contact
  - **Paramètres SEO** - Gérer les métadonnées pour chaque page
  - **Paramètres du site** - Configuration générale
- **Historiques et analytics** :
  - Quiz - Résultats avec scores et statistiques
  - Analyses de sécurité - Détections de menaces
  - Analyses de fuites - Vérifications d'emails compromis
- **Logs de sécurité** :
  - Logs d'activité - Toutes les actions utilisateur
  - Logs de sécurité - Événements et tentatives d'attaque
- **Tableaux professionnels** :
  - Colonnes Actions dédiées et alignées
  - Boutons uniformes et espacés
  - Filtres et recherche en temps réel
  - Export CSV pour tous les historiques
  - Pagination améliorée
- **Protection par authentification Flask-Login**
- **Accès basé sur les rôles** (Admin, Modérateur, Utilisateur)

---

## 🚀 Installation et Configuration

### Prérequis
- Python 3.11+
- PostgreSQL (optionnel, SQLite par défaut)
- **Compte Have I Been Pwned API** (~$3.50/mois) - **OBLIGATOIRE en production**

### Installation rapide

1. **Cloner le projet**
```bash
git clone <votre-repo>
cd CyberConfiance
```

2. **Installer les dépendances**
```bash
pip install -r requirements.txt
```

3. **Configurer les variables d'environnement**

Créez un fichier `.env` ou configurez les secrets Replit:

**Variables OBLIGATOIRES en production:**
```bash
ADMIN_PASSWORD=VotreMotDePasseSécurisé123!
HIBP_API_KEY=votre_clé_api_hibp
```

**Variables recommandées:**
```bash
DATABASE_URL=postgresql://user:pass@host:5432/db  # Pour PostgreSQL
FLASK_DEBUG=False  # En production
SECRET_KEY=votre_clé_secrète_pour_les_sessions
```

4. **Initialiser la base de données** (optionnel - se fait automatiquement au premier démarrage)
```bash
# Initialisation normale
python init_db.py

# Réinitialisation complète (⚠️ SUPPRIME toutes les données!)
python init_db.py --reset
```

5. **Lancer l'application**
```bash
# En développement
python main.py

# En production (avec Gunicorn)
gunicorn --bind=0.0.0.0:5000 --reuse-port --workers=2 main:app
```

---

## 🔐 Obtenir une clé API Have I Been Pwned

La clé API HIBP est **OBLIGATOIRE** car la page d'accueil utilise la fonctionnalité "Vérifiez si votre email a été compromis".

1. Visitez https://haveibeenpwned.com/API/Key
2. Entrez votre email et vérifiez-le
3. Souscrivez à l'abonnement (~$3.50/mois)
4. Recevez votre clé API par email
5. Ajoutez-la dans vos secrets: `HIBP_API_KEY=votre_clé`

**Note:** La vérification de mots de passe est gratuite et ne nécessite pas de clé API. Seule la vérification d'emails en nécessite une.

---

## 📋 Déploiement sur Replit

### Vérification automatique des variables

L'application vérifie automatiquement les variables d'environnement au démarrage:

**En développement:**
```
⚠️  ADMIN_PASSWORD: Non défini (OK en dev)
⚠️  HIBP_API_KEY: Non défini (OK en dev)
```
→ Avertissements affichés, l'application continue de fonctionner

**En production:**
```
❌ ADMIN_PASSWORD: MANQUANT
❌ HIBP_API_KEY: MANQUANT
🚨 ERREUR CRITIQUE
```
→ **L'application refuse de démarrer** avec des instructions claires

### Étapes de déploiement

1. **Configurer les secrets**
   - Allez dans l'onglet "Deployments"
   - Cliquez sur "Add deployment secret"
   - Ajoutez `ADMIN_PASSWORD` et `HIBP_API_KEY`

2. **Déployer**
   - Cliquez sur "Deploy"
   - L'application vérifie automatiquement la configuration
   - Si tout est OK → Démarrage réussi ✅
   - Si manquant → Erreur avec instructions ❌

### Configuration de déploiement

Le fichier `.replit` est configuré pour:
- Serveur Gunicorn (production-ready)
- 2 workers pour gérer les requêtes parallèles
- Binding sur 0.0.0.0:5000
- Option --reuse-port pour les performances

---

## 🎯 Nos 6 piliers

1. **Sensibilisation** - Informer sur les risques cyber actuels
2. **Éducation** - Former aux bonnes pratiques numériques
3. **Fact-Checking** - Vérifier et lutter contre la désinformation
4. **OSINT** - Investigation en sources ouvertes
5. **Cyberconsultation** - Accompagnement professionnel
6. **Outils Essentiels** - Ressources pratiques adaptées

---

## 🛠️ Technologies utilisées

- **Backend:** Flask 3.0, SQLAlchemy, Alembic
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
- **Base de données:** PostgreSQL / SQLite
- **API:** Have I Been Pwned v3
- **Serveur:** Gunicorn 21.2
- **Admin:** Flask-Admin 1.6
- **Auth:** Flask-Login 0.6

---

## 📊 Fonctionnalités de sécurité

### ✅ Vérification des mots de passe compromis
- Intégration de l'API Pwned Passwords (gratuite)
- Utilise k-anonymity (votre mot de passe n'est jamais envoyé)
- Base de données de 800M+ mots de passe compromis

### 🔍 Analyse des fuites de données

L'application affiche des **scénarios d'attaque personnalisés** pour chaque type de données compromises:

| Type de donnée | Icône | Niveau de risque | Scénario |
|----------------|-------|------------------|----------|
| 📧 Email addresses | 📧 | Moyen | Phishing ciblé, spam, inscription frauduleuse |
| 🔑 Passwords | 🔑 | **Critique** | Accès à tous les comptes utilisant ce mot de passe |
| 📱 Phone numbers | 📱 | Élevé | SMS phishing, SIM swapping, usurpation |
| 💳 Credit cards | 💳 | **Critique** | Fraude financière immédiate |
| 🆔 Social security | 🆔 | **Critique** | Usurpation d'identité complète |
| 🏥 Health data | 🏥 | **Critique** | Chantage médical, discrimination |
| ... et 10+ autres types | ... | ... | ... |

### 🛡️ Recommandations intelligentes

Les recommandations sont **condensées et groupées** par catégorie au lieu de listes longues:

**Exemple - Niveau Critique (4+ fuites):**
- 🔥 **URGENT - Sécurisation des comptes** : Changez IMMÉDIATEMENT tous vos mots de passe...
- 💰 **Protection financière critique** : *Si cet email est lié à des comptes bancaires*...
- 🆔 **Gestion de l'identité** : Envisagez de créer une nouvelle adresse email...
- ⚠️ **Vigilance maximale** : Vous êtes une cible de choix pour le phishing...

**Mentions conditionnelles** :
- "Si cet email est utilisé pour vos comptes bancaires..." (seulement si pertinent)
- Actions priorisées selon l'urgence
- Niveaux de risque: Sûr, Avertissement, Critique

---

## 📖 Documentation

- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Guide de déploiement complet
- **[DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md)** - Checklist avec simulations
- **[SECURITY_GUIDE.md](SECURITY_GUIDE.md)** - Guide de sécurité et bonnes pratiques
- **[check_env.py](check_env.py)** - Script de vérification des variables

---

## 🎨 Architecture

```
CyberConfiance/
├── main.py                     # Point d'entrée de l'application
├── __init__.py                # Factory Flask et configuration
├── config.py                  # Configuration de l'application
├── models.py                  # Modèles de base de données
├── routes/
│   ├── main.py               # Routes principales
│   ├── admin_routes.py       # Routes Flask-Admin
│   └── admin_panel.py        # Routes panel admin personnalisé
├── services/
│   └── __init__.py           # Services (HIBP, Content)
├── templates/                # Templates Jinja2
│   ├── base.html             # Template de base public
│   ├── index.html            # Page d'accueil
│   ├── breach_analysis.html  # Analyse de fuites avec scénarios
│   ├── admin/                # Templates admin
│   │   ├── base.html         # Template de base admin avec glassmorphism
│   │   ├── dashboard.html    # Tableau de bord
│   │   ├── blog.html         # Gestion articles
│   │   ├── contacts.html     # Gestion messages
│   │   ├── quiz_history.html # Historique quiz
│   │   ├── security_history.html # Historique analyses sécurité
│   │   ├── breach_history.html   # Historique fuites
│   │   ├── activity_logs.html    # Logs d'activité
│   │   ├── security_logs.html    # Logs sécurité
│   │   ├── site_settings.html    # Paramètres site
│   │   ├── seo_settings.html     # Paramètres SEO
│   │   └── edit_page_content.html # Édition contenu pages
│   └── ...
├── static/                   # CSS, JS, images
│   └── css/
│       └── style.css         # Styles avec glassmorphism
├── utils/
│   ├── hibp_checker.py      # Module HIBP complet
│   └── seed_data.py         # Données initiales et seed
├── init_db.py               # Initialisation base de données
├── check_env.py             # Vérification variables d'environnement
└── requirements.txt         # Dépendances Python
```

---

## 🌍 Vision et Mission

### Notre Vision
Faire de l'Afrique francophone un espace numérique sûr et informé, où chaque citoyen dispose des outils et connaissances pour se protéger contre les cybermenaces et la désinformation.

### Notre Mission
Démocratiser la cybersécurité et lutter contre la désinformation en Afrique francophone grâce à l'éducation, la vérification d'informations et l'accompagnement professionnel.

### Nos Objectifs
- Sensibiliser **100 000 personnes d'ici 2026**
- Vérifier et déconstruire les fake news
- Accompagner les professionnels dans la sécurisation de leurs SI

---

## 🔒 Sécurité et Confidentialité

- ✅ **Pas de stockage** de mots de passe en clair (hashage Werkzeug)
- ✅ **k-anonymity** pour la vérification HIBP (mot de passe jamais envoyé)
- ✅ **Cache-Control** désactivé pour éviter la mise en cache
- ✅ **HTTPS** obligatoire en production
- ✅ **Variables d'environnement** pour tous les secrets
- ✅ **Vérification automatique** au démarrage (refuse de démarrer si config invalide)
- ✅ **Protection CSRF** pour les formulaires
- ✅ **Authentification** requise pour le panel admin

---

## 📞 Contact et Support

- **Email:** admin@cyberconfiance.fr
- **Facebook:** /lacyberconfiance
- **Instagram:** @lacyberconfiance
- **Twitter:** @cyberconfiance
- **LinkedIn:** /company/la-cyberconfiance

---

## 📝 Licence

Projet développé pour la sensibilisation à la cybersécurité en Afrique francophone.

---

## 🙏 Remerciements

- **Have I Been Pwned** - Troy Hunt pour l'API de détection de fuites
- **Replit** - Plateforme de développement et déploiement
- **Communauté** - Tous ceux qui contribuent à un Internet plus sûr

---

## 📈 Statistiques

- ✅ **20 règles** d'or de la cybersécurité
- ✅ **11 scénarios** d'attaques avec solutions
- ✅ **40+ termes** dans le glossaire
- ✅ **24 outils** recommandés
- ✅ **16 types** de données analysées avec scénarios d'attaque personnalisés
- ✅ **800M+** mots de passe compromis dans la base HIBP
- ✅ **4 niveaux** de recommandations (Sûr, Avertissement, Critique, Erreur)
- ✅ **100% sécurisé** - Refuse de démarrer sans configuration valide en production

---

**CyberConfiance - Votre bouclier numérique en Afrique** 🛡️
