# 🛡️ CyberConfiance

**Un bouclier numérique pour l'Afrique francophone**

CyberConfiance est une plateforme bilingue (FR/EN) complète de sensibilisation, fact-checking, analyse de sécurité et accompagnement en cybersécurité destinée aux dirigeants d'entreprise, décideurs publics et citoyens soucieux de leur sécurité numérique.

Initiative créée par **Aisance KALONJI** pour démocratiser les bonnes pratiques de sécurité numérique.

---

## 🌟 Fonctionnalités principales

### 🔍 Analyseur de Sécurité Unifié
Interface unifiée pour analyser :
- **Fichiers** - Upload et scan antivirus/malware
- **URLs et domaines** - Vérification de réputation et détection de phishing
- **Adresses IP** - Analyse de réputation et détection de menaces
- **Emails** - Détection de fuites de données via Have I Been Pwned
- **Export PDF** - Rapports forensiques professionnels avec logos et formatage
- **Stockage en base** - Historique complet accessible aux administrateurs

### 🧪 Quiz de Sécurité Interactif
- Évaluation en 3 catégories : Vigilance, Sécurité, Hygiène numérique
- Recommandations personnalisées basées sur les résultats
- Analyse optionnelle d'email via Have I Been Pwned
- Génération de QR codes pour accès rapide aux résultats
- Historique complet en admin avec détails des réponses

### 📊 Catalogue des Types d'Attaques
- **42 types d'attaques** documentés et catégorisés
- Filtrage par catégorie (Réseau, Social Engineering, Malware, etc.)
- Niveaux de sévérité (Faible, Moyen, Élevé, Critique)
- Descriptions, méthodes de prévention et impacts détaillés
- Interface moderne avec recherche en temps réel

### 🔒 Analyse de Fuites de Données (Breach Analysis)
- Intégration Have I Been Pwned API v3
- Détection des fuites de données personnelles
- **Scénarios d'attaque détaillés** pour 16+ types de données compromises
- **Recommandations personnalisées** groupées par catégorie
- **Export PDF** avec rapport forensique complet
- Niveaux de risque: Critique, Élevé, Moyen, Faible

### 📚 Ressources Éducatives Complètes
- **20 règles d'or** de la cybersécurité
- **11 scénarios** d'attaques courantes avec solutions
- **Glossaire** de 40+ termes techniques expliqués simplement
- **25 outils** recommandés pour la protection
- **Blog et actualités** cyber régulières avec système de catégories
- **Newsletter** avec gestion des abonnés

### 🎯 Services de Soumission Sécurisés

#### 1. **Fact-Checking**
- Vérification des informations et fake news
- Scan automatique de sécurité (fichiers, URLs, texte)
- Lutte contre la désinformation numérique
- Soumission anonyme optionnelle

#### 2. **Cyberconsultation & Investigation OSINT**
- Accompagnement professionnel des organisations
- **Onglet Consultation** : Demandes générales de cybersécurité
- **Onglet Investigation OSINT** : Enquêtes approfondies en sources ouvertes
- Sécurisation des systèmes d'information

#### 3. **Signalement de Cybercriminalité**
- **14 catégories de crimes** : Pédocriminalité, Cyberbanque, Revenge porn, Cyberharcèlement, Escroquerie, Vol d'identité, etc.
- Champ plateforme pour contextualiser
- Soumission anonyme activée par défaut
- Scan de sécurité automatique

Toutes les soumissions incluent :
- Protection CSRF complète
- Scan antimalware automatique
- Support fichiers, URLs et texte
- Génération de codes de suivi
- QR codes pour accès rapide

### 🛡️ Système de Détection de Menaces
- **ThreatLog** - Enregistrement automatique des incidents de sécurité
- **Métadonnées complètes** : IP, user-agent, plateforme, appareil, détection VPN
- **Page d'alerte sécurité** : Affichage détaillé des menaces avec ID d'incident
- **Workflow admin** : URLs partageables pour audit et révision
- **Résilience** : Stockage en session + query parameters pour accès direct

### 🔧 Méthodologie OSINT
- Techniques d'investigation en sources ouvertes
- Guides pratiques pour analyser les menaces
- Outils professionnels
- CTA vers formulaire d'investigation OSINT

### 🛠️ Panel Admin Professionnel

#### Interface & Design
- **Design glassmorphism moderne** avec thème sombre
- **Sidebar avec profil** : Avatar, nom, rôle et déconnexion
- **Favicon admin personnalisé** (`static/admin_favicon.png`)
- **Protection par authentification** Flask-Login
- **Accès basé sur les rôles** (Admin, Modérateur)

#### Gestion des Demandes
- **Requêtes utilisateurs** (Fact-checking, Cyberconsultation, OSINT, Signalements)
- **Messages de contact** - Répondre, archiver, filtrer par statut
- **Détails complets** avec résultats d'analyses de sécurité
- **Mise à jour de statuts** : Pending, In Progress, Completed, Rejected
- **Notes administrateur** pour suivi interne

#### Historiques & Analytics
- **Quiz** - Résultats avec scores par catégorie, réponses détaillées, résumés HIBP formatés
- **Analyses de sécurité** - Fichiers, URLs, IPs, emails avec export PDF
- **Analyses de fuites** - Vérifications emails avec export PDF
- **Filtres & recherche** en temps réel
- **Export CSV** pour tous les historiques
- **Pagination** professionnelle

#### Logs & Sécurité
- **Logs d'activité** - Toutes les actions utilisateur tracées
- **Logs de menaces** - Incidents de sécurité avec métadonnées complètes
- **Alertes en temps réel** pour menaces détectées

#### Gestion de Contenu
- **Contenu via JSON** - Articles, règles, outils gérés par fichiers seed
- **Newsletter** - Gestion des abonnés
- **Paramètres SEO** - Métadonnées pour chaque page
- **Paramètres du site** - Logos, réseaux sociaux, configuration générale
- **Page Content Settings** - Édition de contenu des pages

---

## 🎨 Design & Interface

### Thème & Style
- **Pure black background** (#000000) pour élégance maximale
- **Effets d'orbes lumineux** colorés pour dynamisme
- **Glassmorphism** - Cartes semi-transparentes avec blur
- **Typographie minimale** avec police Inter
- **Animations scroll-triggered** pour fluidité
- **Parallax scrolling** sur certaines sections

### Système de Thèmes
- **Light/Dark mode** avec détection automatique du système
- **Switcher utilisateur** (coin inférieur gauche)
- **Logos variants** configurables (light/dark)
- **CSS custom properties** pour cohérence

### Support Bilingue
- **Français/Anglais** complet via Flask-Babel
- **Détection automatique** du navigateur
- **Switcher de langue** (coin inférieur gauche)
- **Traductions complètes** de l'interface

### Optimisations Mobile
- **Responsive design** complet
- **Boutons optimisés** avec glassmorphism avancé
- **Navigation tactile** fluide
- **Performance** optimisée pour mobile

---

## 🚀 Installation et Configuration

### Prérequis
- Python 3.11+
- PostgreSQL
- **Compte Have I Been Pwned API** (~$3.50/mois) - OBLIGATOIRE
- **Clé d'analyse de sécurité** - OBLIGATOIRE pour scan de fichiers/URLs

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

**Variables OBLIGATOIRES en production:**
```bash
ADMIN_PASSWORD=VotreMotDePasseSécurisé123!
HIBP_API_KEY=votre_clé_api_hibp
SECURITY_ANALYSIS_API_KEY=votre_clé_api_analyse_securite
```

**Variables recommandées:**
```bash
DATABASE_URL=postgresql://user:pass@host:5432/db  # PostgreSQL
FLASK_DEBUG=False  # En production
SECRET_KEY=votre_clé_secrète_pour_les_sessions
```

4. **Initialiser la base de données**
```bash
# Vérification des modèles
python init_db.py --check

# Initialisation normale
python init_db.py

# Réinitialisation complète (⚠️ SUPPRIME toutes les données!)
python init_db.py --reset
```

Le script `init_db.py` vérifie automatiquement que tous les modèles sont chargés et affiche la liste des tables créées, évitant ainsi les erreurs de tables manquantes lors du déploiement.

5. **Lancer l'application**
```bash
# En développement
python main.py

# En production (avec Gunicorn)
gunicorn --bind=0.0.0.0:5000 --reuse-port --workers=2 main:app
```

---

## 🔐 Obtenir les clés API

### Have I Been Pwned (Analyse d'emails)
1. Visitez https://haveibeenpwned.com/API/Key
2. Vérifiez votre email
3. Souscrivez (~$3.50/mois)
4. Recevez votre clé par email
5. Configurez: `HIBP_API_KEY=votre_clé`

### Clé d'Analyse de Sécurité
1. Créez un compte sur votre service d'analyse
2. Obtenez votre clé API
3. Configurez: `SECURITY_ANALYSIS_API_KEY=votre_clé`

**Plan gratuit:** 500 requêtes/jour (généralement suffisant)

---

## 📋 Déploiement

### Sur Replit

L'application vérifie automatiquement les variables au démarrage:

**En développement:** Avertissements affichés, continue de fonctionner  
**En production:** Refuse de démarrer sans configuration valide

1. **Configurer les secrets** dans "Deployments"
2. **Déployer** - Vérification automatique de la configuration
3. **Accéder** à votre application via l'URL Replit

### Sur VPS (Ubuntu/Debian)

1. **Installer les dépendances système**
```bash
sudo apt update
sudo apt install python3-pip python3-venv postgresql nginx
```

2. **Créer la base de données PostgreSQL**
```bash
sudo -u postgres psql
CREATE DATABASE cyberconfiance;
CREATE USER cyberconfiance WITH PASSWORD 'votre_password';
GRANT ALL PRIVILEGES ON DATABASE cyberconfiance TO cyberconfiance;
\q
```

3. **Configurer l'environnement**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. **Variables d'environnement** (fichier `.env`)
```bash
DATABASE_URL=postgresql://cyberconfiance:votre_password@localhost/cyberconfiance
ADMIN_PASSWORD=VotreMotDePasseAdmin123!
HIBP_API_KEY=votre_clé_hibp
SECURITY_ANALYSIS_API_KEY=votre_clé_analyse
FLASK_DEBUG=False
SECRET_KEY=votre_clé_secrète_longue_et_complexe
```

5. **Initialiser la base**
```bash
python init_db.py
```

6. **Configurer Gunicorn** (systemd service)
```bash
sudo nano /etc/systemd/system/cyberconfiance.service
```

```ini
[Unit]
Description=CyberConfiance Flask App
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/CyberConfiance
Environment="PATH=/path/to/CyberConfiance/venv/bin"
EnvironmentFile=/path/to/CyberConfiance/.env
ExecStart=/path/to/CyberConfiance/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --reuse-port main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

7. **Configurer Nginx**
```nginx
server {
    listen 80;
    server_name votre-domaine.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /path/to/CyberConfiance/static;
        expires 30d;
    }
}
```

8. **Activer HTTPS avec Let's Encrypt**
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d votre-domaine.com
```

9. **Démarrer les services**
```bash
sudo systemctl enable cyberconfiance
sudo systemctl start cyberconfiance
sudo systemctl restart nginx
```

---

## 📊 SEO & Indexation

### Robots.txt
Fichier `/robots.txt` configuré automatiquement:
- **Autorise** l'indexation du contenu éducatif
- **Bloque** les pages admin, formulaires, APIs
- **Gère les bots IA** (GPTBot, Claude, Google-Extended, etc.)
- **Bloque les crawlers agressifs** (AhrefsBot, SemrushBot, etc.)

### Sitemap.xml
Sitemap XML dynamique généré automatiquement à `/sitemap.xml`:
- **Pages statiques** avec priorités et fréquences
- **Articles de blog** avec dates de dernière modification
- **Pages de ressources** (règles, outils, glossaire)
- **Mise à jour automatique** selon le contenu en base

Configuration SEO complète dans le panel admin:
- Métadonnées par page (title, description, keywords)
- Open Graph pour réseaux sociaux
- Gestion centralisée

---

## 🔒 Sécurité et Conformité

### Protection CSRF
- **Flask-WTF CSRFProtect** activé globalement
- **Tous les formulaires** (26+) protégés avec tokens CSRF
- **Validation automatique** des POST/PUT/PATCH/DELETE

### Authentification & Autorisation
- **Flask-Login** pour gestion des sessions
- **Werkzeug** pour hashage sécurisé des mots de passe
- **Rôles utilisateur** : Admin, Modérateur, Utilisateur
- **Décorateurs de protection** sur routes sensibles

### Gestion des Erreurs
- **Handlers 404 et 500** avec templates personnalisés
- **Logging automatique** des erreurs 500 avec stack traces
- **Rollback database** automatique en cas d'erreur
- **Messages utilisateur** sans exposition de données sensibles

### Bonnes Pratiques
- ✅ **k-anonymity** pour vérification HIBP
- ✅ **Pas de stockage** de mots de passe en clair
- ✅ **Variables d'environnement** pour secrets
- ✅ **HTTPS** obligatoire en production
- ✅ **Headers sécurisés** (Cache-Control, X-Frame-Options, etc.)
- ✅ **Validation** des entrées utilisateur
- ✅ **Sanitization** des données (max breaches, user-agent, etc.)

---

## 🛠️ Technologies utilisées

### Backend
- **Flask 3.0** - Framework web
- **SQLAlchemy** - ORM pour base de données
- **Alembic** - Migrations de base de données
- **Flask-Login 0.6** - Authentification
- **Flask-Admin 1.6** - Interface admin
- **Flask-WTF** - Protection CSRF
- **Flask-Babel** - Internationalisation (i18n)
- **Werkzeug** - Utilitaires et sécurité
- **Gunicorn 21.2** - Serveur WSGI production

### Sécurité & APIs
- **Have I Been Pwned API v3** - Détection de fuites
- **vt-py** - Client pour analyse de sécurité
- **python-magic** - Détection de types de fichiers
- **filetype** - Validation MIME
- **user-agents** - Parsing user-agent pour logs

### PDF & Rapports
- **PyMuPDF (fitz)** - Génération PDF
- **Pillow** - Traitement d'images pour PDFs

### Base de données
- **PostgreSQL** - Base de données
- **psycopg2-binary** - Adaptateur PostgreSQL

### Frontend
- **HTML5, CSS3, JavaScript (Vanilla)**
- **Inter Font** - Typographie
- **Responsive Design**
- **Glassmorphism CSS**

---

## 🎯 Architecture du Projet

```
CyberConfiance/
├── main.py                          # Point d'entrée
├── __init__.py                      # Factory Flask & configuration
├── config.py                        # Configuration centralisée
├── models.py                        # Modèles SQLAlchemy (18 tables)
├── init_db.py                       # Initialisation DB avec vérification
│
├── routes/
│   ├── main.py                      # Routes publiques + robots.txt + sitemap.xml
│   ├── admin_routes.py              # Routes Flask-Admin
│   ├── admin_panel.py               # Panel admin personnalisé
│   ├── admin_requests.py            # Gestion requêtes utilisateurs
│   └── request_forms.py             # Formulaires soumissions
│
├── services/
│   ├── __init__.py                  # Services (HIBP, Content, Quiz)
│   ├── security_analyzer.py         # Analyseur sécurité unifié
│   ├── pdf_service.py               # Génération rapports PDF
│   └── request_submission.py        # Traitement soumissions
│
├── utils/
│   ├── seed_data.py                 # Seed data depuis JSON
│   ├── document_code_generator.py   # Codes de suivi uniques
│   ├── admin_decorators.py          # Décorateurs @admin_required
│   ├── activity_logger.py           # Logging activités
│   └── threat_detector.py           # Détection menaces
│
├── templates/
│   ├── base.html                    # Template base public
│   ├── index.html                   # Page d'accueil
│   ├── breach_analysis.html         # Analyse fuites
│   ├── quiz.html                    # Quiz interactif
│   ├── security_analyzer.html       # Analyseur sécurité
│   ├── attack_types.html            # Catalogue attaques
│   ├── error_404.html               # Page 404
│   ├── error_500.html               # Page 500
│   ├── admin/
│   │   ├── base.html                # Template base admin
│   │   ├── dashboard.html           # Tableau de bord
│   │   ├── requests.html            # Liste requêtes
│   │   ├── request_detail.html      # Détails requête
│   │   ├── contacts.html            # Messages contact
│   │   ├── contact_detail.html      # Détail message
│   │   ├── quiz_history.html        # Historique quiz
│   │   ├── quiz_detail.html         # Détails quiz (HIBP formaté)
│   │   ├── security_history.html    # Historique analyses
│   │   ├── breach_history.html      # Historique fuites
│   │   ├── threat_logs.html         # Logs menaces
│   │   └── ...
│   └── outils/
│       └── ...                      # Templates outils
│
├── static/
│   ├── css/
│   │   └── style.css                # Styles avec glassmorphism
│   ├── js/
│   │   ├── main.js                  # JavaScript principal
│   │   ├── theme-switcher.js        # Switcher thème
│   │   └── theme-lang-switcher.js   # Switcher langue
│   ├── img/
│   │   ├── logo.png                 # Logo principal
│   │   └── admin_favicon.png        # Favicon admin
│   └── robots.txt                   # Robots.txt statique
│
├── seed_data/                       # Données JSON pour seeding
│   ├── rules.json                   # 20 règles d'or
│   ├── scenarios.json               # 11 scénarios
│   ├── glossary.json                # 40+ termes
│   ├── tools.json                   # 25 outils
│   ├── attack_types.json            # 42 types d'attaques
│   ├── news.json                    # Articles de blog
│   ├── site_settings.json           # Paramètres site
│   ├── page_content.json            # Contenu pages
│   └── seo_metadata.json            # Métadonnées SEO
│
├── requirements.txt                 # Dépendances Python
├── .gitignore                       # Fichiers ignorés Git
├── .replit                          # Config Replit
└── replit.nix                       # Environnement Nix
```

### Modèles de Base de Données (18 tables)

1. **User** - Utilisateurs et admins
2. **Rule** - Règles de cybersécurité
3. **Scenario** - Scénarios d'attaques
4. **GlossaryTerm** - Termes du glossaire
5. **Tool** - Outils recommandés
6. **News** - Articles de blog
7. **RequestSubmission** - Soumissions (fact-checking, consultation, OSINT, cybercrime)
8. **Contact** - Messages de contact
9. **QuizResult** - Résultats de quiz avec réponses
10. **BreachAnalysis** - Analyses de fuites emails (avec PDF)
11. **SecurityAnalysis** - Analyses de sécurité (fichiers, URLs, IPs) (avec PDF)
12. **AttackType** - Types d'attaques documentés
13. **Newsletter** - Abonnés newsletter
14. **ActivityLog** - Logs d'activités utilisateurs
15. **ThreatLog** - Logs d'incidents de sécurité
16. **SiteSettings** - Paramètres du site
17. **PageContentSettings** - Contenu des pages
18. **SEOMetadata** - Métadonnées SEO

---

## 📖 Fonctionnalités Détaillées

### Quiz de Sécurité
- **15 questions** sur 3 catégories
- **Scoring intelligent** avec pourcentages
- **Recommandations personnalisées** basées sur le score
- **Analyse HIBP optionnelle** de l'email utilisateur
- **Résultats avec QR code** pour accès rapide
- **Historique admin** avec tous les détails

### Analyseur de Sécurité
**Fichiers:**
- Upload jusqu'à 50MB
- Scan antivirus/malware automatique
- Détection de types MIME
- Rapport de détection (malicious/suspicious/harmless)

**URLs & Domaines:**
- Vérification de réputation
- Détection de phishing
- Analyse de contenu malveillant

**IPs:**
- Réputation d'adresse IP
- Détection de proxy/VPN/Tor
- Historique d'abus

**Emails:**
- Intégration Have I Been Pwned
- Détection fuites de données
- Rapport détaillé des breaches
- Export PDF avec scénarios d'attaque

### Catalogue d'Attaques (42 types)
**Catégories:**
- Réseau (Man-in-the-Middle, DDoS, DNS Spoofing, etc.)
- Social Engineering (Phishing, Vishing, Pretexting, etc.)
- Malware (Ransomware, Spyware, Trojans, etc.)
- Web (XSS, SQL Injection, CSRF, etc.)
- Sans fil (Evil Twin, WPS Attack, etc.)
- Physique (Tailgating, Shoulder Surfing, etc.)

**Pour chaque attaque:**
- Description complète
- Méthode de prévention
- Impact potentiel
- Niveau de sévérité (Faible/Moyen/Élevé/Critique)

### Système de Soumissions
**Types:**
1. Fact-Checking - Vérification d'informations
2. Cyberconsultation - Conseil général
3. Investigation OSINT - Enquête approfondie
4. Signalement Cybercrime - 14 catégories de crimes

**Fonctionnalités:**
- Scan de sécurité automatique (fichiers, URLs, texte)
- Génération de codes de suivi uniques
- QR codes pour accès rapide
- Support anonyme
- Stockage sécurisé des résultats d'analyse

---

## 📈 Statistiques

- ✅ **20 règles** d'or de cybersécurité
- ✅ **11 scénarios** d'attaques avec solutions
- ✅ **40+ termes** dans le glossaire
- ✅ **25 outils** recommandés
- ✅ **42 types d'attaques** documentés
- ✅ **16 types de données** analysées avec scénarios
- ✅ **800M+** mots de passe dans la base HIBP
- ✅ **18 tables** de base de données
- ✅ **26+ formulaires** protégés CSRF
- ✅ **4 types de soumissions** sécurisées
- ✅ **2 langues** (Français, Anglais)
- ✅ **2 thèmes** (Light, Dark)

---

## 🌍 Vision et Mission

### Notre Vision
Faire de l'Afrique francophone un espace numérique sûr et informé, où chaque citoyen dispose des outils et connaissances pour se protéger contre les cybermenaces et la désinformation.

### Notre Mission
Démocratiser la cybersécurité et lutter contre la désinformation en Afrique francophone grâce à l'éducation, la vérification d'informations, l'analyse de sécurité et l'accompagnement professionnel.

### Nos Objectifs
- Sensibiliser **100 000 personnes d'ici 2026**
- Vérifier et déconstruire les fake news
- Fournir des outils d'analyse de sécurité accessibles
- Accompagner les professionnels dans la sécurisation de leurs SI
- Former aux techniques OSINT

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
© 2025 CyberConfiance - Tous droits réservés

---

## 🙏 Remerciements

- **Have I Been Pwned** - Troy Hunt pour l'API de détection de fuites
- **Replit** - Plateforme de développement et déploiement
- **Communauté open-source** - Tous les contributeurs
- **Utilisateurs** - Tous ceux qui contribuent à un Internet plus sûr

---

**CyberConfiance - Votre bouclier numérique en Afrique** 🛡️
