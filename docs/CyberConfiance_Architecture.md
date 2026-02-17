[ 🇫🇷 Français ] | [ [🇬🇧 English](CyberConfiance_Architecture_en.md) ]

# Architecture Technique - CyberConfiance

## 1. Stack Technologique

*   **Langage** : Python 3.11+
*   **Framework Web** : Flask 3.0 (Pattern Application Factory)
*   **Base de Données** : PostgreSQL 14+
*   **ORM** : SQLAlchemy 2.0
*   **Migrations** : Alembic
*   **Frontend** : Jinja2, HTML5, CSS3 (Glassmorphism), JavaScript (Vanilla)
*   **Serveur WSGI** : Gunicorn (Production)
*   **Reverse Proxy** : Nginx (Recommandé)

---

## 2. Structure du Projet (MVC Modulaire)

L'application suit une architecture modulaire basée sur des "Blueprints" Flask pour séparer les responsabilités.

```
CyberConfiance/
├── main.py                  # Point d'entrée de l'application
├── config.py                # Configuration (Environnement, Clés API)
├── check_env.py             # Validation des prérequis au démarrage
├── init_db.py               # Script d'initialisation de la BDD
├── requirements.txt         # Dépendances Python
│
├── services/                # COUCHE MÉTIER (Business Logic)
│   ├── security_service.py  # Orchestration VirusTotal/GSB
│   ├── breach_checker.py    # Logique HIBP
│   ├── pdf_service.py       # Génération de rapports
│   └── ...
│
├── routes/                  # CONTRÔLEURS (Blueprints)
│   ├── main.py              # Routes principales (Home, Quiz)
│   ├── outils.py            # Routes des outils (Scanner, QR, etc.)
│   └── admin_routes.py      # Back-office
│
├── models/                  # MODÈLES DE DONNÉES (SQLAlchemy)
│   ├── user.py              # Utilisateurs et Rôles
│   ├── analysis.py          # Historique des scans
│   └── content.py           # Blog, Glossaire
│
├── templates/               # VUES (Jinja2)
│   ├── layouts/             # Base templates
│   ├── outils/              # Pages des outils
│   └── admin/               # Panel admin
│
├── static/                  # ASSETS
│   ├── css/                 # Styles
│   ├── js/                  # Scripts client-side
│   └── img/                 # Images
│
└── utils/                   # UTILITAIRES
    ├── security_utils.py    # Fonctions de sécurité (Sanitize, Hash)
    └── helpers.py           # Fonctions diverses
```

---

## 3. Sécurité Implémentée

La sécurité est "Native by Design".

### 3.1. Content Security Policy (CSP)
Un `nonce` cryptographique est généré à chaque requête (`secrets.token_hex(16)`). Il est injecté dans les headers HTTP et dans les balises `<script>` autorisées. Tout script sans ce nonce est bloqué par le navigateur.

### 3.2. Protection CSRF
`Flask-WTF` génère un token unique pour chaque session utilisateur. Ce token est requis pour toute méthode HTTP modifiant l'état (POST, PUT, DELETE).

### 3.3. Secure Headers
*   `Strict-Transport-Security`: Force HTTPS.
*   `X-Content-Type-Options`: Bloque le sniffing MIME.
*   `X-Frame-Options`: Empêche le Clickjacking.
*   `X-XSS-Protection`: Active le filtre XSS du navigateur.

---

## 4. Flux de Données (Data Flow)

1.  **Requête Utilisateur** : Arrive sur Nginx -> Transmise à Gunicorn -> Traitée par Flask.
2.  **Validation** : `CheckEnv` valide la configuration. `WTForms` valide les entrées.
3.  **Logique Métier** : Le contrôleur (`routes/`) appelle un service (`services/`).
4.  **Service Externe** : Le service appelle une API (ex: VirusTotal) via `requests`.
5.  **Persistance** : Le résultat est stocké via SQLAlchemy.
6.  **Réponse** : Le contrôleur rend un template Jinja2 avec les données.

---

*Document Confidentiel - MOA Digital Agency*
