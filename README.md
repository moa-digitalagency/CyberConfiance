# 🛡️ CyberConfiance

**Le Bouclier Numérique pour l'Afrique Francophone**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-green?style=flat&logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success?style=flat)]()
[![Code Style](https://img.shields.io/badge/Code%20Style-Black-000000.svg)](https://github.com/psf/black)

---

## 🚀 Pitch

**CyberConfiance** est la première plateforme de cybersécurité unifiée conçue spécifiquement pour les dirigeants, décideurs et citoyens d'Afrique francophone.
Elle démocratise l'accès aux outils d'analyse forensique (VirusTotal, HIBP) et à l'éducation numérique via une interface simple, bilingue et adaptée aux réalités locales (Mobile Money, Phishing WhatsApp).

> *"La sécurité n'est pas un luxe, c'est un droit."*

---

## 📑 Table des Matières

1.  [Fonctionnalités Clés](#-fonctionnalités-clés)
2.  [Stack Technique](#-stack-technique)
3.  [Installation Rapide](#-installation-rapide)
4.  [Architecture](#-architecture)
5.  [Documentation Complète](#-documentation-complète)
6.  [Auteurs & Crédits](#-auteurs--crédits)

---

## 🌟 Fonctionnalités Clés

### 🔍 Analyseur de Sécurité Unifié
Vérifiez instantanément la dangerosité d'un fichier, d'une URL ou d'une IP grâce à l'agrégation de **70+ moteurs antivirus** (VirusTotal, Google Safe Browsing, URLhaus).
> *Supporte : Uploads jusqu'à 50Mo, Détection de Phishing, Ransomware check.*

### 📱 Analyseur de QR Code (Anti-Quishing)
Protégez-vous contre les QR codes malveillants. L'outil décode l'URL, suit les redirections et analyse la destination finale avant que vous ne scanniez.
> *Supporte : Images, Caméra directe, Détection de trackers.*

### 🧠 Quiz de Cybersécurité Interactif
Évaluez votre niveau de vigilance avec 15 questions dynamiques. Recevez un score, des recommandations personnalisées et vérifiez si votre email a fuité (HIBP).
> *Inclus : Scoring par catégorie (Vigilance, Technique, Hygiène).*

### 🤖 Analyseur de Code & Prompts (BETA)
*   **GitHub Analyzer** : Auditez la sécurité d'un dépôt Open Source (Secrets, Failles, Qualité) avant intégration.
*   **Prompt Analyzer** : Nettoyez vos prompts IA des données sensibles et injections.

### 🛡️ Services Citoyens
*   **Fact-Checking** : Vérification des Fake News.
*   **Signalement** : Rapport de cybercriminalité anonyme.
*   **Rapports PDF** : Génération de preuves d'audit professionnelles.

---

## 🛠 Stack Technique

**Backend**
*   Python 3.11+
*   Flask 3.0 (Blueprints, Application Factory)
*   SQLAlchemy (ORM) + PostgreSQL 14+
*   Celery (Background Tasks - *Roadmap*)

**Sécurité & APIs**
*   **Have I Been Pwned** (Fuites de données)
*   **VirusTotal** (Intelligence des menaces)
*   **Google Safe Browsing** (Anti-Phishing)
*   **Flask-WTF** (CSRF Protection)
*   **CSP Nonces** (Content Security Policy stricte)

**Frontend**
*   HTML5 / CSS3 (Glassmorphism Design System)
*   JavaScript (Vanilla ES6+)
*   Jinja2 (Templating)
*   Bootstrap (Admin Panel uniquement)

---

## ⚡ Installation Rapide

### Prérequis
*   Python 3.11+
*   PostgreSQL (ou SQLite pour dev)
*   Clés API (HIBP, VirusTotal)

### 1. Cloner le projet
```bash
git clone https://github.com/votre-org/CyberConfiance.git
cd CyberConfiance
```

### 2. Environnement Virtuel
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configuration (.env)
```bash
# Créez un fichier .env à la racine
DATABASE_URL=postgresql://user:pass@localhost:5432/cyberconfiance
SECRET_KEY=votre_secret_key_securise
ADMIN_PASSWORD=MonMotDePasseAdmin!
HIBP_API_KEY=votre_cle_hibp
SECURITY_ANALYSIS_API_KEY=votre_cle_virustotal
FLASK_DEBUG=True
```

### 4. Initialisation
```bash
python init_db.py  # Crée les tables et les données de base
```

### 5. Lancement
```bash
python main.py
# Accédez à http://localhost:5000
```

---

## 🏗 Architecture

Le projet suit une architecture MVC modulaire :

```
CyberConfiance/
├── main.py                  # Point d'entrée
├── services/                # Logique Métier (Security, Breach, PDF...)
├── routes/                  # Contrôleurs (Blueprints)
├── models/                  # Schéma de Base de Données
├── templates/               # Vues (Jinja2)
└── static/                  # Assets (CSS/JS/Img)
```

---

## 📚 Documentation Complète

Pour aller plus loin, consultez la documentation détaillée dans le dossier `docs/` :

*   📖 **[La Bible des Fonctionnalités](docs/CyberConfiance_Features_Full_List.md)** (Liste exhaustive)
*   🏗️ **[Architecture Technique](docs/CyberConfiance_Architecture.md)** (Stack, Flux, DB)
*   💻 **[Guide d'Installation](docs/CyberConfiance_Installation.md)** (Déploiement VPS/Replit)
*   🔒 **[Sécurité (Whitepaper)](docs/CyberConfiance_Security.md)** (CSP, CSRF, Privacy)
*   👤 **[Guide Utilisateur](docs/CyberConfiance_User_Guide.md)** (Tutoriels Outils)
*   💼 **[Vision Business](docs/CyberConfiance_Business_Value.md)** (Mission & Stratégie)
*   ⚙️ **[Guide Admin](docs/CyberConfiance_Admin_Guide.md)** (Back-office)
*   🔌 **[APIs Externes](docs/CyberConfiance_API_Integrations.md)** (HIBP, VT, GSB)

---

## ✍ Auteurs & Crédits

**Produit par** : MOA Digital Agency (www.myoneart.com)
**Développé par** : Aisance KALONJI (www.aisancekalonji.com)
**Audité par** : La CyberConfiance (www.cyberconfiance.com)

*Copyright © 2025 CyberConfiance. Tous droits réservés.*
