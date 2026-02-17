[ 🇫🇷 Français ] | [ [🇬🇧 English](README_en.md) ]

# 🛡️ CyberConfiance

**Le Bouclier Numérique pour l'Afrique Francophone**

![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat&logo=python)
![Framework](https://img.shields.io/badge/Framework-Flask%203.0-green?style=flat&logo=flask)
![Database](https://img.shields.io/badge/Database-PostgreSQL-336791?style=flat&logo=postgresql)
![Status: Private/Internal](https://img.shields.io/badge/Status-Private%2FInternal-red?style=flat)
![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red?style=flat)
![Owner: MOA Digital Agency](https://img.shields.io/badge/Owner-MOA%20Digital%20Agency-orange?style=flat)

---

## 🚀 Pitch

**CyberConfiance** est la première plateforme de cybersécurité unifiée conçue spécifiquement pour les dirigeants, décideurs et citoyens d'Afrique francophone. Développée par **MOA Digital Agency**, elle démocratise l'accès aux outils d'analyse forensique (VirusTotal, HIBP) et à l'éducation numérique via une interface simple, bilingue et adaptée aux réalités locales.

> *"La sécurité n'est pas un luxe, c'est un droit."* - Aisance KALONJI

---

## 🏗 Architecture Technique

```mermaid
graph TD
    User((Utilisateur)) -->|HTTPS| WebServer[Serveur Web (Flask)]

    subgraph "Core System"
        WebServer -->|SQLAlchemy| DB[(PostgreSQL)]
        WebServer -->|File I/O| Storage[Stockage Sécurisé]
        WebServer -->|Templates| Jinja[Moteur Jinja2]
    end

    subgraph "Security Services (APIs)"
        WebServer -->|API REST| VT[VirusTotal]
        WebServer -->|API REST| HIBP[Have I Been Pwned]
        WebServer -->|API REST| GSB[Google Safe Browsing]
    end

    style WebServer fill:#f9f,stroke:#333,stroke-width:2px
    style DB fill:#bbf,stroke:#333,stroke-width:2px
    style VT fill:#ddd,stroke:#333,stroke-width:1px
    style HIBP fill:#ddd,stroke:#333,stroke-width:1px
```

---

## 📑 Table des Matières

1.  [Fonctionnalités Clés](#-fonctionnalités-clés)
2.  [Installation & Démarrage](#-installation--démarrage)
3.  [Documentation Complète](#-documentation-complète)
4.  [Mentions Légales](#-mentions-légales)

---

## 🌟 Fonctionnalités Clés

*   **Analyseur Unifié :** Vérification de fichiers, URLs et IPs via 70+ moteurs antivirus.
*   **Anti-Quishing :** Décodage et analyse de sécurité des QR Codes avant scan.
*   **Quiz Interactif :** Évaluation ludique de la maturité cybernétique.
*   **Audit de Code (BETA) :** Analyse statique de dépôts GitHub pour détecter les secrets et vulnérabilités.
*   **Services Citoyens :** Fact-checking et signalement de cybercriminalité.

---

## ⚡ Installation & Démarrage

Ce projet est strictement interne. L'accès au code source est soumis à autorisation.

### Prérequis
*   Python 3.11+
*   PostgreSQL
*   Clés API (HIBP, VirusTotal)

### Lancement Rapide
```bash
# 1. Cloner (Accès restreint)
git clone https://github.com/moa-digital/CyberConfiance.git

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Configurer l'environnement
cp .env.example .env
# Editer .env avec les clés API et DATABASE_URL

# 4. Lancer l'application
python main.py
```

---

## 📚 Documentation Complète

Toute la documentation technique et fonctionnelle se trouve dans le dossier `docs/`.

*   📖 **[La Bible des Fonctionnalités](docs/CyberConfiance_Features_Full_List.md)** (Référence exhaustive)
*   🏗️ **[Architecture Technique](docs/CyberConfiance_Architecture.md)** (Stack, Flux, Sécurité)
*   👤 **[Guide Utilisateur](docs/CyberConfiance_User_Guide.md)** (Manuel d'utilisation)

---

## ⚖️ Mentions Légales

**Produit par** : MOA Digital Agency (www.myoneart.com)
**Auteur** : Aisance KALONJI
**Licence** : Propriétaire (Voir fichier `LICENSE`). Toute reproduction interdite.
