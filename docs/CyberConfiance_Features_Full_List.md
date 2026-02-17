[ 🇫🇷 Français ] | [ [🇬🇧 English](CyberConfiance_Features_Full_List_en.md) ]

# CyberConfiance - Liste Exhaustive des Fonctionnalités ("The Bible")

Ce document recense **chaque fonctionnalité** de la plateforme CyberConfiance dans ses moindres détails techniques et fonctionnels. Il sert de référence absolue pour les développeurs, auditeurs et administrateurs.

**Version du document** : 1.0
**Dernière mise à jour** : 2025

---

## 1. Moteur d'Analyse de Sécurité Unifié

Le cœur de la plateforme repose sur un système d'analyse multi-vecteurs capable de traiter fichiers, URLs, IPs et textes via une orchestration de services tiers et d'algorithmes internes.

### 1.1. Analyseur d'URLs et Domaines (`/outils/analyseur-liens`)
*   **Validation Stricte** : Utilisation de `utils.security_utils.is_safe_url_strict` pour bloquer les SSRF, les IPs privées/réservées et les boucles locales.
*   **Trçage de Redirections** :
    *   Suit jusqu'à 10 sauts de redirection (HTTP 301, 302, 303, 307, 308).
    *   Détecte les boucles de redirection infinies.
    *   Capture les headers HTTP à chaque saut.
*   **Moteurs de Détection** :
    *   **VirusTotal API** : Vérification de la réputation du domaine.
    *   **Google Safe Browsing** : Détection de phishing et malware.
    *   **URLhaus** : Base de données de distribution de malwares.
*   **Rapport** : Génération d'un score de risque (0-100) et d'un niveau de menace.

### 1.2. Analyseur de Fichiers
*   **Upload Sécurisé** : Limite de 50 Mo, noms de fichiers UUID, nettoyage automatique.
*   **Identification de Type** : Utilisation de `python-magic` pour le type MIME réel.
*   **Hachage** : MD5, SHA-1, SHA-256.
*   **Scan VirusTotal** : Recherche par hash ou upload asynchrone.

### 1.3. Analyseur de QR Codes (Anti-Quishing)
*   **Entrée** : Upload d'images ou caméra directe.
*   **Décodage** : `pyzbar` / `opencv`.
*   **Analyse** : Pipeline URL complet si le QR contient un lien.
*   **Quishing** : Détection de redirections obfusquées.

### 1.4. Analyseur de Prompts LLM
*   **Objectif** : Prévenir les injections de prompt et fuites de données.
*   **Détection** : Patterns d'injection ("DAN mode"), code malveillant, données sensibles.
*   **Sanitisation** : Proposition de version nettoyée.

### 1.5. Analyseur de Code GitHub (BETA)
*   **Clonage** : Partiel (`depth=100`).
*   **SAST** : Détection de secrets (Regex), vulnérabilités OWASP, dépendances obsolètes.
*   **Scoring** : Note pondérée (Sécurité, Qualité, Maintenance).

---

## 2. Outils Utilisateur et Services

### 2.1. Quiz de Cybersécurité
*   **Logique** : 15 questions aléatoires (Vigilance, Technique, Hygiène).
*   **HIBP** : Option de vérification de fuite d'email en fin de parcours.
*   **Persistance** : Sauvegarde des résultats (`QuizResult`) avec code unique.

### 2.2. Vérification de Fuites (`/analyze-breach`)
*   **API HIBP** : Interrogation sécurisée (TLS).
*   **Mapping** : Association des données compromises à des scénarios de risque.

### 2.3. Formulaires & Rapports PDF
*   **Sécurité** : CSRF tokens, scan des PJ.
*   **PDF** : Génération vectorielle via `PyMuPDF`.
*   **Suivi** : Code unique et QR code de statut.

---

## 3. Interface d'Administration (`/my4dm1n/admin`)

*   **Accès** : URL obfusquée, authentification forte, protection brute-force.
*   **Dashboard** : Statistiques temps réel, logs d'activité.
*   **CRUD** : Gestion complète des analyses, requêtes utilisateurs, et contenus (Blog, Glossaire).
*   **Audit** : Logs détaillés (`ActivityLog`, `SecurityLog`, `ThreatLog`).

---

## 4. Architecture Technique et Sécurité

*   **CSP** : `nonce` unique par requête pour les scripts.
*   **CSRF** : Protection `Flask-WTF` sur toutes les mutations.
*   **Secure Headers** : HSTS, X-Content-Type-Options, X-Frame-Options.
*   **Rate Limiting** : Protection globale et par route.
*   **Base de Données** : PostgreSQL + SQLAlchemy + Alembic.

---

*Ce document est la propriété de CyberConfiance. Toute modification doit être validée par l'équipe technique.*
