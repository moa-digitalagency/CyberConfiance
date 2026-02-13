# CyberConfiance - Liste Exhaustive des Fonctionnalités ("The Bible")

Ce document recense **chaque fonctionnalité** de la plateforme CyberConfiance dans ses moindres détails techniques et fonctionnels. Il sert de référence absolue pour les développeurs, auditeurs et administrateurs.

**Version du document** : 1.0
**Dernière mise à jour** : 2025

---

## 1. Moteur d'Analyse de Sécurité Unifié

Le cœur de la plateforme repose sur un système d'analyse multi-vecteurs capable de traiter fichiers, URLs, IPs et textes via une orchestration de services tiers et d'algorithmes internes.

### 1.1. Analyseur d'URLs et Domaines (`/outils/analyseur-liens`, `/outils/analyseur-securite`)
*   **Validation Stricte** : Utilisation de `utils.security_utils.is_safe_url_strict` pour bloquer les SSRF (Server-Side Request Forgery), les IPs privées/réservées et les boucles locales.
*   **Trçage de Redirections** :
    *   Suit jusqu'à 10 sauts de redirection (HTTP 301, 302, 303, 307, 308).
    *   Détecte les boucles de redirection infinies.
    *   Capture les headers HTTP à chaque saut pour analyse forensique.
    *   Gère les URLs relatives et absolues via `urllib.parse.urljoin`.
*   **Moteurs de Détection** :
    *   **VirusTotal API** : Vérification de la réputation du domaine et de l'URL spécifique (Ratio malveillant/suspect).
    *   **Google Safe Browsing** : Détection de phishing et malware via API v4.
    *   **URLhaus** : Vérification contre la base de données de distribution de malwares (Abuse.ch).
    *   **URLScan.io** : Analyse comportementale et captures d'écran (si configuré).
    *   **Détection Interne** :
        *   Identification de 100+ raccourcisseurs d'URL (bit.ly, tinyurl, etc.).
        *   Détection de 40+ domaines de tracking et IP loggers connus (grabify, iplogger, etc.).
*   **Rapport** : Génération d'un score de risque (0-100) et d'un niveau de menace (Sûr, Faible, Moyen, Élevé, Critique).

### 1.2. Analyseur de Fichiers (`/outils/analyseur-securite`)
*   **Upload Sécurisé** :
    *   Limite de taille : 50 Mo (configurable).
    *   Stockage temporaire avec noms de fichiers sécurisés (UUID).
    *   Nettoyage automatique des fichiers après analyse.
*   **Identification de Type** :
    *   Utilisation de `python-magic` et `filetype` pour déterminer le vrai type MIME (protection contre le renommage d'extension malveillant).
*   **Hachage** : Calcul des empreintes MD5, SHA-1 et SHA-256.
*   **Scan VirusTotal** :
    *   Recherche par hash (évite l'upload si le fichier est déjà connu).
    *   Upload du fichier si inconnu (mise en file d'attente asynchrone).
*   **Résultats** : Affichage des détections antivirus, score de réputation et lien permalink VirusTotal.

### 1.3. Analyseur de QR Codes (`/outils/analyseur-qrcode`)
*   **Entrée** : Supporte l'upload d'images (PNG, JPG, WEBP, GIF) et la capture caméra directe (Base64).
*   **Décodage** : Utilisation de `pyzbar` et `opencv` pour extraire les données brutes du QR code.
*   **Analyse de la Charge Utile** :
    *   Si c'est une URL : Lancement automatique du pipeline d'analyse d'URL (voir 1.1).
    *   Si c'est du texte : Analyse heuristique pour détecter des patterns suspects.
*   **Détection Spécifique "Quishing"** :
    *   Identification de redirections JavaScript obfusquées.
    *   Détection de doubles extensions ou de caractères homoglyphes.

### 1.4. Analyseur de Prompts LLM (`/outils/analyseur-prompt`)
*   **Objectif** : Détecter les tentatives d'injection de prompt et les fuites de données avant envoi à une IA.
*   **Détection d'Injection** :
    *   Patterns connus ("Ignore previous instructions", "DAN mode", etc.).
    *   Tentatives de jailbreak et d'évasion de contexte.
*   **Détection de Code Malveillant** :
    *   Recherche de commandes système (`rm -rf`, `wget`, `curl`).
    *   Détection de code obfusqué (Base64, Hex).
*   **Sanitisation** : Proposition d'une version "nettoyée" du prompt.
*   **Analyse de Longueur** : Limite à 50 000 caractères pour prévenir les attaques par déni de service (DoS).

### 1.5. Analyseur de Métadonnées (`/outils/analyseur-metadonnee`)
*   **Support Multi-Formats** : Images (JPG, PNG, TIFF, HEIC), Vidéos (MP4, MOV, AVI), Audio (MP3, WAV).
*   **Extraction** :
    *   **EXIF** : Modèle d'appareil, date de prise de vue, paramètres d'exposition via `exifread` et `piexif`.
    *   **GPS** : Extraction et conversion des coordonnées géographiques (Latitude/Longitude).
    *   **IPTC/XMP** : Mots-clés, descriptions, informations de copyright.
*   **Nettoyage (Privacy)** :
    *   Suppression irréversible des métadonnées pour anonymiser le fichier.
    *   Génération d'un nouveau fichier "propre" téléchargeable.
    *   Traitement en mémoire pour éviter la persistance sur disque.

### 1.6. Analyseur de Code GitHub (`/outils/github-analyzer` - BETA)
*   **Clonage** : Clone partiel (`depth=100`) des dépôts publics pour analyse statique.
*   **Analyse Statique (SAST)** :
    *   **Secrets** : Recherche de clés API (AWS, Stripe, Google), mots de passe et tokens via Regex (200+ patterns).
    *   **Vulnérabilités** : Détection de failles OWASP (SQLi, XSS, Command Injection) via motifs syntaxiques.
    *   **Dépendances** : Analyse des fichiers `package.json`, `requirements.txt` pour identifier les paquets obsolètes ou dangereux.
    *   **Qualité Code** : Détection de "Code Smells", complexité cyclomatique élevée, manque de tests.
    *   **"Vibecoding"** : Détection de code généré par IA non relu (commentaires TODO, FIXME, structures vides).
*   **Scoring** : Calcul d'un score global pondéré (Sécurité 35%, Dépendances 15%, Architecture 15%, etc.).

---

## 2. Outils Utilisateur et Services

### 2.1. Quiz de Cybersécurité Interactif (`/quiz`)
*   **Logique** : 15 questions aléatoires tirées d'une base de données JSON (`quiz_questions.json`) couvrant 3 catégories (Vigilance, Technique, Hygiène).
*   **Scoring** : Calcul en temps réel du score global et par catégorie.
*   **Intégration HIBP** : Option pour vérifier son email via l'API "Have I Been Pwned" à la fin du quiz.
*   **Recommandations** : Génération de conseils personnalisés basés sur les mauvaises réponses.
*   **Persistance** : Sauvegarde des résultats en base (`QuizResult`) avec un `document_code` unique pour consultation ultérieure.

### 2.2. Vérification de Fuites de Données (`/analyze-breach`)
*   **API HIBP v3** : Interrogation de la base "Have I Been Pwned" (nécessite clé API).
*   **Confidentialité** : L'email est envoyé via TLS ; aucune donnée de mot de passe n'est traitée.
*   **Détails des Fuites** : Récupération du nom de la fuite, date, description, et types de données compromises (Email, IP, MDP, etc.).
*   **Scénarios** : Mapping automatique des données compromises vers des scénarios de risque (ex: "Mot de passe compromis" -> "Risque de Credential Stuffing").

### 2.3. Formulaires de Soumission (`/services/*`)
*   **Types** : Fact-Checking, Cyberconsultation, Investigation OSINT, Signalement Cybercrime.
*   **Sécurité** :
    *   Protection CSRF sur tous les formulaires.
    *   Scan automatique des pièces jointes et URLs soumises via le moteur de sécurité unifié.
    *   Support de la soumission anonyme (champs optionnels).
*   **Suivi** : Génération d'un code de suivi unique (ex: `REQ-2025-XXXX`) et d'un QR code pour que l'utilisateur puisse vérifier l'état de sa demande.

### 2.4. Rapports PDF (`/generate-*-pdf/*`)
*   **Génération** : Utilisation de `PyMuPDF` (fitz) et `Pillow` pour créer des documents PDF vectoriels.
*   **Contenu** : Mise en page professionnelle, logos vectoriels, tableaux de résultats, graphiques de scores, recommandations colorées.
*   **Mise en Cache** : Stockage du binaire PDF en base de données (`LargeBinary`) pour éviter la régénération coûteuse.
*   **Téléchargement** : Headers HTTP configurés pour forcer le téléchargement (`Content-Disposition: attachment`).

---

## 3. Interface d'Administration (`/my4dm1n/admin`)

### 3.1. Sécurité et Accès
*   **URL Obfusquée** : `/my4dm1n/admin` au lieu du standard `/admin`.
*   **Authentification** : Basée sur `Flask-Login` avec décorateurs `@admin_required`.
*   **Protection Brute-Force** : `Flask-Limiter` restreint les tentatives de connexion.
*   **Rôles** : Distinction entre Admin (accès total) et Modérateur (accès lecture/traitement).

### 3.2. Tableau de Bord (Dashboard)
*   **Statistiques** : Compteurs en temps réel (Total Analyses, Menaces Bloquées, Utilisateurs, Requêtes).
*   **Graphiques** : Visualisation de l'activité sur 30 jours.
*   **Logs** : Flux d'activité récent.

### 3.3. Gestion des Données (CRUD)
*   **Analyses** : Vue détaillée de tous les historiques (Security, Breach, QR, GitHub, Prompt, Metadata). Possibilité de supprimer ou d'exporter.
*   **Requêtes Utilisateurs** : Workflow de traitement (Statuts : Pending -> In Progress -> Completed/Rejected). Ajout de notes internes.
*   **Contenu** : Éditeur pour les Articles de Blog, Règles d'Or, Scénarios, Outils et Glossaire.
*   **Paramètres** : Configuration à chaud du site (Logos, Textes, SEO, Scripts Header/Footer) via la table `SiteSettings`.

### 3.4. Journaux et Audit
*   **ActivityLog** : Trace toutes les actions administratives (qui a modifié quoi).
*   **SecurityLog** : Enregistre les échecs de connexion, erreurs CSRF et exceptions critiques.
*   **ThreatLog** : Journal détaillé des menaces détectées par les outils utilisateurs (IP source, User-Agent, Type de menace).

---

## 4. Architecture Technique et Sécurité

### 4.1. Sécurité Applicative
*   **CSP (Content Security Policy)** : Configuration stricte avec `nonce` généré à chaque requête (`secrets.token_hex(16)`).
    *   `script-src 'self' 'nonce-{nonce}' ...`
    *   Empêche l'exécution de scripts XSS non autorisés.
*   **CSRF (Cross-Site Request Forgery)** : Tokens `Flask-WTF` obligatoires sur toutes les méthodes POST/PUT/DELETE.
*   **Secure Headers** : Injection automatique via `@app.after_request`.
    *   `Strict-Transport-Security` (HSTS)
    *   `X-Content-Type-Options: nosniff`
    *   `X-Frame-Options: SAMEORIGIN`
    *   `X-XSS-Protection: 1; mode=block`
*   **Rate Limiting** : Protection globale et par route via `Flask-Limiter` (Stockage en mémoire).
*   **Sanitization** : Nettoyage des entrées HTML via `bleach` ou filtres personnalisés (`striptags`).

### 4.2. Base de Données (PostgreSQL)
*   **ORM** : SQLAlchemy avec 18 modèles relationnels.
*   **Migrations** : Gérées par `Alembic` (historique des schémas).
*   **Indexation** : Index sur les colonnes fréquemment recherchées (`document_code`, `email`, `created_at`).
*   **Seeds** : Système de peuplement initial (`utils/seed_data.py`) chargeant les données depuis des fichiers JSON (`data/*.json`).

### 4.3. Gestion des Fichiers et Assets
*   **Glassmorphism** : CSS personnalisé utilisant `backdrop-filter: blur()` et des dégradés semi-transparents.
*   **Mode Sombre/Clair** : Gestion via variables CSS (`:root`) et stockage de la préférence dans `localStorage` + Cookie.
*   **Internationalisation** : `Flask-Babel` pour les traductions (fichiers `.po/.mo`), détection auto via header `Accept-Language`.

### 4.4. Tâches de Fond et Performance
*   **File d'attente** : Traitement asynchrone (simulé via ThreadPoolExecutor pour l'instant) pour les scans longs (GitHub, VirusTotal).
*   **Mise en cache** : Cache HTTP pour les ressources statiques (`Expires`, `Cache-Control`).
*   **Compression** : Assets minimisés (bien que servis par Flask en dev, recommandation Nginx en prod).

---

## 5. Intégrations API Externes

| Service | Usage | Auth | Critique ? |
| :--- | :--- | :--- | :--- |
| **Have I Been Pwned** | Vérification fuites emails | API Key (Header) | Oui (Breach Check) |
| **VirusTotal** | Scan fichiers/URLs/IPs | API Key (Header) | Oui (Security Analyzer) |
| **Google Safe Browsing** | Phishing/Malware check | API Key (Query) | Non (Fallback) |
| **URLScan.io** | Analyse profonde URL | API Key (Header) | Non (Optionnel) |
| **URLhaus** | Malware URL database | Open API | Non (Fallback) |

---

*Ce document est la propriété de CyberConfiance. Toute modification doit être validée par l'équipe technique.*
