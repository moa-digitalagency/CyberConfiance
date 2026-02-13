# CyberConfiance - Whitepaper de Sécurité

Ce document détaille l'approche "Security by Design" de la plateforme CyberConfiance, couvrant la confidentialité, l'intégrité et la disponibilité des données.

**Version** : 2.1
**Classification** : Public

---

## 1. Principes Fondamentaux

*   **Défense en Profondeur** : Superposition de contrôles (WAF, CSP, CSRF, Secure Headers, RBAC).
*   **Moindre Privilège** : Les utilisateurs (et l'application elle-même) n'ont accès qu'aux ressources nécessaires.
*   **Sanitization Stricte** : Toutes les entrées utilisateurs (fichiers, URLs, textes) sont considérées comme hostiles par défaut.
*   **Auditabilité** : Traçabilité complète des actions critiques via `ActivityLog`, `SecurityLog` et `ThreatLog`.

---

## 2. Protection des Données Utilisateur

### 2.1. Confidentialité (Privacy-First)
*   **Analyse Anonyme** : Les fichiers soumis pour analyse sont stockés temporairement avec des noms aléatoires (UUIDv4) et purgés immédiatement après le scan.
*   **Nettoyage de Métadonnées** : L'outil "Metadata Analyzer" permet aux utilisateurs de *retirer* les données GPS/EXIF sensibles avant partage.
*   **K-Anonymity (HIBP)** : Lors de la vérification de fuite de mot de passe (si implémentée), seul le préfixe du hash (5 premiers caractères) est envoyé à l'API, garantissant que le mot de passe complet ne quitte jamais le navigateur/serveur.
*   **Rétention Minimale** : Les logs d'activité sont conservés 30 jours par défaut (configurable).

### 2.2. Chiffrement
*   **En Transit (TLS 1.2/1.3)** :
    *   Tout le trafic HTTP est redirigé vers HTTPS (via Nginx/HSTS).
    *   HSTS (`Strict-Transport-Security`) activé avec `includeSubDomains` et `preload`.
*   **Au Repos** :
    *   Les mots de passe administrateurs sont hachés avec **Argon2** (via `Werkzeug.security`).
    *   Les clés API externes (`HIBP_KEY`, `VT_KEY`) sont injectées via variables d'environnement, jamais stockées en base ou dans le code.

---

## 3. Sécurité Applicative (AppSec)

### 3.1. Content Security Policy (CSP)
Une politique CSP stricte est appliquée via `__init__.py` pour mitiger les attaques XSS (Cross-Site Scripting).

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random_hex}' ...
```
*   **Nonces Dynamiques** : Chaque requête génère un token cryptographique unique (`secrets.token_hex(16)`). Seuls les scripts portant ce nonce sont exécutés.
*   **Restrictions** : `unsafe-inline` est interdit pour les scripts (sauf exceptions contrôlées), `eval()` est restreint.

### 3.2. Cross-Site Request Forgery (CSRF)
*   **Protection Globale** : `Flask-WTF` injecte un token CSRF unique dans chaque formulaire HTML (`<input type="hidden" name="csrf_token">`).
*   **Validation** : Le serveur rejette toute requête POST/PUT/DELETE sans token valide ou avec un token expiré.
*   **SameSite Cookies** : Les cookies de session sont marqués `SameSite=Lax` pour prévenir les attaques CSRF cross-origin.

### 3.3. Server-Side Request Forgery (SSRF)
Le module `utils.security_utils.is_safe_url_strict` valide rigoureusement les URLs soumises aux analyseurs :
*   **Résolution DNS Préalable** : L'hôte est résolu en IP *avant* la connexion.
*   **Blacklist IP** : Rejet des plages IP privées (10.0.0.0/8, 192.168.0.0/16, etc.), locales (127.0.0.0/8) et link-local.
*   **Schémas Autorisés** : Seuls `http://` et `https://` sont permis (pas de `file://`, `ftp://`, `gopher://`).

### 3.4. Input Validation & Sanitization
*   **Fichiers** :
    *   Validation du type MIME réel (Magic Bytes) via `python-magic`, pas seulement l'extension.
    *   Renommage forcé des fichiers uploadés (UUID) pour éviter les traversées de chemin (`../../etc/passwd`).
    *   Limite de taille stricte (50 Mo) via `MAX_CONTENT_LENGTH`.
*   **Texte/HTML** :
    *   Échappement automatique via Jinja2 (Autoescape True).
    *   Filtre `striptags` personnalisé pour nettoyer les entrées riches si nécessaire.

---

## 4. Protection de l'Infrastructure

### 4.1. Rate Limiting (Anti-DoS)
Implémenté via `Flask-Limiter` pour protéger les ressources coûteuses :
*   **Global** : 200 requêtes / jour / IP.
*   **Login Admin** : 5 tentatives / heure (Protection Brute-Force).
*   **API Analyse** : 10 scans / minute (Protection des quotas API externes).

### 4.2. Secure Headers
En-têtes HTTP de sécurité injectés systématiquement :
*   `X-Content-Type-Options: nosniff` (Empêche le MIME sniffing).
*   `X-Frame-Options: SAMEORIGIN` (Empêche le Clickjacking via iframes).
*   `X-XSS-Protection: 1; mode=block` (Défense en profondeur pour vieux navigateurs).
*   `Referrer-Policy: strict-origin-when-cross-origin` (Confidentialité du referrer).

---

## 5. Gestion des Incidents

### 5.1. Logging de Sécurité
*   **SecurityLog** : Enregistre les événements critiques (Login échoué, Erreur 500, CSRF invalide).
*   **ThreatLog** : Enregistre les métadonnées des menaces détectées (Hash de malware, URL de phishing).
*   **Alerting** : (Roadmap) Notification par email aux admins en cas de pic d'erreurs ou de détection critique.

### 5.2. Mises à Jour
*   **Dépendances** : Scan régulier via `pip-audit` ou `safety` (intégré dans le CI/CD recommandé).
*   **Base de Données de Menaces** : Mise à jour quotidienne des flux (Threat Intelligence) via les APIs connectées.

---

*CyberConfiance - Security Whitepaper*
