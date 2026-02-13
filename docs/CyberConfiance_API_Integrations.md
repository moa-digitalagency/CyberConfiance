# CyberConfiance - Intégrations API Externes

Ce document détaille les APIs tierces utilisées par CyberConfiance pour ses fonctions d'analyse de sécurité.

**Version** : 2.1
**Mise à jour** : 2025

---

## 1. Have I Been Pwned (HIBP)

**Usage** : Vérification des fuites de données (Email Breach).
**Service** : `services/breach/hibp.py`

### Configuration
*   **Variable d'environnement** : `HIBP_API_KEY`
*   **Coût** : ~3.50$/mois (Plan Commercial).
*   **Rate Limit** : 1 requête / 1.5 secondes.

### Fonctionnement
1.  **Requête** : `GET https://haveibeenpwned.com/api/v3/breachedaccount/{account}`
2.  **Headers** : `hibp-api-key: <KEY>`, `user-agent: CyberConfiance-App`.
3.  **Réponse** : Liste JSON des brèches (Nom, Domaine, Date, Description, DataClasses).
4.  **Confidentialité** : Seul l'email est envoyé. Pas de mot de passe.
5.  **K-Anonymity** : (Implémenté partiellement pour les passwords si activé).

---

## 2. VirusTotal (VT)

**Usage** : Analyse de fichiers, URLs et IPs (Security Analyzer).
**Service** : `services/security/virustotal.py`

### Configuration
*   **Variable d'environnement** : `SECURITY_ANALYSIS_API_KEY` (ou `VT_API_KEY`).
*   **Coût** : Gratuit (500 req/jour) ou Premium.
*   **Rate Limit** : 4 requêtes / minute (Plan Gratuit).

### Fonctionnement (Fichier)
1.  **Hash Check** : Calcul du SHA-256 local.
2.  **Requête 1** : `GET https://www.virustotal.com/api/v3/files/{hash}`
    *   Si trouvé : Retourne le rapport cached.
3.  **Requête 2 (Si inconnu)** : `POST https://www.virustotal.com/api/v3/files` (Upload < 32Mo).
    *   Retourne un `analysis_id`.
4.  **Polling** : Vérification périodique du statut jusqu'à complétion.

### Fonctionnement (URL)
1.  **Requête** : `POST https://www.virustotal.com/api/v3/urls` (`url=<target>`).
2.  **Réponse** : `id` de l'analyse.
3.  **Polling** : `GET https://www.virustotal.com/api/v3/analyses/{id}`.

---

## 3. Google Safe Browsing (GSB)

**Usage** : Détection rapide de Phishing/Malware (URL Analyzer).
**Service** : `services/security/google_safe_browsing.py`

### Configuration
*   **Clé API** : Incluse dans `SECURITY_ANALYSIS_API_KEY` ou séparée `GSB_API_KEY`.
*   **Coût** : Gratuit (Quota élevé).

### Fonctionnement
1.  **Requête** : `POST https://safebrowsing.googleapis.com/v4/threatMatches:find`
2.  **Payload** : Liste d'URLs à vérifier.
3.  **Réponse** : Liste des menaces (`SOCIAL_ENGINEERING`, `MALWARE`, `UNWANTED_SOFTWARE`).

---

## 4. URLScan.io (Optionnel)

**Usage** : Analyse comportementale profonde (Screenshot, DOM).
**Service** : `services/security/urlscan.py`

### Configuration
*   **Variable** : `URLSCAN_API_KEY` (Optionnel).

### Fonctionnement
*   Soumet l'URL pour un scan public ou privé.
*   Récupère : Screenshot, IP de l'hôte, Technologies détectées (Wappalyzer).
*   Utile pour les investigations forensiques manuelles.

---

## 5. URLhaus (Abuse.ch)

**Usage** : Base de données communautaire de Malwares.
**Service** : `services/security/urlhaus.py`

### Configuration
*   **Accès** : Open Data (Pas de clé requise).

### Fonctionnement
*   Vérification si le domaine/URL est présent dans la blacklist active.
*   Focus sur les C2 (Command & Control) de Botnets.

---

## 6. Gestion des Erreurs et Fallbacks

Le service `SecurityAnalyzerService` orchestre ces APIs avec une logique de résilience :
1.  Si **VirusTotal** échoue (Quota/Timeout) -> Fallback sur **GSB**.
2.  Si **GSB** échoue -> Fallback sur **URLhaus** + Analyse Heuristique locale.
3.  Si tout échoue -> Retourne "Analyse Incomplète" (Code 206) mais ne plante pas.

Chaque appel externe est wrappé dans un `try/except` avec logging spécifique.

---

*CyberConfiance - API Documentation*
