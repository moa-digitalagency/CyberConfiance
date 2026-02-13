# CyberConfiance - Guide Administrateur

Ce document est réservé aux administrateurs de la plateforme CyberConfiance. Il décrit les outils de gestion, la modération et la maintenance.

**Accès** : Restreint (Rôle 'admin' requis).
**Version** : 2.1
**Mise à jour** : 2025

---

## 1. Accès au Panneau d'Administration

L'URL d'administration est obfusquée par sécurité :
`https://votre-domaine.com/my4dm1n/admin/`

**Identifiants par défaut** (A changer impérativement !) :
*   **Utilisateur** : `admin`
*   **Mot de passe** : Défini via la variable d'environnement `ADMIN_PASSWORD`.

---

## 2. Tableau de Bord (Dashboard)

Le tableau de bord (`/my4dm1n/admin/`) offre une vue synoptique de l'activité :
*   **KPIs** : Nombre total d'analyses (Fichiers, URLs, QR, Quiz), Requêtes en attente.
*   **Graphiques** : Évolution des menaces détectées sur 30 jours.
*   **Logs Récents** : Dernières connexions, erreurs critiques.

---

## 3. Gestion des Contenus (CMS)

### 3.1. Articles et Actualités (`/my4dm1n/content/news/`)
*   **Ajouter** : Titre, Contenu (HTML autorisé), Image, Date de publication.
*   **Modifier** : Correction de coquilles, mise à jour des liens.
*   **Supprimer** : Archivage définitif.

### 3.2. Règles d'Or et Scénarios (`/my4dm1n/content/rules/`)
*   **Règles** : Les 20 principes fondamentaux affichés sur la page d'accueil.
*   **Scénarios** : Les cas pratiques utilisés dans le Quiz.

### 3.3. Glossaire (`/my4dm1n/content/glossary/`)
*   Définitions des termes techniques (Phishing, Ransomware, etc.).
*   Indispensable pour le SEO et la pédagogie.

---

## 4. Gestion des Requêtes Utilisateurs (`/my4dm1n/requests/`)

Lorsqu'un utilisateur soumet une demande (Fact-Checking, Consultation, OSINT), elle apparaît ici.

### Workflow de Traitement :
1.  **Réception** : Statut "Pending" (En attente).
2.  **Analyse** : L'admin vérifie la demande (Pièces jointes scannées automatiquement).
3.  **Traitement** : L'admin répond à l'utilisateur ou initie l'action.
4.  **Clôture** : Passage au statut "Completed" ou "Rejected".
5.  **Note Interne** : Champ "Admin Notes" pour la traçabilité.

---

## 5. Historique des Analyses (Audit)

Chaque outil dispose de son propre journal d'audit complet :
*   **Security Analysis** : Détails des fichiers/URLs scannés (Hash, Score VT).
*   **Breach Analysis** : Emails vérifiés (sans les résultats HIBP sensibles).
*   **Quiz Results** : Scores et réponses des participants.
*   **QR Code Analysis** : URLs décodées et niveau de menace.
*   **GitHub Analysis** : Repos audités et vulnérabilités trouvées.

**Fonctionnalités** :
*   Recherche par ID unique (`document_code`) ou Email.
*   Export PDF du rapport original.
*   Suppression des données (Droit à l'oubli).

---

## 6. Configuration du Site (`/my4dm1n/settings/`)

Permet de modifier les paramètres globaux sans redéployer le code :
*   **Maintenance Mode** : Activer/Désactiver l'accès public.
*   **Message d'Alerte** : Bannière en haut de site (ex: "Maintenance prévue ce soir").
*   **SEO** : Titres et descriptions par défaut.
*   **Contact** : Email de support affiché.

---

## 7. Logs de Sécurité (`/my4dm1n/logs/`)

### 7.1. Security Logs
Trace les événements critiques du système :
*   `LOGIN_FAIL` : Tentative de connexion admin échouée (IP, User-Agent).
*   `CSRF_ERROR` : Token invalide (Attaque potentielle ou Session expirée).
*   `CRITICAL_ERROR` : Exception non gérée (Bug application).

### 7.2. Threat Logs
Trace les menaces détectées chez les utilisateurs :
*   `MALWARE_DETECTED` : Un utilisateur a tenté d'analyser un fichier infecté.
*   `PHISHING_URL` : Une URL malveillante a été soumise.
*   **Action** : Ces logs permettent d'identifier les campagnes d'attaques en cours.

---

## 8. Maintenance Technique

### 8.1. Sauvegarde
Un dump SQL quotidien est recommandé (voir `Installation.md`).

### 8.2. Mise à Jour des Données de Menaces
Les APIs (VirusTotal, HIBP) sont interrogées en temps réel, aucune mise à jour manuelle de base de signatures n'est requise.

### 8.3. Nettoyage
Un script automatique (cron) purge les fichiers temporaires du dossier `uploads/` toutes les 24h.

---

*CyberConfiance - Admin Guide - Confidentiel*
