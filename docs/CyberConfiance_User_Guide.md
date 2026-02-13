# CyberConfiance - Guide Utilisateur Complet

Ce guide vous accompagne pas à pas dans l'utilisation de tous les outils de sécurité de la plateforme CyberConfiance.

**Public cible** : Citoyens, Décideurs, Professionnels.
**Version** : 2.1

---

## 1. Analyseur de Sécurité Unifié (`/outils/analyseur-securite`)

**Objectif** : Vérifier si un fichier, une adresse web (URL) ou une adresse IP est dangereux avant de cliquer ou d'ouvrir.

### Comment l'utiliser ?

#### 1.1. Analyser un Lien (URL)
1.  Copiez l'adresse du site web douteux (ex: `http://offre-speciale-kdo.com`).
2.  Allez dans **Outils > Analyseur de Sécurité**.
3.  Sélectionnez l'onglet **URL**.
4.  Collez le lien et cliquez sur **Analyser**.
5.  **Résultat** : Un score de risque (0-100) s'affiche.
    *   **Vert** : Site légitime connu.
    *   **Rouge** : Site de phishing ou malware détecté.
    *   **Détails** : Cliquez pour voir les redirections suspectes (ex: `bit.ly` -> `site-hacke.com`).

#### 1.2. Analyser un Fichier
1.  Sélectionnez l'onglet **Fichier**.
2.  Cliquez sur **Choisir un fichier** (Max 50 Mo).
3.  L'outil calcule l'empreinte numérique (Hash) du fichier sans l'ouvrir.
4.  Il interroge 70+ antivirus mondiaux (VirusTotal).
5.  **Résultat** : Nombre de détections (ex: "3/72 moteurs ont détecté un Trojan").

---

## 2. Analyseur de QR Code (`/outils/analyseur-qrcode`)

**Objectif** : Scanner un QR code sans risque de se faire pirater via "Quishing" (QR Phishing).

### Comment l'utiliser ?
1.  Prenez une photo du QR code suspect ou faites une capture d'écran.
2.  Allez dans **Outils > Analyseur QR Code**.
3.  Chargez l'image ou utilisez la caméra de votre appareil.
4.  **Analyse** :
    *   L'outil décode le lien caché.
    *   Il vérifie s'il redirige vers un site malveillant.
    *   Il détecte les pièges JavaScript.
5.  **Verdict** : "Sûr" ou "Dangereux" avec l'URL réelle affichée en clair.

---

## 3. Quiz de Cybersécurité (`/quiz`)

**Objectif** : Évaluer votre niveau de vigilance numérique et recevoir des conseils personnalisés.

### Déroulement
1.  Répondez à **15 questions** aléatoires sur 3 thèmes :
    *   **Vigilance** (Phishing, Arnaques).
    *   **Technique** (Mots de passe, Wifi).
    *   **Hygiène** (Mises à jour, Sauvegardes).
2.  Obtenez votre **Score Global** (ex: 75%).
3.  Consultez les **Recommandations** basées sur vos erreurs.
4.  (Optionnel) Entrez votre email pour vérifier s'il a déjà fuité.

---

## 4. Vérification de Fuites (`/analyze-breach`)

**Objectif** : Savoir si vos mots de passe ont été volés lors d'un piratage de site web (LinkedIn, Adobe, Canva, etc.).

### Comment faire ?
1.  Entrez votre adresse email professionnelle ou personnelle.
2.  L'outil interroge la base mondiale **Have I Been Pwned**.
3.  **Résultat** :
    *   "Bonne nouvelle" : Aucune fuite connue.
    *   "Attention" : Votre email apparaît dans X fuites de données.
4.  **Action requise** : Changez immédiatement les mots de passe des sites listés.

---

## 5. Analyseur de Prompt IA (`/outils/analyseur-prompt`)

**Objectif** : Vérifier qu'un texte envoyé à ChatGPT ou une autre IA ne contient pas de données sensibles ou d'injections.

### Usage
1.  Collez votre prompt (texte de commande).
2.  L'outil détecte :
    *   Données confidentielles (Clés API, Emails, Noms).
    *   Tentatives d'injection ("Ignore previous instructions").
3.  Obtenez une version "nettoyée" à utiliser sans risque.

---

## 6. Analyseur GitHub (`/outils/github-analyzer`)

**Objectif** : Auditer rapidement la sécurité d'un projet Open Source avant de l'installer.

### Usage
1.  Collez l'URL du dépôt GitHub (ex: `https://github.com/user/projet`).
2.  L'outil scanne le code source (sans l'exécuter).
3.  Il détecte :
    *   Mots de passe oubliés dans le code.
    *   Dépendances périmées.
    *   Code de mauvaise qualité ("Vibecoding").
4.  Téléchargez le rapport PDF complet pour votre DSI.

---

## 7. Rapports PDF

Pour chaque outil, un bouton **"Télécharger le Rapport PDF"** est disponible.
Ces rapports professionnels contiennent :
*   Le résumé exécutif (pour la direction).
*   Les détails techniques (pour l'IT).
*   La preuve d'audit (Date, Heure, ID unique).

---

*CyberConfiance - Guide Utilisateur v2.1*
