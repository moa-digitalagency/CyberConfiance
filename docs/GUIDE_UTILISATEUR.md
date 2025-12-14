# Guide Utilisateur - CyberConfiance

## Bienvenue sur CyberConfiance

CyberConfiance est une plateforme de cybersecurite qui vous aide a vous proteger contre les menaces en ligne. Ce guide vous explique comment utiliser chaque outil de maniere simple.

**Version**: 2.1  
**Derniere mise a jour**: Decembre 2025

---

## Les Outils Disponibles

### 1. Analyseur de QR Code (Anti-Quishing)

**Ou le trouver:** Menu > Outils > Analyseur QR Code

**A quoi ca sert:**
Cet outil vous permet de verifier si un QR code est dangereux AVANT de le scanner avec votre telephone. Il detecte les arnaques, les liens malveillants et les trackers caches.

**Comment l'utiliser:**
1. Prenez une photo du QR code suspect
2. Telechargez l'image sur le site (ou utilisez la camera)
3. L'outil analyse automatiquement le contenu
4. Lisez le verdict: vert = sur, orange = prudence, rouge = danger

**Ce que l'outil detecte:**
- **IP Loggers**: Liens qui capturent votre adresse IP et localisation
- **Trackers**: Elements qui suivent votre activite en ligne
- **Redirections cachees**: Liens qui vous emmenent ailleurs que prevu
- **Sites malveillants**: Pages connues pour distribuer des virus
- **Phishing**: Faux sites imitant des marques legitimes

**Resultat de l'analyse:**
Vous recevez un rapport clair avec:
- Le niveau de risque global (Sur, Faible, Moyen, Eleve, Critique)
- La liste des problemes detectes
- Des recommandations de securite
- Un bouton pour telecharger le rapport PDF

---

### 2. Analyseur de Securite

**Ou le trouver:** Menu > Outils > Analyseur de Securite

**A quoi ca sert:**
Verifiez si un fichier, une URL ou un domaine est dangereux. L'outil consulte plus de 70 sources de securite differentes pour vous donner un verdict fiable.

**Comment l'utiliser:**

*Pour une URL:*
1. Copiez l'adresse du site suspect
2. Collez-la dans le champ "URL"
3. Cliquez sur "Analyser"
4. Consultez les resultats

*Pour un fichier:*
1. Cliquez sur "Fichier"
2. Selectionnez le fichier a verifier
3. L'outil calcule son empreinte numerique
4. Il verifie si le fichier est connu comme malveillant

*Pour un domaine:*
1. Entrez le nom de domaine (ex: exemple.com)
2. L'outil verifie sa reputation
3. Vous obtenez l'historique de securite

**Ce que l'outil detecte:**
- Virus et malwares
- Ransomwares (logiciels de rancon)
- Chevaux de Troie
- Sites de phishing
- Domaines compromis

---

### 3. Analyseur de Prompt (Anti-Injection)

**Ou le trouver:** Menu > Outils > Analyseur Prompt

**A quoi ca sert:**
Cet outil analyse les textes pour detecter les tentatives d'injection malveillante, notamment dans les systemes d'intelligence artificielle.

**Comment l'utiliser:**
1. Collez le texte suspect dans la zone de saisie
2. Cliquez sur "Analyser"
3. L'outil detecte les patterns dangereux
4. Consultez le rapport avec les problemes identifies

**Ce que l'outil detecte:**
- Tentatives d'injection de prompts
- Code malveillant cache (eval, exec)
- Techniques d'obfuscation
- URLs et adresses IP suspectes dans le texte
- Tentatives de jailbreak

---

### 4. Analyseur de Code GitHub (BETA)

**Ou le trouver:** Menu > Outils > Analyseur GitHub

**A quoi ca sert:**
Analysez la securite d'un depot de code GitHub avant de l'utiliser. L'outil detecte les vulnerabilites, les mauvaises pratiques et le code "vibecoding" genere par IA sans verification.

**Comment l'utiliser:**
1. Copiez l'URL du depot GitHub (ex: https://github.com/user/repo)
2. Collez-la dans le champ URL
3. Selectionnez la branche (main par defaut)
4. Cliquez sur "Analyser"
5. Consultez le rapport detaille

**Ce que l'outil detecte:**
- **Secrets exposes**: Cles API, mots de passe dans le code
- **Injections SQL**: Requetes SQL vulnerables
- **XSS**: Failles Cross-Site Scripting
- **Dependances vulnerables**: Packages avec failles connues
- **Code IA toxique**: TODOs, FIXMEs, code non implemente
- **Problemes d'architecture**: Structure, tests manquants

**Resultat de l'analyse:**
- Score global sur 100
- Scores par categorie (securite, architecture, performance...)
- Liste des problemes avec recommandations
- Detection des langages et frameworks utilises

---

### 5. Verification des Fuites de Donnees

**Ou le trouver:** Menu > Outils > Verification Fuites

**A quoi ca sert:**
Verifiez si votre adresse email a ete compromise dans une fuite de donnees. Si c'est le cas, vos mots de passe pourraient etre en danger.

**Comment l'utiliser:**
1. Entrez votre adresse email
2. Cliquez sur "Verifier"
3. Consultez la liste des fuites detectees

**Que faire si des fuites sont detectees:**
- Changez immediatement vos mots de passe
- Activez la double authentification
- Utilisez des mots de passe uniques pour chaque site
- Surveillez vos comptes pour toute activite suspecte

---

### 6. Quiz Cybersecurite

**Ou le trouver:** Menu > Quiz

**A quoi ca sert:**
Testez vos connaissances en cybersecurite et identifiez vos points faibles. Le quiz analyse vos reponses et vous donne des conseils personnalises.

**Comment l'utiliser:**
1. Cliquez sur "Commencer le Quiz"
2. Repondez aux questions honnetement
3. Consultez votre score et vos resultats
4. Suivez les recommandations pour vous ameliorer

**Types de questions:**
- Securite des mots de passe
- Protection des donnees personnelles
- Detection des arnaques
- Bonnes pratiques sur les reseaux sociaux
- Securite des appareils mobiles

---

## Comprendre les Resultats

### Niveaux de Risque

| Couleur | Niveau | Signification |
|---------|--------|---------------|
| Vert | Sur | Aucun probleme detecte |
| Bleu | Faible | Elements mineurs a surveiller |
| Orange | Moyen | Prudence recommandee |
| Rouge clair | Eleve | Risque significatif |
| Rouge fonce | Critique | Danger immediat - Ne pas ouvrir |

### Icones Courantes

- **Triangle avec !**: Avertissement
- **Bouclier**: Protection/Securite
- **Oeil**: Tracker detecte
- **Lien**: Redirection
- **Cadenas**: Connexion securisee

---

## Les Rapports PDF

### Pourquoi telecharger un rapport?

- Garder une trace de l'analyse
- Partager les resultats avec quelqu'un
- Documentation pour signaler une arnaque
- Reference pour actions futures

### Contenu du rapport

1. **Resume**: Vue d'ensemble du probleme
2. **Details**: Explication technique
3. **Sources**: APIs de securite consultees (VirusTotal, Google Safe Browsing, etc.)
4. **Preuves**: Captures des redirections et trackers
5. **Recommandations**: Actions a entreprendre
6. **Reference**: Date, heure et identifiant unique

---

## Conseils de Securite

### QR Codes

- Ne scannez jamais un QR code colle par-dessus un autre
- Mefiez-vous des QR codes dans les emails non sollicites
- Verifiez toujours l'URL avant de cliquer
- Si le lien semble bizarre, n'y allez pas
- Utilisez l'analyseur CyberConfiance avant de scanner

### Mots de Passe

- Utilisez un mot de passe different pour chaque compte
- Minimum 12 caracteres avec majuscules, chiffres et symboles
- Utilisez un gestionnaire de mots de passe
- Ne partagez jamais vos mots de passe
- Activez l'authentification a deux facteurs

### Navigation Web

- Verifiez que le site utilise HTTPS (cadenas)
- Mefiez-vous des offres trop belles pour etre vraies
- Ne telechargez pas de fichiers de sources inconnues
- Gardez votre navigateur a jour
- Installez un bloqueur de publicites

### Emails et Phishing

- Ne cliquez pas sur les liens dans les emails suspects
- Verifiez l'adresse de l'expediteur (pas juste le nom)
- Mefiez-vous des demandes urgentes d'informations
- En cas de doute, contactez directement l'organisme concerne

### Code Source (pour developpeurs)

- N'utilisez jamais de code sans le verifier d'abord
- Analysez les depots GitHub avec notre outil
- Mefiez-vous du code genere par IA non revise
- Verifiez les dependances avant installation

---

## Questions Frequentes

### L'outil stocke-t-il mes donnees?

Vos analyses sont enregistrees temporairement pour generer les rapports et permettre un suivi dans le panneau d'administration. Aucune donnee personnelle n'est vendue ou partagee.

### Pourquoi l'analyse prend du temps?

L'outil consulte plusieurs sources de securite (VirusTotal, Google Safe Browsing, URLhaus, URLScan.io) pour vous donner un resultat fiable. Cela prend quelques secondes.

### Un QR code "sur" peut-il devenir dangereux?

Oui, le site de destination peut changer. Nous vous recommandons de re-verifier les QR codes importants regulierement.

### Puis-je utiliser l'outil sur mobile?

Oui, le site est optimise pour les smartphones et tablettes. Vous pouvez meme utiliser la camera de votre telephone pour scanner les QR codes directement.

### Que faire si une menace est detectee?

1. Ne visitez pas le lien
2. Ne partagez pas ce lien avec d'autres personnes
3. Si vous avez deja visite le site, changez vos mots de passe
4. Signalez le lien malveillant aux autorites competentes

### Comment sont calculees les menaces?

Chaque URL est analysee par 4-5 services de securite independants:
- **VirusTotal**: 70+ moteurs antivirus
- **Google Safe Browsing**: Base de phishing/malware Google
- **URLhaus**: Base de malwares abuse.ch
- **URLScan.io**: Analyse comportementale
- **Detecteur interne**: IP loggers et trackers

Le niveau de menace affiche est le plus eleve parmi toutes les sources.

### L'analyseur GitHub est-il fiable?

L'analyseur GitHub est en version BETA. Il utilise l'analyse statique (sans executer le code) et peut avoir des faux positifs. Utilisez-le comme un outil d'aide a la decision, pas comme une garantie absolue de securite.

---

## Besoin d'Aide?

Si vous avez des questions ou rencontrez un probleme:
- Consultez notre FAQ complete
- Contactez-nous via le formulaire de contact
- Signalez les bugs via notre systeme de support

---

*CyberConfiance - Votre securite numerique simplifiee*
*Version 2.1 - Decembre 2025*
