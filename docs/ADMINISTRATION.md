# Guide d'Administration - CyberConfiance

Ce document decrit l'interface d'administration, les fonctionnalites de gestion et les procedures de maintenance.

**Version**: 2.1  
**Mise a jour**: Decembre 2025

---

## Acces a l'Administration

### URL d'Acces

```
https://votre-domaine.com/my4dm1n/admin/
```

L'URL est volontairement non standard pour limiter les tentatives d'acces non autorisees.

### Identifiants

| Champ | Valeur par defaut | Configuration |
|-------|-------------------|---------------|
| Utilisateur | admin | Fixe |
| Mot de passe | admin123 | Variable `ADMIN_PASSWORD` |

### Configuration du Mot de Passe

```bash
# Variable d'environnement
ADMIN_PASSWORD=VotreMotDePasseSecurise123!
```

Si la variable n'est pas definie, le mot de passe par defaut est utilise avec un avertissement dans les logs.

---

## Interface d'Administration

### Dashboard Principal

Le dashboard affiche :
- Statistiques globales (analyses, contacts, demandes)
- Activite recente
- Alertes de securite
- Graphiques d'utilisation

### Sections Disponibles

| Section | Description | Acces |
|---------|-------------|-------|
| Dashboard | Vue d'ensemble et statistiques | `/my4dm1n/` |
| Historique Analyses | Toutes les analyses effectuees | `/my4dm1n/history/` |
| Contacts | Messages du formulaire de contact | `/my4dm1n/contacts/` |
| Demandes | Demandes de service (fact-checking, consultation) | `/my4dm1n/requests/` |
| Contenu | Gestion du contenu editorial | `/my4dm1n/content/` |
| Parametres | Configuration du site | `/my4dm1n/settings/` |
| Logs | Journaux d'activite et securite | `/my4dm1n/logs/` |

---

## Gestion des Analyses

### Types d'Historiques

| Type | Route | Donnees |
|------|-------|---------|
| QR Code | `/my4dm1n/history/qrcode/` | URL extraite, niveau de menace, redirections |
| Securite | `/my4dm1n/history/security/` | Type d'analyse, resultat, sources |
| Fuite Email | `/my4dm1n/history/breach/` | Email, nombre de fuites, details |
| Prompt | `/my4dm1n/history/prompt/` | Texte analyse, menaces detectees |
| GitHub | `/my4dm1n/history/github/` | Depot, score, vulnerabilites |
| Quiz | `/my4dm1n/history/quiz/` | Email, score, recommandations |

### Detail d'une Analyse

Chaque analyse affiche :
- Code document unique
- Date et heure
- IP source et User-Agent
- Resultats complets
- Lien de telechargement PDF

### Export de Donnees

Les analyses peuvent etre exportees en :
- PDF (rapport individuel)
- Consultation directe dans l'interface

---

## Gestion des Contacts

### Liste des Messages

Affiche tous les messages du formulaire de contact avec :
- Nom et email de l'expediteur
- Sujet et date
- Statut (lu/non lu, archive)

### Actions Disponibles

| Action | Description |
|--------|-------------|
| Marquer comme lu | Change le statut du message |
| Archiver | Deplace vers les archives |
| Supprimer | Suppression definitive |
| Repondre | Ouvre le client email avec l'adresse pre-remplie |

---

## Gestion des Demandes

### Types de Demandes

| Type | Description |
|------|-------------|
| fact-checking | Verification d'information |
| cyberconsultation | Accompagnement personnalise |
| osint-investigation | Enquete sur sources ouvertes |
| cybercrime-report | Signalement de crime en ligne |

### Statuts des Demandes

| Statut | Signification |
|--------|---------------|
| pending | En attente de traitement |
| in_progress | En cours de traitement |
| completed | Traitee |
| cancelled | Annulee |

### Detail d'une Demande

Affiche :
- Informations du demandeur
- Type de demande et details
- Documents soumis
- Historique des actions
- Metadonnees (IP, navigateur, plateforme)

---

## Gestion du Contenu

### Sections Editables

| Section | Contenu |
|---------|---------|
| Regles d'Or | 20 regles de cybersecurite |
| Scenarios | Scenarios de menaces |
| Glossaire | Definitions des termes |
| Outils | Outils recommandes |
| Types d'Attaques | Catalogue des attaques |
| Actualites | Articles d'actualite |

### Edition de Contenu

Chaque element peut etre :
- Cree
- Modifie
- Active/Desactive
- Reordonne

### Actualites

Pour les actualites :
- Titre et contenu
- Categorie (Alerte, Conseil, General)
- Source et URL
- Date de publication

---

## Parametres du Site

### Apparence

| Parametre | Description |
|-----------|-------------|
| logo_light | Logo pour le theme sombre |
| logo_dark | Logo pour le theme clair et PDFs |
| favicon | Icone du site |
| default_og_image | Image par defaut pour partage social |

### SEO

Configuration par page :
- Titre
- Description
- Mots-cles
- Titre et description Open Graph
- Image Open Graph
- URL canonique
- Directives robots

### Contenu des Pages

Textes editables par section pour :
- Page d'accueil
- A propos
- Pages de services
- Footer

### Code Personnalise

Possibilite d'injecter du code dans le `<head>` :
- Scripts analytics
- Meta tags supplementaires
- CSS personnalise

---

## Logs et Securite

### Types de Logs

| Type | Contenu |
|------|---------|
| Activity Logs | Actions utilisateur (analyses, soumissions) |
| Security Logs | Evenements de securite (connexions, erreurs) |
| Threat Logs | Menaces detectees avec details complets |

### Detail des Threat Logs

Chaque menace enregistree contient :
- Incident ID unique
- Type de menace
- Details de l'analyse
- IP source
- User-Agent
- Plateforme et type d'appareil
- Detection VPN
- Timestamp

### Consultation

Les logs sont accessibles via :
- Interface admin
- Export (si configure)
- Requetes SQL directes (pour debug)

---

## Maintenance

### Sauvegarde Base de Donnees

```bash
# Export PostgreSQL
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d).sql

# Restauration
psql $DATABASE_URL < backup_20251226.sql
```

### Nettoyage des Donnees

Recommandations de retention :
- Analyses : 90 jours
- Logs d'activite : 30 jours
- Threat logs : 365 jours
- Contacts archives : 180 jours

### Migration de Base

Les migrations sont gerees via des scripts dans `/migrations/` :

```bash
python migrations/add_document_code_columns.py
```

### Mise a Jour des Donnees Seed

Les donnees initiales sont dans `/data/` :
- `rules_seed.json`
- `scenarios_seed.json`
- `glossary_seed.json`
- `tools_seed.json`
- `news_seed.json`
- `quiz_questions.json`

Pour re-seeder :

```python
from utils.seed_data import seed_all_data
seed_all_data(db)
```

---

## Securite Administrative

### Bonnes Pratiques

1. **Mot de passe fort** : Minimum 12 caracteres, mixte
2. **Acces restreint** : IP whitelisting si possible
3. **Logs reguliers** : Verifier les connexions admin
4. **Deconnexion** : Toujours se deconnecter apres usage

### Alertes a Surveiller

| Alerte | Action |
|--------|--------|
| Connexions echouees repetees | Verifier tentatives d'intrusion |
| Threat logs nombreux | Possible attaque en cours |
| Erreurs 500 frequentes | Probleme applicatif a investiguer |
| Rate limit atteint | Verifier utilisation anormale |

### Rotation des Secrets

Frequence recommandee :
- Mot de passe admin : Tous les 90 jours
- Cles API : Tous les 6 mois
- SECRET_KEY Flask : Annuellement

---

## Support et Debug

### Logs Applicatifs

Les erreurs sont loguees dans :
- Console (stdout)
- Base de donnees (SecurityLog)

### Debug Mode

Pour activer en developpement :

```bash
FLASK_DEBUG=True python main.py
```

Ne jamais activer en production.

### Problemes Courants

| Probleme | Solution |
|----------|----------|
| Page 500 | Verifier les logs console |
| CSRF Error | Session expiree, reconnecter |
| PDF non genere | Verifier les donnees de l'analyse |
| API timeout | Verifier connectivite externe |

---

## Contact Support

En cas de probleme technique :
1. Consulter les logs applicatifs
2. Verifier les variables d'environnement
3. Contacter l'equipe technique avec les logs

---

*Administration CyberConfiance v2.1 - Decembre 2025*
