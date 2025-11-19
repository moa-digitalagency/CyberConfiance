# Mapping des Pages d'Édition Admin

Ce document explique le mapping entre les pages d'édition admin et les pages publiques du site.

## Comment ça marche?

Chaque page publique a du contenu éditable stocké dans la base de données (table `SiteSettings`) avec une `category` qui correspond à la page.

## Mapping des Pages

### 1. Page d'Accueil (`/`)
**URL d'édition**: `/my4dm1n/content/edit/home`  
**Catégorie**: `home`

**Contenu éditable**:
- `hero_title` - Titre principal ("Votre Bouclier Numérique en Afrique")
- `hero_subtitle` - Sous-titre de la page d'accueil
- `hero_description` - Description détaillée sous le hero
- `cta_text` - Texte du bouton d'appel à l'action
- `cta_secondary` - Texte du bouton secondaire
- `features_title` - Titre de la section fonctionnalités
- `features_description` - Description de la section fonctionnalités
- `why_us_title` - Titre de la section avantages
- `why_us_description` - Description de la section avantages

### 2. Page À Propos (`/about`)
**URL d'édition**: `/my4dm1n/content/edit/about`  
**Catégorie**: `about`

**Contenu éditable**:
- `about_intro` - Introduction de la page à propos
- `about_mission` - Mission de CyberConfiance
- `about_vision` - Vision de CyberConfiance
- `about_values` - Valeurs de l'entreprise
- `about_context` - Contexte et raison d'être
- `about_approach` - Notre approche méthodologique

### 3. Page Services (`/services`)
**URL d'édition**: `/my4dm1n/content/edit/services`  
**Catégorie**: `services`

**Contenu éditable**:
- `services_intro` - Introduction de la page services
- `services_commitment` - Engagement de service
- `sensibilisation_title` - Titre du service sensibilisation
- `sensibilisation_description` - Description du service
- `factchecking_title` - Titre du service fact-checking
- `factchecking_description` - Description du service
- `cyberconsultation_title` - Titre du service cyber-consultation
- `cyberconsultation_description` - Description du service

### 4. Service Sensibilisation (`/services/sensibilisation`)
**URL d'édition**: `/my4dm1n/content/edit/services_sensibilisation`  
**Catégorie**: `services_sensibilisation`

*Note: Le contenu de cette page peut être ajouté via la page d'édition si nécessaire*

### 5. Service Fact-checking (`/services/factchecking`)
**URL d'édition**: `/my4dm1n/content/edit/services_factchecking`  
**Catégorie**: `services_factchecking`

*Note: Le contenu de cette page peut être ajouté via la page d'édition si nécessaire*

### 6. Service Cyber-consultation (`/services/cyberconsultation`)
**URL d'édition**: `/my4dm1n/content/edit/services_cyberconsultation`  
**Catégorie**: `services_cyberconsultation`

*Note: Le contenu de cette page peut être ajouté via la page d'édition si nécessaire*

### 7. Page Contact (`/contact`)
**URL d'édition**: `/my4dm1n/content/edit/contact`  
**Catégorie**: `contact`

**Contenu éditable**:
- `contact_title` - Titre de la page contact
- `contact_subtitle` - Sous-titre de la page contact
- `contact_description` - Description détaillée
- `contact_hours` - Horaires d'ouverture
- `contact_response_time` - Temps de réponse
- `contact_emergency` - Message urgence

### 8. Page Actualités (`/news`)
**URL d'édition**: `/my4dm1n/content/edit/news`  
**Catégorie**: `news`

*Note: Les articles d'actualité sont gérés via `/my4dm1n/blog` (système CRUD complet)*

## Structure de la Base de Données

```sql
SiteSettings:
  - id: integer
  - key: string (ex: "hero_title")
  - value: text (le contenu éditable)
  - value_type: string ("string", "textarea", "text")
  - description: text (description du champ)
  - category: string (ex: "home", "about", "contact")
  - is_public: boolean
  - updated_at: datetime
  - updated_by: integer (user_id)
```

## Comment ajouter du contenu à une page?

1. Accédez à la page d'édition via `/my4dm1n/content/edit/<page>`
2. Si aucun contenu n'apparaît, vous pouvez ajouter des paramètres via `/my4dm1n/admin/sitesettings/new/`
3. Utilisez la catégorie correspondante (ex: "home" pour la page d'accueil)

## Exemple d'ajout manuel

Pour ajouter un nouveau champ éditable à la page d'accueil:

1. Allez sur `/my4dm1n/admin/sitesettings/new/`
2. Remplissez:
   - **Key**: `nouveau_champ`
   - **Value**: Le contenu du champ
   - **Category**: `home`
   - **Value Type**: `textarea` ou `string`
   - **Description**: Description du champ
   - **Is Public**: Cochez si le contenu doit être accessible publiquement

## Résumé du Mapping

| Page Publique | URL Admin | Catégorie |
|--------------|-----------|-----------|
| `/` | `/my4dm1n/content/edit/home` | `home` |
| `/about` | `/my4dm1n/content/edit/about` | `about` |
| `/services` (général) | `/my4dm1n/content/edit/services` | `services` |
| `/services/sensibilisation` | `/my4dm1n/content/edit/services_sensibilisation` | `services_sensibilisation` |
| `/services/factchecking` | `/my4dm1n/content/edit/services_factchecking` | `services_factchecking` |
| `/services/cyberconsultation` | `/my4dm1n/content/edit/services_cyberconsultation` | `services_cyberconsultation` |
| `/contact` | `/my4dm1n/content/edit/contact` | `contact` |
| `/news` | `/my4dm1n/blog` (CRUD) | Articles via système blog |
