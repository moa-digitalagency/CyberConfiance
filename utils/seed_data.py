import json
import os
from pathlib import Path
from datetime import datetime

def load_json_seed(filename):
    """Load seed data from JSON file"""
    data_dir = Path(__file__).parent.parent / 'data'
    file_path = data_dir / filename
    
    if not file_path.exists():
        print(f"Warning: Seed file {filename} not found at {file_path}")
        return []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def seed_rules(db):
    """Seed or update rules from JSON data (idempotent)"""
    from models import Rule
    
    rules_data = load_json_seed('rules_seed.json')
    if not rules_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for rule_data in rules_data:
        # Check if rule exists by title
        existing_rule = Rule.query.filter_by(title=rule_data['title']).first()
        
        if existing_rule:
            # Update existing rule
            existing_rule.description = rule_data['description']
            existing_rule.order = rule_data['order']
            updated_count += 1
        else:
            # Create new rule
            new_rule = Rule(
                title=rule_data['title'],
                description=rule_data['description'],
                order=rule_data['order']
            )
            db.session.add(new_rule)
            seeded_count += 1
    
    db.session.commit()
    print(f"[OK] Rules: {seeded_count} created, {updated_count} updated")

def seed_scenarios(db):
    """Seed or update scenarios from JSON data (idempotent)"""
    from models import Scenario
    
    scenarios_data = load_json_seed('scenarios_seed.json')
    if not scenarios_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for scenario_data in scenarios_data:
        # Check if scenario exists by title
        existing_scenario = Scenario.query.filter_by(title=scenario_data['title']).first()
        
        if existing_scenario:
            # Update existing scenario (only update provided fields)
            existing_scenario.description = scenario_data['description']
            if 'severity' in scenario_data:
                existing_scenario.severity = scenario_data['severity']
            if 'threat_type' in scenario_data:
                existing_scenario.threat_type = scenario_data['threat_type']
            if 'solution' in scenario_data:
                existing_scenario.solution = scenario_data['solution']
            updated_count += 1
        else:
            # Create new scenario
            new_scenario = Scenario(
                title=scenario_data['title'],
                description=scenario_data['description'],
                severity=scenario_data.get('severity', 'Moyen'),
                threat_type=scenario_data.get('threat_type', ''),
                solution=scenario_data.get('solution', '')
            )
            db.session.add(new_scenario)
            seeded_count += 1
    
    db.session.commit()
    print(f"[OK] Scenarios: {seeded_count} created, {updated_count} updated")

def seed_glossary(db):
    """Seed or update glossary terms from JSON data (idempotent)"""
    from models import GlossaryTerm
    
    glossary_data = load_json_seed('glossary_seed.json')
    if not glossary_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for term_data in glossary_data:
        # Check if term exists by term name
        existing_term = GlossaryTerm.query.filter_by(term=term_data['term']).first()
        
        if existing_term:
            # Update existing term
            existing_term.definition = term_data['definition']
            updated_count += 1
        else:
            # Create new term
            new_term = GlossaryTerm(
                term=term_data['term'],
                definition=term_data['definition']
            )
            db.session.add(new_term)
            seeded_count += 1
    
    db.session.commit()
    print(f"[OK] Glossary: {seeded_count} created, {updated_count} updated")

def seed_tools(db):
    """Seed or update tools from JSON data (idempotent)"""
    from models import Tool
    
    tools_data = load_json_seed('tools_seed.json')
    if not tools_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for tool_data in tools_data:
        # Check if tool exists by name
        existing_tool = Tool.query.filter_by(name=tool_data['name']).first()
        
        if existing_tool:
            # Update existing tool
            existing_tool.description = tool_data['description']
            existing_tool.category = tool_data.get('category', '')
            existing_tool.type = tool_data.get('type', '')
            existing_tool.url = tool_data.get('url', '')
            existing_tool.use_case = tool_data.get('use_case', '')
            existing_tool.dangers = tool_data.get('dangers', '')
            existing_tool.related_rules = tool_data.get('related_rules', '')
            existing_tool.related_scenarios = tool_data.get('related_scenarios', '')
            updated_count += 1
        else:
            # Create new tool
            new_tool = Tool(
                name=tool_data['name'],
                description=tool_data['description'],
                category=tool_data.get('category', ''),
                type=tool_data.get('type', ''),
                url=tool_data.get('url', ''),
                use_case=tool_data.get('use_case', ''),
                dangers=tool_data.get('dangers', ''),
                related_rules=tool_data.get('related_rules', ''),
                related_scenarios=tool_data.get('related_scenarios', '')
            )
            db.session.add(new_tool)
            seeded_count += 1
    
    db.session.commit()
    print(f"[OK] Tools: {seeded_count} created, {updated_count} updated")

def seed_attack_types(db):
    """Seed or update attack types (idempotent)"""
    from models import AttackType
    
    attacks_data = [
        {'name_en': 'SQL Injection', 'name_fr': 'Injection SQL', 'description_fr': 'Une vulnérabilité permettant aux attaquants d\'exécuter des commandes SQL arbitraires contre votre base de données, pouvant exposer ou détruire des données sensibles.', 'category': 'Web', 'severity': 'Critique', 'prevention': 'Utilisez des requêtes paramétrées, validez toutes les entrées utilisateur et implémentez le principe du moindre privilège pour les comptes de base de données.', 'order': 1},
        {'name_en': 'Cross-Site Scripting (XSS)', 'name_fr': 'Cross-Site Scripting (XSS)', 'description_fr': 'Permet aux attaquants d\'injecter du JavaScript malveillant dans votre site, volant ainsi les données des utilisateurs ou détournant leurs sessions.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Échappez tout contenu utilisateur, utilisez Content Security Policy (CSP) et validez les entrées côté serveur.', 'order': 2},
        {'name_en': 'Command Execution', 'name_fr': 'Exécution de Commandes', 'description_fr': 'Si votre application appelle le système d\'exploitation, vous devez vous assurer que les chaînes de commandes sont construites de manière sécurisée pour éviter l\'exécution de code arbitraire.', 'category': 'Web', 'severity': 'Critique', 'prevention': 'Évitez d\'exécuter des commandes système avec des entrées utilisateur. Si nécessaire, utilisez des listes blanches et validez strictement les paramètres.', 'order': 3},
        {'name_en': 'Clickjacking', 'name_fr': 'Détournement de Clic', 'description_fr': 'Les attaquants superposent des éléments invisibles sur votre site pour détourner les clics des utilisateurs vers des actions non souhaitées.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Utilisez les en-têtes X-Frame-Options ou Content-Security-Policy avec frame-ancestors pour empêcher l\'intégration de votre site dans des iframes malveillantes.', 'order': 4},
        {'name_en': 'Cross-Site Request Forgery (CSRF)', 'name_fr': 'Falsification de Requête Inter-Sites (CSRF)', 'description_fr': 'Les attaquants peuvent forger des requêtes HTTP vers votre site pour tromper vos utilisateurs et déclencher des actions non désirées.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Implémentez des jetons CSRF, vérifiez l\'en-tête Referer et utilisez SameSite cookies.', 'order': 5},
        {'name_en': 'Directory Traversal', 'name_fr': 'Traversée de Répertoires', 'description_fr': 'Permet aux attaquants d\'accéder à des fichiers sensibles sur votre serveur en manipulant les chemins de fichiers.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Validez et normalisez tous les chemins de fichiers, utilisez des listes blanches de fichiers autorisés et ne faites jamais confiance aux entrées utilisateur.', 'order': 6},
        {'name_en': 'Reflected XSS', 'name_fr': 'XSS Réfléchi', 'description_fr': 'Du JavaScript malveillant est renvoyé depuis votre serveur dans la réponse, permettant aux attaquants d\'exploiter vos utilisateurs.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Échappez toutes les données reflétées dans les réponses, validez les entrées et utilisez CSP.', 'order': 7},
        {'name_en': 'DOM-based XSS', 'name_fr': 'XSS Basé sur le DOM', 'description_fr': 'Vulnérabilité XSS qui se produit entièrement côté client, souvent via la manipulation des fragments d\'URI.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Évitez d\'utiliser des fonctions JavaScript dangereuses avec des données non fiables, validez les fragments d\'URI et utilisez des bibliothèques de sécurité.', 'order': 8},
        {'name_en': 'File Upload Vulnerabilities', 'name_fr': 'Vulnérabilités de Téléversement de Fichiers', 'description_fr': 'Les uploads de fichiers sont un moyen facile pour un attaquant d\'injecter du code malveillant dans votre application.', 'category': 'Web', 'severity': 'Critique', 'prevention': 'Validez le type et la taille des fichiers, stockez-les en dehors de la racine web, scannez-les avec un antivirus et renommez-les.', 'order': 9},
        {'name_en': 'Broken Access Control', 'name_fr': 'Contrôle d\'Accès Défaillant', 'description_fr': 'Toutes les ressources de votre site doivent avoir un contrôle d\'accès, même si elles ne sont pas destinées à être découvertes.', 'category': 'Web', 'severity': 'Critique', 'prevention': 'Implémentez une autorisation stricte sur toutes les ressources, utilisez le principe du moindre privilège et testez régulièrement les contrôles d\'accès.', 'order': 10},
        {'name_en': 'Open Redirects', 'name_fr': 'Redirections Ouvertes', 'description_fr': 'Si votre site redirige vers des URLs fournies dans les paramètres, vous pourriez faciliter des attaques de phishing.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Utilisez des listes blanches de destinations de redirection valides ou évitez complètement les redirections basées sur des paramètres.', 'order': 11},
        {'name_en': 'Unencrypted Communication', 'name_fr': 'Communication Non Chiffrée', 'description_fr': 'Un chiffrement insuffisant vous rend vulnérable aux attaques de type homme du milieu.', 'category': 'Network', 'severity': 'Critique', 'prevention': 'Utilisez HTTPS avec TLS 1.2 ou supérieur, implémentez HSTS et utilisez des certificats valides.', 'order': 12},
        {'name_en': 'User Enumeration', 'name_fr': 'Énumération d\'Utilisateurs', 'description_fr': 'Divulguer des informations sur les noms d\'utilisateur facilite grandement le travail des hackers.', 'category': 'Web', 'severity': 'Faible', 'prevention': 'Utilisez des messages d\'erreur génériques pour l\'authentification et le reset de mot de passe.', 'order': 13},
        {'name_en': 'Information Leakage', 'name_fr': 'Fuite d\'Informations', 'description_fr': 'Révéler des informations système aide un attaquant à en apprendre davantage sur votre stack technique.', 'category': 'Web', 'severity': 'Faible', 'prevention': 'Désactivez les messages d\'erreur détaillés en production, supprimez les en-têtes révélateurs et masquez les versions.', 'order': 14},
        {'name_en': 'Password Mismanagement', 'name_fr': 'Mauvaise Gestion des Mots de Passe', 'description_fr': 'Le traitement sécurisé des mots de passe est essentiel, pourtant de nombreux sites le font mal.', 'category': 'Web', 'severity': 'Critique', 'prevention': 'Utilisez des algorithmes de hachage modernes (bcrypt, Argon2), n\'envoyez jamais de mots de passe en clair et implémentez une politique de mots de passe forts.', 'order': 15},
        {'name_en': 'Privilege Escalation', 'name_fr': 'Élévation de Privilèges', 'description_fr': 'Se produit quand un attaquant exploite une vulnérabilité pour usurper l\'identité d\'un autre utilisateur ou obtenir des permissions supplémentaires.', 'category': 'Web', 'severity': 'Critique', 'prevention': 'Vérifiez les autorisations à chaque requête, séparez les rôles clairement et auditez les actions privilégiées.', 'order': 16},
        {'name_en': 'Session Fixation', 'name_fr': 'Fixation de Session', 'description_fr': 'Un traitement non sécurisé des IDs de session peut permettre le détournement de session utilisateur.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Régénérez les IDs de session après l\'authentification, utilisez des cookies sécurisés et implémentez des timeouts de session.', 'order': 17},
        {'name_en': 'Weak Session IDs', 'name_fr': 'IDs de Session Faibles', 'description_fr': 'Des IDs de session prévisibles rendent votre site vulnérable au détournement de session.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Utilisez des générateurs cryptographiquement sécurisés pour les IDs de session et assurez une entropie suffisante.', 'order': 18},
        {'name_en': 'XML Bombs', 'name_fr': 'Bombes XML', 'description_fr': 'Un traitement non sécurisé des macros XML peut rendre votre serveur vulnérable à des fichiers XML spécialement conçus.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Désactivez les entités externes XML, limitez la profondeur et la taille des documents XML, et utilisez des parseurs sécurisés.', 'order': 19},
        {'name_en': 'XML External Entities (XXE)', 'name_fr': 'Entités Externes XML (XXE)', 'description_fr': 'Un traitement non sécurisé des références externes dans XML permet à un attaquant de sonder votre système de fichiers.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Désactivez les entités externes XML, utilisez des formats de données moins complexes comme JSON quand possible.', 'order': 20},
        {'name_en': 'Denial of Service Attacks', 'name_fr': 'Attaques par Déni de Service (DoS)', 'description_fr': 'Parfois les attaquants veulent simplement rendre votre site indisponible aux autres utilisateurs.', 'category': 'Network', 'severity': 'Élevé', 'prevention': 'Implémentez la limitation de débit, utilisez des CDN et services anti-DDoS, et configurez des timeouts appropriés.', 'order': 21},
        {'name_en': 'Email Spoofing', 'name_fr': 'Usurpation d\'Email', 'description_fr': 'L\'envoi de messages email avec une adresse d\'expéditeur falsifiée pour tromper les destinataires.', 'category': 'Social', 'severity': 'Moyen', 'prevention': 'Configurez SPF, DKIM et DMARC pour votre domaine, et éduquez les utilisateurs sur la vérification des expéditeurs.', 'order': 22},
        {'name_en': 'Malvertising', 'name_fr': 'Publicité Malveillante', 'description_fr': 'Les publicités intégrées sont une cible commune pour les hackers qui y injectent du code malveillant.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Utilisez des réseaux publicitaires de confiance, implémentez CSP et scannez régulièrement votre site.', 'order': 23},
        {'name_en': 'Lax Security Settings', 'name_fr': 'Paramètres de Sécurité Laxistes', 'description_fr': 'Des paramètres de sécurité inappropriés sont une cause commune de vulnérabilités.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Suivez les guides de durcissement sécuritaire, désactivez les fonctionnalités inutilisées et maintenez les systèmes à jour.', 'order': 24},
        {'name_en': 'Toxic Dependencies', 'name_fr': 'Dépendances Toxiques', 'description_fr': 'Les bibliothèques tierces peuvent introduire des vulnérabilités ou du code malveillant dans votre système.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Auditez vos dépendances régulièrement, utilisez des outils de scan de vulnérabilités et maintenez-les à jour.', 'order': 25},
        {'name_en': 'Logging and Monitoring', 'name_fr': 'Journalisation et Surveillance', 'description_fr': 'Une journalisation et surveillance complètes sont essentielles pour détecter les événements de sécurité.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Implémentez une journalisation centralisée, surveillez les événements de sécurité et configurez des alertes.', 'order': 26},
        {'name_en': 'Buffer Overflows', 'name_fr': 'Dépassements de Tampon', 'description_fr': 'Les dépassements de tampon peuvent permettre aux attaquants de prendre le contrôle de votre serveur ou d\'injecter du code malveillant.', 'category': 'Web', 'severity': 'Critique', 'prevention': 'Utilisez des langages avec gestion automatique de la mémoire, validez les tailles d\'entrée et utilisez des protections au niveau système.', 'order': 27},
        {'name_en': 'Server-Side Request Forgery (SSRF)', 'name_fr': 'Falsification de Requête Côté Serveur (SSRF)', 'description_fr': 'Permet aux attaquants d\'utiliser votre serveur pour sonder votre réseau interne.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Validez et filtrez toutes les URLs fournies par l\'utilisateur, utilisez des listes blanches et segmentez votre réseau.', 'order': 28},
        {'name_en': 'Host Header Poisoning', 'name_fr': 'Empoisonnement de l\'En-tête Host', 'description_fr': 'Il est dangereux de se fier à la valeur fournie dans l\'en-tête Host d\'une requête HTTP.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Validez l\'en-tête Host, utilisez des listes blanches de domaines et configurez correctement votre serveur web.', 'order': 29},
        {'name_en': 'Insecure Design', 'name_fr': 'Conception Non Sécurisée', 'description_fr': 'La sécurité commence avant même d\'écrire du code - une mauvaise conception architecturale crée des vulnérabilités.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Intégrez la sécurité dès la conception, effectuez des modélisations de menaces et suivez les principes de sécurité by design.', 'order': 30},
        {'name_en': 'Mass Assignment', 'name_fr': 'Affectation en Masse', 'description_fr': 'Déballer automatiquement les données de requête HTTP peut parfois être trop facile et permettre la modification de champs non autorisés.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Utilisez des listes blanches explicites pour les champs autorisés et ne faites pas confiance aux entrées utilisateur.', 'order': 31},
        {'name_en': 'Prototype Pollution', 'name_fr': 'Pollution de Prototype', 'description_fr': 'Si un attaquant peut accéder et modifier les objets prototype en JavaScript, votre application est en danger.', 'category': 'Web', 'severity': 'Élevé', 'prevention': 'Validez les clés d\'objets, utilisez Object.create(null) pour créer des objets sans prototype et gelés les prototypes critiques.', 'order': 32},
        {'name_en': 'Regex Injection', 'name_fr': 'Injection d\'Expressions Régulières', 'description_fr': 'Les expressions régulières sont fréquemment utilisées en développement web, mais peuvent être abusées par les attaquants.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Évitez d\'utiliser des regex avec des entrées utilisateur, limitez la complexité et le temps d\'exécution des regex.', 'order': 33},
        {'name_en': 'Remote Code Execution', 'name_fr': 'Exécution de Code à Distance', 'description_fr': 'Si un attaquant peut injecter du code dans votre processus serveur, vous avez un problème grave.', 'category': 'Web', 'severity': 'Critique', 'prevention': 'Évitez d\'exécuter du code non fiable, désactivez les fonctions dangereuses et appliquez le principe du moindre privilège.', 'order': 34},
        {'name_en': 'Cross-Site Script Inclusion (XSSI)', 'name_fr': 'Inclusion de Script Inter-Sites (XSSI)', 'description_fr': 'Si vous placez des données sensibles dans vos fichiers JavaScript, un attaquant les vole probablement.', 'category': 'Web', 'severity': 'Moyen', 'prevention': 'Ne stockez jamais de données sensibles dans des fichiers JavaScript, utilisez des endpoints JSON protégés par CSRF.', 'order': 35},
        {'name_en': 'Downgrade Attacks', 'name_fr': 'Attaques par Rétrogradation', 'description_fr': 'Les attaquants peuvent intercepter et manipuler le trafic HTTPS si vous ne spécifiez pas une version moderne de TLS.', 'category': 'Network', 'severity': 'Élevé', 'prevention': 'Désactivez les versions anciennes de SSL/TLS, utilisez TLS 1.2+ uniquement et configurez HSTS.', 'order': 36},
        {'name_en': 'DNS Poisoning', 'name_fr': 'Empoisonnement DNS', 'description_fr': 'Si les caches DNS en amont ont été empoisonnés, les attaquants peuvent intercepter le trafic avant qu\'il n\'arrive chez vous.', 'category': 'Network', 'severity': 'Élevé', 'prevention': 'Utilisez DNSSEC, surveillez les résolutions DNS et utilisez des serveurs DNS de confiance.', 'order': 37},
        {'name_en': 'SSL Stripping', 'name_fr': 'Suppression SSL', 'description_fr': 'Si seules certaines actions nécessitent HTTPS, un attaquant peut voler les identifiants de vos utilisateurs.', 'category': 'Network', 'severity': 'Élevé', 'prevention': 'Utilisez HTTPS partout, implémentez HSTS et ne mélangez jamais contenu HTTP et HTTPS.', 'order': 38},
        {'name_en': 'Subdomain Squatting', 'name_fr': 'Détournement de Sous-domaines', 'description_fr': 'Les attaquants voleront des sous-domaines non utilisés pour distribuer des malwares et effectuer des attaques de phishing.', 'category': 'Network', 'severity': 'Moyen', 'prevention': 'Supprimez les enregistrements DNS inutilisés, surveillez vos sous-domaines et utilisez des certificats wildcard avec précaution.', 'order': 39},
        {'name_en': 'AI: Bias and Unreliability', 'name_fr': 'IA: Biais et Fiabilité', 'description_fr': 'L\'apprentissage automatique est sujet aux biais et à l\'instabilité - il faut des garde-fous pour s\'en protéger.', 'category': 'AI', 'severity': 'Moyen', 'prevention': 'Testez les modèles sur des datasets diversifiés, surveillez les prédictions et implémentez des contrôles humains.', 'order': 40},
        {'name_en': 'AI: Prompt Injection', 'name_fr': 'IA: Injection de Prompt', 'description_fr': 'L\'injection de prompt permet aux attaquants d\'introduire facilement des comportements inattendus dans un modèle d\'apprentissage.', 'category': 'AI', 'severity': 'Élevé', 'prevention': 'Validez et filtrez les prompts utilisateur, limitez les actions du modèle et surveillez les sorties anormales.', 'order': 41},
        {'name_en': 'AI: Data Extraction Attacks', 'name_fr': 'IA: Attaques d\'Extraction de Données', 'description_fr': 'Votre modèle d\'apprentissage peut divulguer des données sensibles sans que vous le sachiez.', 'category': 'AI', 'severity': 'Critique', 'prevention': 'N\'entraînez pas les modèles sur des données sensibles, utilisez la confidentialité différentielle et auditez les sorties du modèle.', 'order': 42}
    ]
    
    created_count = 0
    updated_count = 0
    
    for attack_data in attacks_data:
        existing = AttackType.query.filter_by(name_en=attack_data['name_en']).first()
        
        if existing:
            existing.name_fr = attack_data['name_fr']
            existing.description_fr = attack_data['description_fr']
            existing.category = attack_data['category']
            existing.severity = attack_data['severity']
            existing.prevention = attack_data['prevention']
            existing.order = attack_data['order']
            updated_count += 1
        else:
            attack = AttackType(**attack_data)
            db.session.add(attack)
            created_count += 1
    
    db.session.commit()
    print(f"[OK] Attack Types: {created_count} created, {updated_count} updated")

def seed_site_settings(db):
    """Seed default site settings"""
    from models import SiteSettings
    
    default_settings = [
        {'key': 'site_name', 'value': 'CyberConfiance', 'description': 'Nom du site', 'category': 'general', 'is_public': True},
        {'key': 'contact_email', 'value': 'contact@cyberconfiance.fr', 'description': 'Email de contact principal', 'category': 'general', 'is_public': True},
        {'key': 'logo_light', 'value': '/static/img/logo.png', 'description': 'Logo for light theme', 'category': 'appearance', 'is_public': True},
        {'key': 'logo_dark', 'value': '/static/img/logo.png', 'description': 'Logo for dark theme', 'category': 'appearance', 'is_public': True},
        {'key': 'maintenance_mode', 'value': 'false', 'value_type': 'boolean', 'description': 'Mode maintenance activé', 'category': 'system', 'is_public': False},
        {'key': 'analytics_enabled', 'value': 'true', 'value_type': 'boolean', 'description': 'Activer les statistiques', 'category': 'system', 'is_public': False},
    ]
    
    created_count = 0
    
    for setting_data in default_settings:
        existing = SiteSettings.query.filter_by(key=setting_data['key']).first()
        if not existing:
            setting = SiteSettings(**setting_data)
            db.session.add(setting)
            created_count += 1
    
    db.session.commit()
    print(f"[OK] Site Settings: {created_count} created")

def seed_seo_metadata(db):
    """Seed default SEO metadata for main pages"""
    from models import SEOMetadata
    
    default_seo = [
        {
            'page_path': '/',
            'title': 'CyberConfiance - Votre bouclier numérique en RDC',
            'description': 'Plateforme de sensibilisation à la cybersécurité pour les entreprises et particuliers en République Démocratique du Congo. Apprenez à vous protéger des menaces numériques.',
            'keywords': 'cybersécurité, RDC, Congo, sécurité numérique, protection données, formation cybersécurité',
            'og_title': 'CyberConfiance - Sécurité Numérique pour Tous',
            'og_description': 'Protégez votre entreprise et vos données avec CyberConfiance. Formation, outils et conseils en cybersécurité.',
            'robots': 'index, follow',
            'is_active': True
        },
        {
            'page_path': '/rules',
            'title': '20 Règles d\'Or - CyberConfiance',
            'description': 'Découvrez les 20 règles essentielles pour renforcer votre sécurité numérique au quotidien. Conseils pratiques et applicables immédiatement.',
            'keywords': 'règles cybersécurité, bonnes pratiques sécurité, conseils protection',
            'robots': 'index, follow',
            'is_active': True
        },
        {
            'page_path': '/scenarios',
            'title': 'Scénarios d\'Attaque - CyberConfiance',
            'description': 'Apprenez à reconnaître et à vous protéger contre les cybermenaces actuelles avec nos scénarios d\'attaque détaillés.',
            'keywords': 'scénarios attaque, cybermenaces, phishing, ransomware',
            'robots': 'index, follow',
            'is_active': True
        },
        {
            'page_path': '/tools',
            'title': 'Outils de Cybersécurité - CyberConfiance',
            'description': 'Découvrez notre collection d\'outils pour tester et améliorer votre sécurité numérique.',
            'keywords': 'outils cybersécurité, test sécurité, analyse vulnérabilités',
            'robots': 'index, follow',
            'is_active': True
        },
        {
            'page_path': '/glossary',
            'title': 'Glossaire Cybersécurité - CyberConfiance',
            'description': 'Comprenez les termes techniques de la cybersécurité avec notre glossaire complet et accessible.',
            'keywords': 'glossaire cybersécurité, termes techniques, définitions sécurité',
            'robots': 'index, follow',
            'is_active': True
        },
        {
            'page_path': '/contact',
            'title': 'Contact - CyberConfiance',
            'description': 'Contactez-nous pour toute question sur la cybersécurité ou nos services.',
            'keywords': 'contact, support, cybersécurité RDC',
            'robots': 'index, follow',
            'is_active': True
        }
    ]
    
    created_count = 0
    
    for seo_data in default_seo:
        existing = SEOMetadata.query.filter_by(page_path=seo_data['page_path']).first()
        if not existing:
            seo = SEOMetadata(**seo_data)
            db.session.add(seo)
            created_count += 1
    
    db.session.commit()
    print(f"[OK] SEO Metadata: {created_count} created")

def seed_news(db):
    """Seed or update news articles from JSON data (idempotent)"""
    from models import News
    
    news_data = load_json_seed('news_seed.json')
    if not news_data:
        return
    
    seeded_count = 0
    updated_count = 0
    
    for article_data in news_data:
        existing_article = News.query.filter_by(title=article_data['title']).first()
        
        if existing_article:
            existing_article.content = article_data['content']
            if 'source' in article_data:
                existing_article.source = article_data['source']
            if 'url' in article_data:
                existing_article.url = article_data.get('url')
            if 'published_date' in article_data:
                existing_article.published_date = datetime.strptime(article_data['published_date'], '%Y-%m-%d')
            updated_count += 1
        else:
            new_article = News(
                title=article_data['title'],
                content=article_data['content'],
                source=article_data.get('source', ''),
                url=article_data.get('url'),
                published_date=datetime.strptime(article_data['published_date'], '%Y-%m-%d') if 'published_date' in article_data else datetime.utcnow()
            )
            db.session.add(new_article)
            seeded_count += 1
    
    db.session.commit()
    print(f"[OK] News: {seeded_count} created, {updated_count} updated")

def seed_page_content_settings(db):
    """Seed default content settings for page editing"""
    from models import SiteSettings
    
    default_content_settings = [
        # Page d'accueil - Section Hero
        {'key': 'hero_title', 'value': 'Votre Bouclier Numérique en Afrique', 'description': 'Titre principal de la page d\'accueil', 'category': 'home', 'value_type': 'string', 'is_public': True},
        {'key': 'hero_subtitle', 'value': 'Plateforme de sensibilisation, fact-checking et accompagnement en cybersécurité pour l\'Afrique francophone', 'description': 'Sous-titre de la page d\'accueil', 'category': 'home', 'value_type': 'textarea', 'is_public': True},
        {'key': 'hero_description', 'value': 'Dans un monde numérique en constante évolution, la cybersécurité n\'est plus une option mais une nécessité. CyberConfiance vous accompagne dans la protection de vos données, la sensibilisation de vos équipes et la lutte contre la désinformation en ligne.', 'description': 'Description détaillée sous le hero', 'category': 'home', 'value_type': 'textarea', 'is_public': True},
        {'key': 'cta_text', 'value': 'Découvrir nos services', 'description': 'Texte du bouton d\'appel à l\'action', 'category': 'home', 'value_type': 'string', 'is_public': True},
        {'key': 'cta_secondary', 'value': 'Évaluer ma sécurité', 'description': 'Texte du bouton secondaire', 'category': 'home', 'value_type': 'string', 'is_public': True},
        
        # Page d'accueil - Sections
        {'key': 'features_title', 'value': 'Nos Solutions de Protection', 'description': 'Titre de la section fonctionnalités', 'category': 'home', 'value_type': 'string', 'is_public': True},
        {'key': 'features_description', 'value': 'Des services adaptés à tous les besoins, des particuliers aux grandes organisations, pour une protection numérique optimale.', 'description': 'Description de la section fonctionnalités', 'category': 'home', 'value_type': 'textarea', 'is_public': True},
        {'key': 'why_us_title', 'value': 'Pourquoi Choisir CyberConfiance?', 'description': 'Titre de la section avantages', 'category': 'home', 'value_type': 'string', 'is_public': True},
        {'key': 'why_us_description', 'value': 'Une expertise locale combinée à des standards internationaux pour protéger l\'Afrique francophone contre les cybermenaces.', 'description': 'Description de la section avantages', 'category': 'home', 'value_type': 'textarea', 'is_public': True},
        
        # Page À propos - Mission & Vision
        {'key': 'about_intro', 'value': 'CyberConfiance est née d\'une conviction : la cybersécurité doit être accessible à tous. Fondée en 2024, notre mission est de protéger l\'Afrique francophone contre les menaces numériques croissantes.', 'description': 'Introduction de la page à propos', 'category': 'about', 'value_type': 'textarea', 'is_public': True},
        {'key': 'about_mission', 'value': 'Démocratiser la cybersécurité et lutter contre la désinformation en Afrique francophone grâce à l\'éducation, la vérification d\'informations et l\'accompagnement professionnel. Nous croyons que chaque citoyen, entreprise et institution mérite d\'évoluer dans un espace numérique sûr et fiable.', 'description': 'Mission de CyberConfiance', 'category': 'about', 'value_type': 'textarea', 'is_public': True},
        {'key': 'about_vision', 'value': 'Faire de l\'Afrique francophone un espace numérique sûr et informé, où chaque citoyen dispose des outils et connaissances pour se protéger contre les cybermenaces et la désinformation. Nous aspirons à devenir le partenaire de référence en cybersécurité pour toute l\'Afrique francophone d\'ici 2030.', 'description': 'Vision de CyberConfiance', 'category': 'about', 'value_type': 'textarea', 'is_public': True},
        {'key': 'about_values', 'value': 'Excellence • Intégrité • Innovation • Accessibilité • Impact Social', 'description': 'Valeurs de l\'entreprise', 'category': 'about', 'value_type': 'textarea', 'is_public': True},
        {'key': 'about_context', 'value': 'Face à l\'explosion des cyberattaques en Afrique (+38% en 2023) et la prolifération de la désinformation en ligne, nous avons créé une plateforme complète qui combine sensibilisation, vérification de faits et conseil expert. Notre approche est unique : nous adaptons les meilleures pratiques internationales au contexte africain.', 'description': 'Contexte et raison d\'être', 'category': 'about', 'value_type': 'textarea', 'is_public': True},
        {'key': 'about_approach', 'value': 'Notre approche repose sur trois piliers : l\'éducation accessible (formations, webinaires, contenus pédagogiques), le fact-checking rigoureux (vérification d\'informations en temps réel), et l\'accompagnement personnalisé (audits, conseils, mise en conformité). Nous utilisons des méthodologies éprouvées adaptées aux réalités locales.', 'description': 'Notre approche méthodologique', 'category': 'about', 'value_type': 'textarea', 'is_public': True},
        
        # Page Services - Introduction et détails
        {'key': 'services_intro', 'value': 'CyberConfiance propose une gamme complète de services pour protéger votre organisation contre les menaces numériques. De la sensibilisation à l\'audit technique, nous couvrons tous vos besoins en cybersécurité.', 'description': 'Introduction de la page services', 'category': 'services', 'value_type': 'textarea', 'is_public': True},
        {'key': 'services_commitment', 'value': 'Notre engagement : des solutions pragmatiques, accessibles et adaptées au contexte africain. Nous ne vendons pas de la technologie, nous construisons votre sécurité numérique.', 'description': 'Engagement de service', 'category': 'services', 'value_type': 'textarea', 'is_public': True},
        
        # Services détaillés
        {'key': 'sensibilisation_title', 'value': 'Sensibilisation & Formation', 'description': 'Titre du service sensibilisation', 'category': 'services', 'value_type': 'string', 'is_public': True},
        {'key': 'sensibilisation_description', 'value': 'Formations sur mesure pour tous les niveaux : dirigeants, employés, citoyens. Ateliers interactifs, webinaires, contenus e-learning. Certification de vos équipes aux bonnes pratiques de cybersécurité. Simulations d\'attaques (phishing, ransomware) pour tester et améliorer la résilience.', 'description': 'Description du service de sensibilisation', 'category': 'services', 'value_type': 'textarea', 'is_public': True},
        
        {'key': 'factchecking_title', 'value': 'Fact-Checking & Vérification', 'description': 'Titre du service fact-checking', 'category': 'services', 'value_type': 'string', 'is_public': True},
        {'key': 'factchecking_description', 'value': 'Vérification rigoureuse des informations circulant en ligne. Analyse des deepfakes et contenus manipulés. Surveillance des campagnes de désinformation. Rapports détaillés et recommandations. Service disponible 24/7 pour les organisations et médias.', 'description': 'Description du service fact-checking', 'category': 'services', 'value_type': 'textarea', 'is_public': True},
        
        {'key': 'cyberconsultation_title', 'value': 'Cyber-Consultation & Audit', 'description': 'Titre du service cyber-consultation', 'category': 'services', 'value_type': 'string', 'is_public': True},
        {'key': 'cyberconsultation_description', 'value': 'Audits de sécurité complets (infrastructure, applications, processus). Tests d\'intrusion et évaluation des vulnérabilités. Mise en conformité (RGPD, ISO 27001, directives locales). Plans de reprise après incident. Accompagnement stratégique de votre DSI/RSSI.', 'description': 'Description du service cyber-consultation', 'category': 'services', 'value_type': 'textarea', 'is_public': True},
        
        # Page Contact - Informations détaillées
        {'key': 'contact_title', 'value': 'Contactez-Nous', 'description': 'Titre de la page contact', 'category': 'contact', 'value_type': 'string', 'is_public': True},
        {'key': 'contact_subtitle', 'value': 'Notre équipe est à votre disposition pour répondre à toutes vos questions sur la cybersécurité. Que vous soyez un particulier, une PME ou une grande organisation, nous avons les solutions adaptées à vos besoins.', 'description': 'Sous-titre de la page contact', 'category': 'contact', 'value_type': 'textarea', 'is_public': True},
        {'key': 'contact_description', 'value': 'Besoin d\'une consultation urgente ? D\'un audit de sécurité ? D\'une formation pour vos équipes ? Ou simplement d\'un conseil expert ? N\'hésitez pas à nous contacter. Nous nous engageons à répondre sous 24h ouvrées.', 'description': 'Description détaillée page contact', 'category': 'contact', 'value_type': 'textarea', 'is_public': True},
        {'key': 'contact_hours', 'value': 'Lundi - Vendredi: 8h00 - 18h00\nSamedi: 9h00 - 13h00\nDimanche: Fermé (support urgence uniquement)', 'description': 'Horaires d\'ouverture', 'category': 'contact', 'value_type': 'textarea', 'is_public': True},
        {'key': 'contact_response_time', 'value': 'Temps de réponse moyen : 4 heures (durant les heures ouvrables)', 'description': 'Temps de réponse', 'category': 'contact', 'value_type': 'string', 'is_public': True},
        {'key': 'contact_emergency', 'value': 'Pour les urgences de sécurité (incident en cours, violation de données), contactez notre ligne d\'urgence 24/7.', 'description': 'Message urgence', 'category': 'contact', 'value_type': 'textarea', 'is_public': True},
    ]
    
    created_count = 0
    updated_count = 0
    
    for setting_data in default_content_settings:
        existing = SiteSettings.query.filter_by(key=setting_data['key'], category=setting_data['category']).first()
        if not existing:
            setting = SiteSettings(**setting_data)
            db.session.add(setting)
            created_count += 1
        else:
            # Update existing settings
            existing.value = setting_data['value']
            existing.description = setting_data['description']
            existing.value_type = setting_data.get('value_type', 'string')
            updated_count += 1
    
    db.session.commit()
    print(f"[OK] Page Content Settings: {created_count} created, {updated_count} updated")

def create_admin_user(db):
    """Create the first admin user if it doesn't exist"""
    from models import User
    
    admin_password = os.getenv('ADMIN_PASSWORD')
    
    if not admin_password:
        print("[!] ADMIN_PASSWORD not set - skipping admin user creation")
        return
    
    admin = User.query.filter_by(username='admin').first()
    
    if admin:
        admin.role = 'admin'
        admin.is_admin = True
        admin.is_active = True
        admin.email = 'admin@cyberconfiance.fr'
        admin.set_password(admin_password)
        db.session.commit()
        print("[OK] Admin user updated with role and permissions")
    else:
        admin = User(
            username='admin',
            email='admin@cyberconfiance.fr',
            role='admin',
            is_admin=True,
            is_active=True,
            created_at=datetime.utcnow()
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        print("[OK] Admin user created successfully (username: admin)")

def seed_all_data(db):
    """Seed all data from JSON files"""
    print("Starting database seeding...")
    seed_rules(db)
    seed_scenarios(db)
    seed_glossary(db)
    seed_tools(db)
    seed_attack_types(db)
    seed_news(db)
    seed_site_settings(db)
    seed_page_content_settings(db)
    seed_seo_metadata(db)
    create_admin_user(db)
    print("Database seeding completed!")
