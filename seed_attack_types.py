from models import AttackType
import __init__ as app_module
db = app_module.db

def seed_attack_types():
    """
    Remplit la base de données avec les types d'attaques depuis Hacksplaining
    Traduit en français avec descriptions adaptées
    """
    
    attacks_data = [
        {
            'name_en': 'SQL Injection',
            'name_fr': 'Injection SQL',
            'description_fr': 'Une vulnérabilité permettant aux attaquants d\'exécuter des commandes SQL arbitraires contre votre base de données, pouvant exposer ou détruire des données sensibles.',
            'category': 'Web',
            'severity': 'Critique',
            'prevention': 'Utilisez des requêtes paramétrées, validez toutes les entrées utilisateur et implémentez le principe du moindre privilège pour les comptes de base de données.',
            'order': 1
        },
        {
            'name_en': 'Cross-Site Scripting (XSS)',
            'name_fr': 'Cross-Site Scripting (XSS)',
            'description_fr': 'Permet aux attaquants d\'injecter du JavaScript malveillant dans votre site, volant ainsi les données des utilisateurs ou détournant leurs sessions.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Échappez tout contenu utilisateur, utilisez Content Security Policy (CSP) et validez les entrées côté serveur.',
            'order': 2
        },
        {
            'name_en': 'Command Execution',
            'name_fr': 'Exécution de Commandes',
            'description_fr': 'Si votre application appelle le système d\'exploitation, vous devez vous assurer que les chaînes de commandes sont construites de manière sécurisée pour éviter l\'exécution de code arbitraire.',
            'category': 'Web',
            'severity': 'Critique',
            'prevention': 'Évitez d\'exécuter des commandes système avec des entrées utilisateur. Si nécessaire, utilisez des listes blanches et validez strictement les paramètres.',
            'order': 3
        },
        {
            'name_en': 'Clickjacking',
            'name_fr': 'Détournement de Clic',
            'description_fr': 'Les attaquants superposent des éléments invisibles sur votre site pour détourner les clics des utilisateurs vers des actions non souhaitées.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Utilisez les en-têtes X-Frame-Options ou Content-Security-Policy avec frame-ancestors pour empêcher l\'intégration de votre site dans des iframes malveillantes.',
            'order': 4
        },
        {
            'name_en': 'Cross-Site Request Forgery (CSRF)',
            'name_fr': 'Falsification de Requête Inter-Sites (CSRF)',
            'description_fr': 'Les attaquants peuvent forger des requêtes HTTP vers votre site pour tromper vos utilisateurs et déclencher des actions non désirées.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Implémentez des jetons CSRF, vérifiez l\'en-tête Referer et utilisez SameSite cookies.',
            'order': 5
        },
        {
            'name_en': 'Directory Traversal',
            'name_fr': 'Traversée de Répertoires',
            'description_fr': 'Permet aux attaquants d\'accéder à des fichiers sensibles sur votre serveur en manipulant les chemins de fichiers.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Validez et normalisez tous les chemins de fichiers, utilisez des listes blanches de fichiers autorisés et ne faites jamais confiance aux entrées utilisateur.',
            'order': 6
        },
        {
            'name_en': 'Reflected XSS',
            'name_fr': 'XSS Réfléchi',
            'description_fr': 'Du JavaScript malveillant est renvoyé depuis votre serveur dans la réponse, permettant aux attaquants d\'exploiter vos utilisateurs.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Échappez toutes les données reflétées dans les réponses, validez les entrées et utilisez CSP.',
            'order': 7
        },
        {
            'name_en': 'DOM-based XSS',
            'name_fr': 'XSS Basé sur le DOM',
            'description_fr': 'Vulnérabilité XSS qui se produit entièrement côté client, souvent via la manipulation des fragments d\'URI.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Évitez d\'utiliser des fonctions JavaScript dangereuses avec des données non fiables, validez les fragments d\'URI et utilisez des bibliothèques de sécurité.',
            'order': 8
        },
        {
            'name_en': 'File Upload Vulnerabilities',
            'name_fr': 'Vulnérabilités de Téléversement de Fichiers',
            'description_fr': 'Les uploads de fichiers sont un moyen facile pour un attaquant d\'injecter du code malveillant dans votre application.',
            'category': 'Web',
            'severity': 'Critique',
            'prevention': 'Validez le type et la taille des fichiers, stockez-les en dehors de la racine web, scannez-les avec un antivirus et renommez-les.',
            'order': 9
        },
        {
            'name_en': 'Broken Access Control',
            'name_fr': 'Contrôle d\'Accès Défaillant',
            'description_fr': 'Toutes les ressources de votre site doivent avoir un contrôle d\'accès, même si elles ne sont pas destinées à être découvertes.',
            'category': 'Web',
            'severity': 'Critique',
            'prevention': 'Implémentez une autorisation stricte sur toutes les ressources, utilisez le principe du moindre privilège et testez régulièrement les contrôles d\'accès.',
            'order': 10
        },
        {
            'name_en': 'Open Redirects',
            'name_fr': 'Redirections Ouvertes',
            'description_fr': 'Si votre site redirige vers des URLs fournies dans les paramètres, vous pourriez faciliter des attaques de phishing.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Utilisez des listes blanches de destinations de redirection valides ou évitez complètement les redirections basées sur des paramètres.',
            'order': 11
        },
        {
            'name_en': 'Unencrypted Communication',
            'name_fr': 'Communication Non Chiffrée',
            'description_fr': 'Un chiffrement insuffisant vous rend vulnérable aux attaques de type homme du milieu.',
            'category': 'Network',
            'severity': 'Critique',
            'prevention': 'Utilisez HTTPS avec TLS 1.2 ou supérieur, implémentez HSTS et utilisez des certificats valides.',
            'order': 12
        },
        {
            'name_en': 'User Enumeration',
            'name_fr': 'Énumération d\'Utilisateurs',
            'description_fr': 'Divulguer des informations sur les noms d\'utilisateur facilite grandement le travail des hackers.',
            'category': 'Web',
            'severity': 'Faible',
            'prevention': 'Utilisez des messages d\'erreur génériques pour l\'authentification et le reset de mot de passe.',
            'order': 13
        },
        {
            'name_en': 'Information Leakage',
            'name_fr': 'Fuite d\'Informations',
            'description_fr': 'Révéler des informations système aide un attaquant à en apprendre davantage sur votre stack technique.',
            'category': 'Web',
            'severity': 'Faible',
            'prevention': 'Désactivez les messages d\'erreur détaillés en production, supprimez les en-têtes révélateurs et masquez les versions.',
            'order': 14
        },
        {
            'name_en': 'Password Mismanagement',
            'name_fr': 'Mauvaise Gestion des Mots de Passe',
            'description_fr': 'Le traitement sécurisé des mots de passe est essentiel, pourtant de nombreux sites le font mal.',
            'category': 'Web',
            'severity': 'Critique',
            'prevention': 'Utilisez des algorithmes de hachage modernes (bcrypt, Argon2), n\'envoyez jamais de mots de passe en clair et implémentez une politique de mots de passe forts.',
            'order': 15
        },
        {
            'name_en': 'Privilege Escalation',
            'name_fr': 'Élévation de Privilèges',
            'description_fr': 'Se produit quand un attaquant exploite une vulnérabilité pour usurper l\'identité d\'un autre utilisateur ou obtenir des permissions supplémentaires.',
            'category': 'Web',
            'severity': 'Critique',
            'prevention': 'Vérifiez les autorisations à chaque requête, séparez les rôles clairement et auditez les actions privilégiées.',
            'order': 16
        },
        {
            'name_en': 'Session Fixation',
            'name_fr': 'Fixation de Session',
            'description_fr': 'Un traitement non sécurisé des IDs de session peut permettre le détournement de session utilisateur.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Régénérez les IDs de session après l\'authentification, utilisez des cookies sécurisés et implémentez des timeouts de session.',
            'order': 17
        },
        {
            'name_en': 'Weak Session IDs',
            'name_fr': 'IDs de Session Faibles',
            'description_fr': 'Des IDs de session prévisibles rendent votre site vulnérable au détournement de session.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Utilisez des générateurs cryptographiquement sécurisés pour les IDs de session et assurez une entropie suffisante.',
            'order': 18
        },
        {
            'name_en': 'XML Bombs',
            'name_fr': 'Bombes XML',
            'description_fr': 'Un traitement non sécurisé des macros XML peut rendre votre serveur vulnérable à des fichiers XML spécialement conçus.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Désactivez les entités externes XML, limitez la profondeur et la taille des documents XML, et utilisez des parseurs sécurisés.',
            'order': 19
        },
        {
            'name_en': 'XML External Entities (XXE)',
            'name_fr': 'Entités Externes XML (XXE)',
            'description_fr': 'Un traitement non sécurisé des références externes dans XML permet à un attaquant de sonder votre système de fichiers.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Désactivez les entités externes XML, utilisez des formats de données moins complexes comme JSON quand possible.',
            'order': 20
        },
        {
            'name_en': 'Denial of Service Attacks',
            'name_fr': 'Attaques par Déni de Service (DoS)',
            'description_fr': 'Parfois les attaquants veulent simplement rendre votre site indisponible aux autres utilisateurs.',
            'category': 'Network',
            'severity': 'Élevé',
            'prevention': 'Implémentez la limitation de débit, utilisez des CDN et services anti-DDoS, et configurez des timeouts appropriés.',
            'order': 21
        },
        {
            'name_en': 'Email Spoofing',
            'name_fr': 'Usurpation d\'Email',
            'description_fr': 'L\'envoi de messages email avec une adresse d\'expéditeur falsifiée pour tromper les destinataires.',
            'category': 'Social',
            'severity': 'Moyen',
            'prevention': 'Configurez SPF, DKIM et DMARC pour votre domaine, et éduquez les utilisateurs sur la vérification des expéditeurs.',
            'order': 22
        },
        {
            'name_en': 'Malvertising',
            'name_fr': 'Publicité Malveillante',
            'description_fr': 'Les publicités intégrées sont une cible commune pour les hackers qui y injectent du code malveillant.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Utilisez des réseaux publicitaires de confiance, implémentez CSP et scannez régulièrement votre site.',
            'order': 23
        },
        {
            'name_en': 'Lax Security Settings',
            'name_fr': 'Paramètres de Sécurité Laxistes',
            'description_fr': 'Des paramètres de sécurité inappropriés sont une cause commune de vulnérabilités.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Suivez les guides de durcissement sécuritaire, désactivez les fonctionnalités inutilisées et maintenez les systèmes à jour.',
            'order': 24
        },
        {
            'name_en': 'Toxic Dependencies',
            'name_fr': 'Dépendances Toxiques',
            'description_fr': 'Les bibliothèques tierces peuvent introduire des vulnérabilités ou du code malveillant dans votre système.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Auditez vos dépendances régulièrement, utilisez des outils de scan de vulnérabilités et maintenez-les à jour.',
            'order': 25
        },
        {
            'name_en': 'Logging and Monitoring',
            'name_fr': 'Journalisation et Surveillance',
            'description_fr': 'Une journalisation et surveillance complètes sont essentielles pour détecter les événements de sécurité.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Implémentez une journalisation centralisée, surveillez les événements de sécurité et configurez des alertes.',
            'order': 26
        },
        {
            'name_en': 'Buffer Overflows',
            'name_fr': 'Dépassements de Tampon',
            'description_fr': 'Les dépassements de tampon peuvent permettre aux attaquants de prendre le contrôle de votre serveur ou d\'injecter du code malveillant.',
            'category': 'Web',
            'severity': 'Critique',
            'prevention': 'Utilisez des langages avec gestion automatique de la mémoire, validez les tailles d\'entrée et utilisez des protections au niveau système.',
            'order': 27
        },
        {
            'name_en': 'Server-Side Request Forgery (SSRF)',
            'name_fr': 'Falsification de Requête Côté Serveur (SSRF)',
            'description_fr': 'Permet aux attaquants d\'utiliser votre serveur pour sonder votre réseau interne.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Validez et filtrez toutes les URLs fournies par l\'utilisateur, utilisez des listes blanches et segmentez votre réseau.',
            'order': 28
        },
        {
            'name_en': 'Host Header Poisoning',
            'name_fr': 'Empoisonnement de l\'En-tête Host',
            'description_fr': 'Il est dangereux de se fier à la valeur fournie dans l\'en-tête Host d\'une requête HTTP.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Validez l\'en-tête Host, utilisez des listes blanches de domaines et configurez correctement votre serveur web.',
            'order': 29
        },
        {
            'name_en': 'Insecure Design',
            'name_fr': 'Conception Non Sécurisée',
            'description_fr': 'La sécurité commence avant même d\'écrire du code - une mauvaise conception architecturale crée des vulnérabilités.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Intégrez la sécurité dès la conception, effectuez des modélisations de menaces et suivez les principes de sécurité by design.',
            'order': 30
        },
        {
            'name_en': 'Mass Assignment',
            'name_fr': 'Affectation en Masse',
            'description_fr': 'Déballer automatiquement les données de requête HTTP peut parfois être trop facile et permettre la modification de champs non autorisés.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Utilisez des listes blanches explicites pour les champs autorisés et ne faites pas confiance aux entrées utilisateur.',
            'order': 31
        },
        {
            'name_en': 'Prototype Pollution',
            'name_fr': 'Pollution de Prototype',
            'description_fr': 'Si un attaquant peut accéder et modifier les objets prototype en JavaScript, votre application est en danger.',
            'category': 'Web',
            'severity': 'Élevé',
            'prevention': 'Validez les clés d\'objets, utilisez Object.create(null) pour créer des objets sans prototype et gelés les prototypes critiques.',
            'order': 32
        },
        {
            'name_en': 'Regex Injection',
            'name_fr': 'Injection d\'Expressions Régulières',
            'description_fr': 'Les expressions régulières sont fréquemment utilisées en développement web, mais peuvent être abusées par les attaquants.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Évitez d\'utiliser des regex avec des entrées utilisateur, limitez la complexité et le temps d\'exécution des regex.',
            'order': 33
        },
        {
            'name_en': 'Remote Code Execution',
            'name_fr': 'Exécution de Code à Distance',
            'description_fr': 'Si un attaquant peut injecter du code dans votre processus serveur, vous avez un problème grave.',
            'category': 'Web',
            'severity': 'Critique',
            'prevention': 'Évitez d\'exécuter du code non fiable, désactivez les fonctions dangereuses et appliquez le principe du moindre privilège.',
            'order': 34
        },
        {
            'name_en': 'Cross-Site Script Inclusion (XSSI)',
            'name_fr': 'Inclusion de Script Inter-Sites (XSSI)',
            'description_fr': 'Si vous placez des données sensibles dans vos fichiers JavaScript, un attaquant les vole probablement.',
            'category': 'Web',
            'severity': 'Moyen',
            'prevention': 'Ne stockez jamais de données sensibles dans des fichiers JavaScript, utilisez des endpoints JSON protégés par CSRF.',
            'order': 35
        },
        {
            'name_en': 'Downgrade Attacks',
            'name_fr': 'Attaques par Rétrogradation',
            'description_fr': 'Les attaquants peuvent intercepter et manipuler le trafic HTTPS si vous ne spécifiez pas une version moderne de TLS.',
            'category': 'Network',
            'severity': 'Élevé',
            'prevention': 'Désactivez les versions anciennes de SSL/TLS, utilisez TLS 1.2+ uniquement et configurez HSTS.',
            'order': 36
        },
        {
            'name_en': 'DNS Poisoning',
            'name_fr': 'Empoisonnement DNS',
            'description_fr': 'Si les caches DNS en amont ont été empoisonnés, les attaquants peuvent intercepter le trafic avant qu\'il n\'arrive chez vous.',
            'category': 'Network',
            'severity': 'Élevé',
            'prevention': 'Utilisez DNSSEC, surveillez les résolutions DNS et utilisez des serveurs DNS de confiance.',
            'order': 37
        },
        {
            'name_en': 'SSL Stripping',
            'name_fr': 'Suppression SSL',
            'description_fr': 'Si seules certaines actions nécessitent HTTPS, un attaquant peut voler les identifiants de vos utilisateurs.',
            'category': 'Network',
            'severity': 'Élevé',
            'prevention': 'Utilisez HTTPS partout, implémentez HSTS et ne mélangez jamais contenu HTTP et HTTPS.',
            'order': 38
        },
        {
            'name_en': 'Subdomain Squatting',
            'name_fr': 'Détournement de Sous-domaines',
            'description_fr': 'Les attaquants voleront des sous-domaines non utilisés pour distribuer des malwares et effectuer des attaques de phishing.',
            'category': 'Network',
            'severity': 'Moyen',
            'prevention': 'Supprimez les enregistrements DNS inutilisés, surveillez vos sous-domaines et utilisez des certificats wildcard avec précaution.',
            'order': 39
        },
        {
            'name_en': 'AI: Bias and Unreliability',
            'name_fr': 'IA: Biais et Fiabilité',
            'description_fr': 'L\'apprentissage automatique est sujet aux biais et à l\'instabilité - il faut des garde-fous pour s\'en protéger.',
            'category': 'AI',
            'severity': 'Moyen',
            'prevention': 'Testez les modèles sur des datasets diversifiés, surveillez les prédictions et implémentez des contrôles humains.',
            'order': 40
        },
        {
            'name_en': 'AI: Prompt Injection',
            'name_fr': 'IA: Injection de Prompt',
            'description_fr': 'L\'injection de prompt permet aux attaquants d\'introduire facilement des comportements inattendus dans un modèle d\'apprentissage.',
            'category': 'AI',
            'severity': 'Élevé',
            'prevention': 'Validez et filtrez les prompts utilisateur, limitez les actions du modèle et surveillez les sorties anormales.',
            'order': 41
        },
        {
            'name_en': 'AI: Data Extraction Attacks',
            'name_fr': 'IA: Attaques d\'Extraction de Données',
            'description_fr': 'Votre modèle d\'apprentissage peut divulguer des données sensibles sans que vous le sachiez.',
            'category': 'AI',
            'severity': 'Critique',
            'prevention': 'N\'entraînez pas les modèles sur des données sensibles, utilisez la confidentialité différentielle et auditez les sorties du modèle.',
            'order': 42
        }
    ]
    
    print("Démarrage du seed des types d'attaques...")
    
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
    
    try:
        db.session.commit()
        print(f"✓ Types d'attaques: {created_count} créés, {updated_count} mis à jour")
    except Exception as e:
        db.session.rollback()
        print(f"❌ Erreur lors du seed: {str(e)}")
        raise

if __name__ == '__main__':
    with app_module.app.app_context():
        seed_attack_types()
        print("✅ Seed terminé avec succès!")
