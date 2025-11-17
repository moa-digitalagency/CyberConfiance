import sys
sys.path.insert(0, '/home/runner/workspace')

from __init__ import create_app, db
from models import Rule

app = create_app()

with app.app_context():
    # Clear existing rules
    Rule.query.delete()
    db.session.commit()
    
    # Reset the auto-increment sequence for PostgreSQL
    db.session.execute(db.text("ALTER SEQUENCE rules_id_seq RESTART WITH 1"))
    
    rules_data = [
        {
            "title": "Séparez strictement vos usages privés et professionnels",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Mélanger vos activités personnelles et professionnelles expose vos données sensibles à des risques accrus. Un simple clic sur un lien malveillant depuis votre messagerie personnelle peut compromettre toute l'infrastructure de votre organisation.</p>

<h3>Risques</h3>
<ul>
<li>Fuite de données sensibles via des comptes personnels moins sécurisés</li>
<li>Contamination croisée en cas de cyberattaque</li>
<li>Difficulté à contrôler l'accès aux informations professionnelles</li>
<li>Violation des politiques de sécurité de l'organisation</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Utilisez un appareil distinct pour le travail et pour votre usage personnel</li>
<li>Si un seul appareil est disponible, créez des sessions utilisateur séparées</li>
<li>N'installez jamais d'applications personnelles sur votre équipement professionnel</li>
<li>Évitez de consulter vos e-mails professionnels sur vos appareils personnels non sécurisés</li>
<li>Configurez des profils séparés sur votre navigateur</li>
</ul>"""
        },
        {
            "title": "Protégez vos accès par des mots de passe complexes et uniques",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Un mot de passe faible ou réutilisé est la porte d'entrée principale pour les cybercriminels. Plus de 80% des violations de données impliquent des mots de passe compromis.</p>

<h3>Risques</h3>
<ul>
<li>Accès non autorisé à vos comptes et données sensibles</li>
<li>Vol d'identité et usurpation</li>
<li>Compromission en chaîne si le même mot de passe est utilisé sur plusieurs plateformes</li>
<li>Difficultés à prouver une violation non autorisée</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Créez des mots de passe d'au moins 12 caractères mélangeant majuscules, minuscules, chiffres et symboles</li>
<li>Utilisez un gestionnaire de mots de passe (Bitwarden, 1Password, KeePass)</li>
<li>Ne réutilisez jamais le même mot de passe sur plusieurs services</li>
<li>Changez vos mots de passe tous les 3-6 mois pour les comptes critiques</li>
<li>Évitez les informations personnelles (dates de naissance, noms de famille)</li>
</ul>"""
        },
        {
            "title": "Activez l'authentification à deux facteurs (2FA)",
            "description": """<h3>Pourquoi c'est important</h3>
<p>L'authentification à deux facteurs ajoute une couche de sécurité cruciale. Même si votre mot de passe est compromis, l'attaquant ne pourra pas accéder à votre compte sans le second facteur.</p>

<h3>Risques sans 2FA</h3>
<ul>
<li>Accès facile pour les pirates disposant de votre mot de passe</li>
<li>Vulnérabilité aux attaques par force brute</li>
<li>Impossibilité de détecter les tentatives d'accès non autorisées</li>
<li>Perte de contrôle total en cas de vol de mot de passe</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Activez la 2FA sur tous vos comptes importants (email, réseaux sociaux, banque)</li>
<li>Privilégiez les applications d'authentification (Google Authenticator, Authy) plutôt que les SMS</li>
<li>Utilisez une clé de sécurité physique (YubiKey) pour les comptes critiques</li>
<li>Conservez les codes de récupération dans un endroit sûr</li>
<li>Ne partagez jamais vos codes 2FA avec qui que ce soit</li>
</ul>"""
        },
        {
            "title": "Protégez vos équipements physiques",
            "description": """<h3>Pourquoi c'est important</h3>
<p>La sécurité numérique commence par la sécurité physique. Un ordinateur volé ou accessible peut compromettre toutes vos données, même avec des mots de passe robustes.</p>

<h3>Risques</h3>
<ul>
<li>Vol d'appareils contenant des données sensibles</li>
<li>Accès physique direct aux fichiers et systèmes</li>
<li>Installation de logiciels malveillants via un accès physique</li>
<li>Extraction de données depuis des disques durs non chiffrés</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Chiffrez intégralement vos disques durs (BitLocker pour Windows, FileVault pour Mac)</li>
<li>Ne laissez jamais vos appareils sans surveillance dans des lieux publics</li>
<li>Utilisez un câble antivol pour sécuriser vos ordinateurs portables</li>
<li>Rangez vos équipements dans des armoires verrouillées en fin de journée</li>
<li>Marquez vos appareils pour faciliter leur récupération en cas de vol</li>
</ul>"""
        },
        {
            "title": "Verrouillez vos appareils et espaces de travail",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Un écran déverrouillé est une invitation ouverte aux regards indiscrets et aux accès non autorisés. Quelques secondes suffisent pour compromettre des informations confidentielles.</p>

<h3>Risques</h3>
<ul>
<li>Accès non autorisé à vos données en votre absence</li>
<li>Vol ou modification de documents sensibles</li>
<li>Envoi de messages ou emails compromettants en votre nom</li>
<li>Installation discrète de logiciels espions</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Verrouillez votre écran dès que vous quittez votre poste (Windows + L sur Windows, Cmd + Ctrl + Q sur Mac)</li>
<li>Configurez un verrouillage automatique après 5 minutes d'inactivité</li>
<li>Utilisez des codes PIN ou la reconnaissance biométrique</li>
<li>Fermez vos sessions avant de partir en réunion</li>
<li>Rangez les documents physiques sensibles dans des tiroirs verrouillés</li>
</ul>"""
        },
        {
            "title": "Soyez vigilant avec les courriels et les liens non sollicités",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Le phishing (hameçonnage) est la technique d'attaque la plus courante. Les cybercriminels se font passer pour des entités de confiance pour voler vos informations.</p>

<h3>Risques</h3>
<ul>
<li>Vol de mots de passe et informations d'identification</li>
<li>Installation de ransomware ou logiciels malveillants</li>
<li>Accès non autorisé aux systèmes de votre organisation</li>
<li>Fraude financière et transferts frauduleux</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Vérifiez toujours l'adresse email de l'expéditeur avant de cliquer sur un lien</li>
<li>Survolez les liens avec votre souris pour voir la vraie URL avant de cliquer</li>
<li>Méfiez-vous des messages urgents demandant des actions immédiates</li>
<li>Ne téléchargez jamais de pièces jointes suspectes</li>
<li>Contactez l'expéditeur par un autre canal pour confirmer l'authenticité</li>
<li>Utilisez des outils anti-phishing dans votre navigateur</li>
</ul>"""
        },
        {
            "title": "Sauvegardez vos données régulièrement et de manière sécurisée",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Les sauvegardes sont votre dernier rempart contre les ransomwares, les pannes matérielles et les erreurs humaines. Sans sauvegardes régulières, vous risquez de perdre des années de travail.</p>

<h3>Risques</h3>
<ul>
<li>Perte définitive de données en cas d'attaque ransomware</li>
<li>Impossibilité de récupérer après une panne matérielle</li>
<li>Perte de données suite à des erreurs de manipulation</li>
<li>Interruption prolongée de l'activité professionnelle</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Suivez la règle 3-2-1 : 3 copies, sur 2 supports différents, dont 1 hors site</li>
<li>Automatisez vos sauvegardes quotidiennes ou hebdomadaires</li>
<li>Testez régulièrement la restauration de vos sauvegardes</li>
<li>Chiffrez vos sauvegardes pour protéger les données sensibles</li>
<li>Conservez une copie hors ligne (déconnectée d'Internet) pour éviter les ransomwares</li>
<li>Utilisez des services cloud réputés (Google Drive, OneDrive, Dropbox) en complément</li>
</ul>"""
        },
        {
            "title": "Évitez les réseaux publics non sécurisés",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Les réseaux Wi-Fi publics sont des terrains de chasse pour les cybercriminels. Vos données peuvent être interceptées facilement sur ces réseaux non sécurisés.</p>

<h3>Risques</h3>
<ul>
<li>Interception de vos communications et mots de passe</li>
<li>Attaques de type "Man-in-the-Middle"</li>
<li>Injection de malwares via des portails captifs compromis</li>
<li>Vol de données bancaires et d'identité</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Utilisez un VPN de confiance (NordVPN, ExpressVPN, ProtonVPN) sur les réseaux publics</li>
<li>Privilégiez votre connexion 4G/5G personnelle avec partage de connexion</li>
<li>Désactivez le partage de fichiers et la découverte réseau</li>
<li>Vérifiez que les sites utilisent HTTPS (cadenas dans la barre d'adresse)</li>
<li>Évitez les transactions bancaires ou l'accès à des données sensibles sur Wi-Fi public</li>
<li>Oubliez les réseaux Wi-Fi après utilisation pour éviter la reconnexion automatique</li>
</ul>"""
        },
        {
            "title": "Faites preuve de vigilance lors de vos échanges téléphoniques ou en visioconférence",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Les attaques par ingénierie sociale exploitent la confiance humaine. Les cybercriminels peuvent se faire passer pour des collègues, des fournisseurs ou des autorités pour obtenir des informations sensibles.</p>

<h3>Risques</h3>
<ul>
<li>Divulgation d'informations confidentielles par manipulation</li>
<li>Usurpation d'identité via clonage vocal (deepfake audio)</li>
<li>Interception de communications non chiffrées</li>
<li>Espionnage industriel et vol de secrets commerciaux</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Vérifiez toujours l'identité de votre interlocuteur avant de partager des informations</li>
<li>Utilisez des plateformes de visioconférence sécurisées avec chiffrement de bout en bout</li>
<li>Ne divulguez jamais de mots de passe ou informations sensibles par téléphone</li>
<li>Méfiez-vous des demandes urgentes ou inhabituelles</li>
<li>Établissez un protocole de vérification d'identité avec votre organisation</li>
<li>Enregistrez les numéros de téléphone officiels pour les rappels de vérification</li>
</ul>"""
        },
        {
            "title": "Veillez à la sécurité de votre smartphone",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Votre smartphone contient autant, sinon plus, d'informations sensibles que votre ordinateur : emails, messages, contacts, photos, applications bancaires. Sa sécurité est primordiale.</p>

<h3>Risques</h3>
<ul>
<li>Accès à toutes vos données personnelles et professionnelles en cas de vol</li>
<li>Interception de vos communications et messages</li>
<li>Utilisation malveillante de vos applications bancaires et de paiement</li>
<li>Vol d'identité via vos réseaux sociaux et emails</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Activez le verrouillage biométrique (empreinte digitale ou reconnaissance faciale)</li>
<li>Installez uniquement des applications depuis les stores officiels (Google Play, App Store)</li>
<li>Mettez à jour régulièrement votre système d'exploitation et vos applications</li>
<li>Activez la localisation à distance et l'effacement des données en cas de perte</li>
<li>Chiffrez les données de votre smartphone</li>
<li>Vérifiez les permissions demandées par chaque application</li>
<li>Désactivez Bluetooth et Wi-Fi quand vous ne les utilisez pas</li>
</ul>"""
        },
        {
            "title": "Surveillez votre identité numérique sur les réseaux sociaux",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Vos publications sur les réseaux sociaux révèlent énormément d'informations sur vous. Les cybercriminels utilisent ces données pour créer des attaques ciblées et personnalisées.</p>

<h3>Risques</h3>
<ul>
<li>Utilisation de vos informations pour des attaques de phishing ciblées</li>
<li>Ingénierie sociale basée sur vos habitudes et relations</li>
<li>Atteinte à votre réputation professionnelle</li>
<li>Exposition de votre famille et de vos proches à des risques</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Limitez la visibilité de vos publications aux amis/contacts de confiance uniquement</li>
<li>Ne partagez jamais d'informations sensibles (adresse, numéros, calendrier de voyage)</li>
<li>Vérifiez régulièrement vos paramètres de confidentialité</li>
<li>Réfléchissez avant de publier : cette information peut-elle me nuire professionnellement ?</li>
<li>Utilisez différents comptes pour usage personnel et professionnel</li>
<li>Évitez de géolocaliser vos publications en temps réel</li>
<li>Désactivez le marquage automatique sur les photos</li>
</ul>"""
        },
        {
            "title": "Mettez à jour vos logiciels et appareils régulièrement",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Les mises à jour corrigent les failles de sécurité découvertes dans les logiciels. Les cybercriminels exploitent activement ces vulnérabilités connues pour infiltrer les systèmes non à jour.</p>

<h3>Risques</h3>
<ul>
<li>Exploitation de failles de sécurité connues et documentées</li>
<li>Infection par des malwares ciblant des versions obsolètes</li>
<li>Incompatibilité avec les nouveaux protocoles de sécurité</li>
<li>Perte de support technique et de correctifs</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Activez les mises à jour automatiques sur tous vos appareils</li>
<li>Installez les correctifs de sécurité dès leur disponibilité</li>
<li>Remplacez les logiciels qui ne sont plus supportés par l'éditeur</li>
<li>Planifiez des fenêtres de maintenance régulières pour les mises à jour</li>
<li>Vérifiez que tous vos plugins et extensions de navigateur sont à jour</li>
<li>Testez les mises à jour critiques sur un environnement de test avant déploiement massif</li>
</ul>"""
        },
        {
            "title": "Formez-vous et sensibilisez votre équipe aux bonnes pratiques de cybersécurité",
            "description": """<h3>Pourquoi c'est important</h3>
<p>L'humain reste le maillon faible de la sécurité. Une équipe bien formée est votre meilleure défense contre les cyberattaques.</p>

<h3>Risques</h3>
<ul>
<li>Erreurs humaines causant des violations de données</li>
<li>Manque de vigilance face aux nouvelles menaces</li>
<li>Réponse inadéquate lors d'incidents de sécurité</li>
<li>Culture de sécurité inexistante dans l'organisation</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Organisez des formations régulières sur la cybersécurité</li>
<li>Effectuez des simulations d'attaques (phishing tests, exercices de réponse aux incidents)</li>
<li>Créez des guides de bonnes pratiques accessibles à tous</li>
<li>Encouragez le signalement des incidents sans crainte de sanctions</li>
<li>Nommez des référents sécurité dans chaque département</li>
<li>Restez informé des nouvelles menaces via des newsletters spécialisées</li>
<li>Partagez les leçons apprises lors d'incidents de sécurité</li>
</ul>"""
        },
        {
            "title": "Installez des filtres de confidentialité sur vos écrans",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Dans les lieux publics, les regards indiscrets peuvent facilement capturer des informations sensibles affichées sur votre écran. Un filtre de confidentialité limite l'angle de vision.</p>

<h3>Risques</h3>
<ul>
<li>Surveillance visuelle directe de vos activités</li>
<li>Capture de mots de passe et informations confidentielles</li>
<li>Espionnage industriel dans les transports et espaces publics</li>
<li>Prise de photos/vidéos de votre écran à votre insu</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Installez un filtre de confidentialité 3M ou similaire sur vos écrans d'ordinateur et smartphone</li>
<li>Positionnez-vous dos au mur dans les espaces publics</li>
<li>Réduisez la luminosité de votre écran dans les lieux publics</li>
<li>Évitez de travailler sur des documents sensibles dans les transports</li>
<li>Utilisez le mode "écran de confidentialité" s'il est disponible sur votre appareil</li>
<li>Restez vigilant à votre environnement lors du travail en mobilité</li>
</ul>"""
        },
        {
            "title": "Évitez d'utiliser des équipements non vérifiés",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Les équipements inconnus peuvent être compromis ou contenir des logiciels malveillants. Un simple câble USB ou une clé de charge peut servir de vecteur d'attaque.</p>

<h3>Risques</h3>
<ul>
<li>Infection par malware via des périphériques compromis</li>
<li>Vol de données via des câbles USB malveillants</li>
<li>Keylogging et surveillance via du matériel modifié</li>
<li>Prise de contrôle totale de vos appareils</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>N'utilisez jamais de clés USB trouvées ou d'origine inconnue</li>
<li>Utilisez vos propres câbles de charge, évitez les bornes USB publiques</li>
<li>Si nécessaire, utilisez un "USB data blocker" sur les bornes publiques</li>
<li>Scannez tous les périphériques externes avec un antivirus avant utilisation</li>
<li>Désactivez l'exécution automatique des périphériques USB</li>
<li>Fournissez du matériel officiel validé à vos équipes</li>
<li>Marquez et inventoriez tous les équipements de l'organisation</li>
</ul>"""
        },
        {
            "title": "Stockez vos données sensibles dans des espaces sécurisés",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Les données sensibles nécessitent une protection renforcée. Un stockage non sécurisé expose vos informations critiques à des accès non autorisés.</p>

<h3>Risques</h3>
<ul>
<li>Accès non autorisé à des informations confidentielles</li>
<li>Fuite de données personnelles ou commerciales</li>
<li>Non-conformité aux réglementations (RGPD, etc.)</li>
<li>Perte de contrôle sur la diffusion des informations</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Chiffrez tous les fichiers contenant des données sensibles</li>
<li>Utilisez des coffres-forts numériques (VeraCrypt, Cryptomator)</li>
<li>Stockez les documents ultra-confidentiels hors ligne sur des supports déconnectés</li>
<li>Limitez l'accès aux données sensibles selon le principe du "besoin d'en connaître"</li>
<li>Utilisez des services cloud avec chiffrement de bout en bout</li>
<li>Évitez de stocker des données sensibles sur des appareils mobiles non chiffrés</li>
<li>Détruisez correctement les supports de stockage obsolètes</li>
</ul>"""
        },
        {
            "title": "Identifiez et signalez les anomalies",
            "description": """<h3>Pourquoi c'est important</h3>
<p>La détection précoce d'une intrusion peut limiter considérablement les dégâts. Rester vigilant aux signaux d'alerte est essentiel.</p>

<h3>Signes d'alerte</h3>
<ul>
<li>Ralentissements inexpliqués de votre système</li>
<li>Activités suspectes sur vos comptes (connexions inhabituelles, modifications non effectuées)</li>
<li>Fenêtres pop-up inattendues ou comportement étrange des applications</li>
<li>Fichiers modifiés ou supprimés sans raison</li>
<li>Messages ou emails envoyés sans votre consentement</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Surveillez régulièrement l'historique de connexion de vos comptes</li>
<li>Activez les alertes pour les connexions depuis de nouveaux appareils</li>
<li>Installez et maintenez à jour un antivirus de qualité</li>
<li>Consultez régulièrement les journaux d'activité de vos systèmes</li>
<li>Établissez un protocole clair de signalement des incidents</li>
<li>Ne tentez pas de résoudre seul un incident grave, contactez votre équipe IT</li>
<li>Documentez tout comportement anormal pour faciliter l'investigation</li>
</ul>"""
        },
        {
            "title": "Protégez vos sauvegardes contre les ransomwares",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Les ransomwares modernes ciblent spécifiquement les sauvegardes pour vous forcer à payer la rançon. Une stratégie de sauvegarde robuste doit anticiper cette menace.</p>

<h3>Risques</h3>
<ul>
<li>Chiffrement de toutes vos sauvegardes accessibles par le ransomware</li>
<li>Impossibilité de récupérer vos données sans payer la rançon</li>
<li>Interruption prolongée de l'activité</li>
<li>Pertes financières importantes</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Conservez au moins une copie de sauvegarde complètement déconnectée (air-gapped)</li>
<li>Utilisez le principe d'immutabilité : rendez vos sauvegardes non modifiables</li>
<li>Stockez des sauvegardes dans différents emplacements physiques</li>
<li>Testez régulièrement la restauration de vos sauvegardes hors ligne</li>
<li>Implémentez une rotation de sauvegardes (quotidienne, hebdomadaire, mensuelle)</li>
<li>Séparez les droits d'accès : l'utilisateur quotidien ne doit pas pouvoir supprimer les sauvegardes</li>
<li>Automatisez le processus pour éviter les oublis</li>
</ul>"""
        },
        {
            "title": "Soyez vigilant face aux deepfakes et fraudes vocales",
            "description": """<h3>Pourquoi c'est important</h3>
<p>L'intelligence artificielle permet désormais de créer des faux audios et vidéos ultra-réalistes. Ces deepfakes sont utilisés pour des escroqueries financières et de la manipulation.</p>

<h3>Risques</h3>
<ul>
<li>Fraudes financières par usurpation d'identité vocale</li>
<li>Manipulation politique et diffusion de fausses informations</li>
<li>Chantage et atteinte à la réputation</li>
<li>Prise de décisions basées sur de fausses preuves</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Établissez un mot de code secret avec vos proches et collègues pour les situations critiques</li>
<li>Vérifiez toujours les demandes urgentes par un second canal de communication</li>
<li>Méfiez-vous des appels vidéo de mauvaise qualité ou avec des anomalies visuelles</li>
<li>Limitez le contenu audio/vidéo que vous publiez publiquement</li>
<li>Formez vos équipes à reconnaître les signes de deepfakes</li>
<li>Utilisez des outils de détection de deepfakes quand c'est possible</li>
<li>Ne validez jamais de transactions importantes uniquement sur base d'un appel téléphonique</li>
</ul>"""
        },
        {
            "title": "Prévoyez une politique claire de gestion des incidents",
            "description": """<h3>Pourquoi c'est important</h3>
<p>Une cyberattaque peut survenir à tout moment. Avoir un plan de réponse préétabli permet de réagir rapidement et efficacement, limitant les dégâts.</p>

<h3>Risques sans plan</h3>
<ul>
<li>Panique et décisions impulsives aggravant la situation</li>
<li>Perte de temps précieux dans les premières heures critiques</li>
<li>Absence de coordination entre les équipes</li>
<li>Destruction de preuves nécessaires à l'investigation</li>
<li>Communication incohérente créant la confusion</li>
</ul>

<h3>Solutions pratiques</h3>
<ul>
<li>Créez un plan de réponse aux incidents documenté et accessible</li>
<li>Identifiez une équipe de réponse avec des rôles et responsabilités clairs</li>
<li>Établissez une chaîne de communication d'urgence</li>
<li>Conservez les contacts d'experts en cybersécurité et forces de l'ordre</li>
<li>Organisez des exercices de simulation d'incidents régulièrement</li>
<li>Préparez des templates de communication de crise</li>
<li>Documentez toutes les actions prises pendant un incident</li>
<li>Réalisez un débriefing après chaque incident pour améliorer le processus</li>
</ul>"""
        }
    ]
    
    for rule_data in rules_data:
        rule = Rule(
            title=rule_data["title"],
            description=rule_data["description"]
        )
        db.session.add(rule)
    
    db.session.commit()
    print(f"✓ {len(rules_data)} règles d'or ajoutées avec succès!")
