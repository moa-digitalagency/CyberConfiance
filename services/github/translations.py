"""
Traductions françaises complètes pour l'analyseur GitHub.
Couvre tous les messages Semgrep et descriptions génériques.
"""

SEMGREP_TRANSLATIONS = {
    "The password on 'admin' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Le mot de passe 'admin' est défini sans validation - utilisez check_password()",
    
    "The password on 'dr_kalonji' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Le mot de passe 'dr_kalonji' est défini sans validation - utilisez check_password()",
    
    "The password on 'current_user' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Le mot de passe utilisateur est modifié sans validation préalable",
    
    "The password on 'user' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Le mot de passe utilisateur est défini sans validation de sécurité",
    
    "Running flask app with host 0.0.0.0 could expose the server publicly. This is dangerous as any computer on the network could connect. Use '127.0.0.1' instead.":
        "Lancer Flask avec host='0.0.0.0' expose le serveur publiquement - utilisez '127.0.0.1' en développement",
    
    "Detected explicitly unescaped content using 'Markup()'. This bypasses HTML escaping and could lead to XSS attacks.":
        "Contenu non échappé via Markup() - contournement de la protection XSS",
    
    "Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF).":
        "Données de requête transmises à une requête serveur - risque SSRF (Server-Side Request Forgery)",
    
    "User data flows into the host portion of this manually-constructed URL. This could lead to SSRF.":
        "Données utilisateur injectées dans l'URL construite manuellement - risque SSRF",
    
    "Data from request is passed to redirect(). This is an open redirect and could be used to redirect users to malicious sites.":
        "Redirection ouverte détectée - les utilisateurs peuvent être redirigés vers des sites malveillants",
    
    "Detected user input flowing into a manually constructed HTML string. You may be bypassing Jinja2's built-in HTML escaping. Use render_template() and templates with autoescaping enabled to prevent XSS.":
        "Injection d'entrée utilisateur dans HTML manuel - contournement de l'échappement Jinja2 - risque XSS",
    
    "User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` can result in XSS. Consider using `textContent` or `createTextNode` instead.":
        "Données utilisateur dans innerHTML/outerHTML - risque XSS critique - utilisez textContent à la place",
    
    "The password on 'admin' is being set without validating":
        "Le mot de passe 'admin' est défini sans validation",
    
    "Running flask app with host 0.0.0.0 could expose the server":
        "Lancer Flask avec host 0.0.0.0 expose le serveur publiquement",
    
    "Detected explicitly unescaped content using 'Markup()'":
        "Contenu non échappé détecté avec Markup() - risque XSS",
    
    "Data from request object is passed to a new server-side request":
        "Données de requête transmises à une requête serveur - risque SSRF",
    
    "User data flows into the host portion of this manually-constructed":
        "Données utilisateur injectées dans l'hôte de l'URL - risque SSRF",
    
    "Data from request is passed to redirect()":
        "Données de requête passées à redirect() - risque Open Redirect",
    
    "This is an open redirect":
        "Redirection ouverte détectée",
}

REMEDIATION_TRANSLATIONS = {
    "Consult the Semgrep documentation": 
        "Voir les meilleures pratiques de sécurité pour ce type de vulnérabilité",
    
    "Consultez la documentation Semgrep": 
        "Voir les meilleures pratiques de sécurité pour ce type de vulnérabilité",
    
    "See the Semgrep rule": 
        "Consultez la règle de sécurité spécifique",
    
    "Review the code": 
        "Révisez le code pour corriger cette vulnérabilité",
    
    "Consider using": 
        "Envisagez d'utiliser",
    
    "Use parameterized queries": 
        "Utilisez des requêtes paramétrées",
    
    "Validate user input": 
        "Validez les entrées utilisateur",
    
    "Escape HTML content": 
        "Échappez le contenu HTML",
    
    "Use environment variables": 
        "Utilisez des variables d'environnement",
    
    "Update the dependency": 
        "Mettez à jour la dépendance",
}

SECURITY_TRANSLATIONS = {
    "Hardcoded password": "Mot de passe codé en dur",
    "SQL injection": "Injection SQL",
    "Cross-site scripting": "Faille XSS (Cross-site scripting)",
    "Command injection": "Injection de commandes",
    "Path traversal": "Traversée de chemin",
    "Insecure deserialization": "Désérialisation non sécurisée",
    "Server-side request forgery": "Falsification de requête côté serveur (SSRF)",
    "Unvalidated redirect": "Redirection non validée",
    "Debug mode enabled": "Mode debug activé",
    "Weak cryptography": "Cryptographie faible",
    "Insecure random": "Générateur aléatoire non sécurisé",
    "Hardcoded secret": "Secret codé en dur",
    "Missing authentication": "Authentification manquante",
    "Insufficient logging": "Journalisation insuffisante",
    "Exposed sensitive data": "Données sensibles exposées",
    "Insecure cookie": "Cookie non sécurisé",
    "Missing CSRF protection": "Protection CSRF manquante",
    "Insecure SSL/TLS": "SSL/TLS non sécurisé",
    "Dangerous function": "Fonction dangereuse",
    "Eval injection": "Injection via eval()",
    "Use a secure random number generator": "Utilisez un générateur aléatoire sécurisé",
    "Enable HTTPS": "Activez HTTPS",
    "Enable CSRF protection": "Activez la protection CSRF",
    "Use secure cookies": "Utilisez des cookies sécurisés",
    "Disable debug mode in production": "Désactivez le mode debug en production",
}

KEYWORD_TRANSLATIONS = {
    "password": "mot de passe",
    "security": "sécurité",
    "vulnerability": "vulnérabilité",
    "detected": "détecté",
    "exposed": "exposé",
    "unvalidated": "non validé",
    "insecure": "non sécurisé",
    "hardcoded": "codé en dur",
    "injection": "injection",
    "traversal": "traversée",
    "redirect": "redirection",
    "authentication": "authentification",
    "authorization": "autorisation",
    "sensitive": "sensible",
    "dangerous": "dangereux",
    "deprecated": "obsolète",
    "unsafe": "non sûr",
    "missing": "manquant",
    "weak": "faible",
    "broken": "cassé",
    "invalid": "invalide",
    "untrusted": "non fiable",
    "unencrypted": "non chiffré",
    "plaintext": "texte en clair",
    "leaked": "fuite",
    "disclosed": "divulgué",
}


def translate_text(text: str, aggressive: bool = True) -> str:
    """
    Traduit un texte anglais en français.
    
    Args:
        text: Texte à traduire
        aggressive: Si True, applique toutes les traductions partielles
        
    Returns:
        Texte traduit
    """
    if not text or not isinstance(text, str):
        return text
    
    if text in SEMGREP_TRANSLATIONS:
        return SEMGREP_TRANSLATIONS[text]
    
    if text in REMEDIATION_TRANSLATIONS:
        return REMEDIATION_TRANSLATIONS[text]
    
    if text in SECURITY_TRANSLATIONS:
        return SECURITY_TRANSLATIONS[text]
    
    if aggressive:
        translated = text
        
        for en_phrase, fr_phrase in SEMGREP_TRANSLATIONS.items():
            if len(en_phrase) > 10 and en_phrase.lower() in translated.lower():
                if len(en_phrase) > len(translated) * 0.7:
                    return fr_phrase
                translated = translated.replace(en_phrase, fr_phrase)
        
        for en_word, fr_word in REMEDIATION_TRANSLATIONS.items():
            if en_word.lower() in translated.lower():
                translated = translated.replace(en_word, fr_word)
                translated = translated.replace(en_word.lower(), fr_word.lower())
        
        for en_word, fr_word in SECURITY_TRANSLATIONS.items():
            if en_word.lower() in translated.lower():
                translated = translated.replace(en_word, fr_word)
                translated = translated.replace(en_word.lower(), fr_word.lower())
        
        return translated
    
    return text


def get_contextual_remediation(issue_type: str, severity: str = "medium") -> str:
    """
    Génère une remédiation contextualisée en français.
    
    Args:
        issue_type: Type de problème (ex: 'password_validation', 'xss', 'ssrf')
        severity: Sévérité (critical, high, medium, low)
        
    Returns:
        Message de remédiation approprié en français
    """
    remediation_map = {
        'password': "Utilisez werkzeug.security.check_password_hash() ou une bibliothèque de hachage sécurisée (bcrypt, argon2)",
        'xss': "Échappez toutes les entrées utilisateur avec Jinja2 autoescaping ou utilisez textContent au lieu de innerHTML",
        'ssrf': "Validez et limitez les URLs de destination - utilisez une whitelist de domaines autorisés",
        'sql_injection': "Utilisez des requêtes paramétrées avec SQLAlchemy ou parameterized queries",
        'sql': "Utilisez des requêtes paramétrées avec SQLAlchemy ou parameterized queries",
        'command_injection': "Évitez subprocess.call() avec shell=True - utilisez une liste d'arguments sécurisée",
        'command': "Évitez subprocess.call() avec shell=True - utilisez une liste d'arguments sécurisée",
        'open_redirect': "Validez les URLs de redirection contre une whitelist ou utilisez url_for() de Flask",
        'redirect': "Validez les URLs de redirection contre une whitelist ou utilisez url_for() de Flask",
        'sensitive_data': "Supprimez les secrets du code - utilisez des variables d'environnement et un gestionnaire de secrets",
        'secret': "Supprimez les secrets du code - utilisez des variables d'environnement et un gestionnaire de secrets",
        'insecure_config': "Désactivez DEBUG=False en production et utilisez des configurations sécurisées",
        'config': "Désactivez DEBUG=False en production et utilisez des configurations sécurisées",
        'dependency': "Mettez à jour vers la dernière version stable ou appliquez les correctifs de sécurité",
        'path_traversal': "Validez et normalisez les chemins de fichiers, utilisez une whitelist de répertoires autorisés",
        'path': "Validez et normalisez les chemins de fichiers, utilisez une whitelist de répertoires autorisés",
        'deserialization': "Utilisez des formats de sérialisation sécurisés (JSON) ou des loaders sécurisés",
        'csrf': "Implémentez une protection CSRF avec des tokens",
        'authentication': "Utilisez des fonctions de hachage sécurisées (bcrypt, Argon2) et des comparaisons à temps constant",
        'hardcoded': "Utilisez des variables d'environnement ou des fichiers de configuration externes",
        'semgrep': "Appliquez les meilleures pratiques de sécurité OWASP pour ce type de vulnérabilité",
        'default': "Appliquez les meilleures pratiques de sécurité OWASP pour ce type de vulnérabilité"
    }
    
    issue_lower = issue_type.lower()
    for key in remediation_map:
        if key in issue_lower:
            return remediation_map[key]
    
    return remediation_map['default']


def translate_security_message(english_text: str) -> str:
    """
    Traduit les messages de sécurité anglais en français.
    Retourne le texte original si aucune traduction exacte n'est trouvée.
    
    Args:
        english_text: Message en anglais
        
    Returns:
        Message traduit en français ou texte original
    """
    if not english_text:
        return english_text
    
    result = translate_text(english_text, aggressive=True)
    
    if "Semgrep" in result or "documentation" in result.lower():
        return get_contextual_remediation(english_text)
    
    return result
