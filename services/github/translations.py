SECURITY_TRANSLATIONS = {
    "The password on 'admin' is being set without validating": 
        "Le mot de passe 'admin' est defini sans validation",
    
    "Running flask app with host 0.0.0.0 could expose the server": 
        "Lancer Flask avec host 0.0.0.0 expose le serveur publiquement",
    
    "Detected explicitly unescaped content using 'Markup()'": 
        "Contenu non echappe detecte avec Markup() - risque XSS",
    
    "Data from request object is passed to a new server-side request": 
        "Donnees de requete transmises a une requete serveur - risque SSRF",
    
    "User data flows into the host portion of this manually-constructed": 
        "Donnees utilisateur injectees dans l'hote de l'URL - risque SSRF",
    
    "Data from request is passed to redirect()": 
        "Donnees de requete passees a redirect() - risque Open Redirect",
    
    "This is an open redirect": 
        "Redirection ouverte detectee",
    
    "Consult the Semgrep documentation": 
        "Consultez la documentation Semgrep",
    
    "Hardcoded password": 
        "Mot de passe code en dur",
    
    "SQL injection": 
        "Injection SQL",
    
    "Cross-site scripting": 
        "Faille XSS (Cross-site scripting)",
    
    "Command injection": 
        "Injection de commandes",
    
    "Path traversal": 
        "Traversee de chemin",
    
    "Insecure deserialization": 
        "Deserialisation non securisee",
    
    "Server-side request forgery": 
        "Falsification de requete cote serveur (SSRF)",
    
    "Unvalidated redirect": 
        "Redirection non validee",
    
    "Debug mode enabled": 
        "Mode debug active",
    
    "Weak cryptography": 
        "Cryptographie faible",
    
    "Insecure random": 
        "Generateur aleatoire non securise",
    
    "Hardcoded secret": 
        "Secret code en dur",
    
    "Missing authentication": 
        "Authentification manquante",
    
    "Insufficient logging": 
        "Journalisation insuffisante",
    
    "Exposed sensitive data": 
        "Donnees sensibles exposees",
    
    "Insecure cookie": 
        "Cookie non securise",
    
    "Missing CSRF protection": 
        "Protection CSRF manquante",
    
    "Insecure SSL/TLS": 
        "SSL/TLS non securise",
    
    "Dangerous function": 
        "Fonction dangereuse",
    
    "Eval injection": 
        "Injection via eval()",
    
    "Use parameterized queries": 
        "Utilisez des requetes parametrees",
    
    "Use a secure random number generator": 
        "Utilisez un generateur aleatoire securise",
    
    "Enable HTTPS": 
        "Activez HTTPS",
    
    "Validate user input": 
        "Validez les entrees utilisateur",
    
    "Use environment variables": 
        "Utilisez des variables d'environnement",
    
    "Enable CSRF protection": 
        "Activez la protection CSRF",
    
    "Use secure cookies": 
        "Utilisez des cookies securises",
    
    "Disable debug mode in production": 
        "Desactivez le mode debug en production",
}

KEYWORD_TRANSLATIONS = {
    "password": "mot de passe",
    "security": "securite",
    "vulnerability": "vulnerabilite",
    "detected": "detecte",
    "exposed": "expose",
    "unvalidated": "non valide",
    "insecure": "non securise",
    "hardcoded": "code en dur",
    "injection": "injection",
    "traversal": "traversee",
    "redirect": "redirection",
    "authentication": "authentification",
    "authorization": "autorisation",
    "sensitive": "sensible",
    "dangerous": "dangereux",
    "deprecated": "obsolete",
    "unsafe": "non sur",
    "missing": "manquant",
    "weak": "faible",
    "broken": "casse",
    "invalid": "invalide",
    "untrusted": "non fiable",
    "unencrypted": "non chiffre",
    "plaintext": "texte en clair",
    "leaked": "fuite",
    "disclosed": "divulgue",
}

def translate_security_message(english_text: str) -> str:
    """
    Traduit les messages de securite anglais en francais.
    Retourne le texte original si aucune traduction exacte n'est trouvee.
    
    Args:
        english_text: Message en anglais
        
    Returns:
        Message traduit en francais ou texte original
    """
    if not english_text:
        return english_text
    
    if english_text in SECURITY_TRANSLATIONS:
        return SECURITY_TRANSLATIONS[english_text]
    
    english_lower = english_text.lower().strip()
    for en_key, fr_value in SECURITY_TRANSLATIONS.items():
        if en_key.lower() == english_lower:
            return fr_value
    
    for en_key, fr_value in SECURITY_TRANSLATIONS.items():
        if len(en_key) > 20 and en_key.lower() in english_lower:
            return fr_value
    
    return english_text
