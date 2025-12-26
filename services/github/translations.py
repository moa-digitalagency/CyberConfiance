"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Traductions francaises pour l'analyseur GitHub.
"""

import re

COMPLETE_TRANSLATIONS = {
    "The password on 'admin' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Mot de passe 'admin' défini sans validation",
    "The password on 'dr_kalonji' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Mot de passe 'dr_kalonji' défini sans validation",
    "The password on 'current_user' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Mot de passe utilisateur modifié sans validation",
    "The password on 'user' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Mot de passe utilisateur défini sans validation",
    
    "Running flask app with host 0.0.0.0 could expose the server publicly. This is dangerous as any computer on the network could connect. Use '127.0.0.1' instead.":
        "Serveur Flask exposé publiquement avec host=0.0.0.0",
    "Running flask app with host 0.0.0.0 could expose the server publicly.":
        "Serveur Flask exposé publiquement avec host=0.0.0.0",
    "Running flask app with host 0.0.0.0 could expose the server":
        "Serveur Flask exposé publiquement avec host=0.0.0.0",
    
    "Detected user input flowing into a manually constructed HTML string. You may be bypassing Jinja2's built-in HTML escaping. Use render_template() and templates with autoescaping enabled to prevent XSS.":
        "Injection d'entrée utilisateur dans HTML manuel - risque XSS",
    "User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` can result in XSS. Consider using `textContent` or `createTextNode` instead.":
        "Données utilisateur dans innerHTML/outerHTML - risque XSS",
    "Detected explicitly unescaped content using 'Markup()'. This bypasses HTML escaping and could lead to XSS attacks.":
        "Contenu non échappé avec Markup()",
    "Be careful with `flask.make_response()`. If this response is rendered onto a page, it could introduce XSS vulnerabilities.":
        "Réponse Flask non sécurisée - risque XSS potentiel",
    "Detected explicitly unescaped content using 'Markup()'":
        "Contenu non échappé avec Markup()",
    "This bypasses HTML escaping and could lead to XSS":
        "contourne l'échappement HTML - risque XSS",
    
    "Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF). To mitigate, ensure that schemes and hosts are validated against an allowlist.":
        "Données de requête transmises à une requête serveur - risque SSRF",
    "User data flows into the host portion of this manually-constructed URL. This could lead to SSRF vulnerabilities.":
        "Données utilisateur injectées dans URL construite - risque SSRF",
    "User data flows into the host portion of this manually-constructed URL. This could lead to SSRF.":
        "Données utilisateur injectées dans l'URL - risque SSRF",
    "Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF).":
        "Données de requête transmises à une requête serveur - risque SSRF",
    
    "Data from request is passed to redirect(). This is an open redirect and could be used to redirect users to malicious sites.":
        "Redirection ouverte détectée - risque de phishing",
    
    "Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks.":
        "Formulaire sans protection CSRF détecté",
    
    "is being set without validating the password":
        "est défini sans validation sécurisée",
    
    ". Call django.contrib.auth.models.check_password.": "",
    ". Call django.contrib.auth.models.check_password": "",
    ". Call django": "",
    ". Call werkzeug": "",
    ". This is dangerous": "",
    ". You may be bypassing": "",
    ". Consider using": "",
    ". To mitigate": "",
    ". If this response": "",
    " publicly.": "",
    " .password_valid": "",
    " .password_": "",
    " be accidentally": "",
    "`site` is an anti-patt": "",
    "Call django.contrib.auth": "",
    "Call werkzeug.security": "",
    "Consult the Semgrep documentation": "",
    "Consultez la documentation Semgrep": "",
}

CLEANUP_PHRASES = [
    "the password",
    "The password",
    "the user",
    "Call django",
    "Call werkzeug",
    "This is dangerous",
    "You may be",
    "Consider using",
    "can result in",
    "Semgrep",
    "documentation",
]


def aggressive_cleanup(text: str) -> str:
    """
    Nettoyage agressif des résidus anglais.
    
    Args:
        text: Texte à nettoyer
        
    Returns:
        Texte nettoyé
    """
    if not text:
        return text
    
    cleaned = text
    
    cleanup_patterns = [
        r'\. Ca[ln].*$',
        r'\. You.*$',
        r'\. This.*$',
        r'\. If.*$',
        r'\. To.*$',
        r'\. Consider.*$',
        r'\. Use.*$',
        r' publicly\.$',
        r' \.password_\w*',
        r' be accidentally.*$',
        r'`site` is an.*$',
    ]
    
    for pattern in cleanup_patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)
    
    cleaned = re.sub(r'\s*\.\s*\.+', '.', cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned)
    
    return cleaned.strip().rstrip('.')


def clean_text(text: str) -> str:
    """Nettoie le texte des phrases anglaises résiduelles."""
    if not text:
        return text
    
    cleaned = text
    
    for phrase in CLEANUP_PHRASES:
        if phrase in cleaned:
            idx = cleaned.find(phrase)
            if idx > 0:
                cleaned = cleaned[:idx].strip()
                cleaned = cleaned.rstrip('.,;: ')
    
    cleaned = aggressive_cleanup(cleaned)
    
    return cleaned.strip()


def translate_complete(text: str) -> str:
    """
    Traduction complète avec nettoyage agressif.
    
    Args:
        text: Texte à traduire
        
    Returns:
        Texte traduit et nettoyé
    """
    if not text or not isinstance(text, str):
        return text
    
    if text in COMPLETE_TRANSLATIONS:
        return COMPLETE_TRANSLATIONS[text]
    
    translated = text
    sorted_translations = sorted(
        COMPLETE_TRANSLATIONS.items(),
        key=lambda x: len(x[0]),
        reverse=True
    )
    
    for en_text, fr_text in sorted_translations:
        if en_text in translated:
            if fr_text == "":
                translated = translated.replace(en_text, "")
            else:
                translated = translated.replace(en_text, fr_text)
    
    translated = aggressive_cleanup(translated)
    translated = ' '.join(translated.split())
    
    return translated.strip()


def translate_text(text: str, deep_clean: bool = True) -> str:
    """Traduit un texte anglais en français avec nettoyage profond."""
    if not text or not isinstance(text, str):
        return text
    
    if text in COMPLETE_TRANSLATIONS:
        return COMPLETE_TRANSLATIONS[text]
    
    translated = text
    
    translations_sorted = sorted(
        COMPLETE_TRANSLATIONS.items(),
        key=lambda x: len(x[0]),
        reverse=True
    )
    
    for en_text, fr_text in translations_sorted:
        if en_text in translated:
            if fr_text == "":
                translated = translated.replace(en_text, "")
            else:
                translated = translated.replace(en_text, fr_text)
    
    if deep_clean:
        translated = clean_text(translated)
    
    translated = ' '.join(translated.split())
    
    return translated.strip()


def smart_remediation(title: str, category: str, severity: str) -> str:
    """
    Génère une remédiation intelligente et contextuelle.
    
    Args:
        title: Titre du problème
        category: Catégorie (security, dependencies, etc.)
        severity: Sévérité (critical, high, medium, low)
        
    Returns:
        Remédiation appropriée
    """
    title_lower = title.lower()
    
    remediation_map = {
        'password': "Utilisez werkzeug.security.generate_password_hash() pour stocker et check_password_hash() pour valider",
        'mot de passe': "Utilisez werkzeug.security.generate_password_hash() pour stocker et check_password_hash() pour valider",
        
        'flask': "En développement utilisez host='127.0.0.1', en production utilisez un reverse proxy (nginx/Apache)",
        'host': "En développement utilisez host='127.0.0.1', en production utilisez un reverse proxy (nginx/Apache)",
        '0.0.0.0': "En développement utilisez host='127.0.0.1', en production utilisez un reverse proxy (nginx/Apache)",
        
        'xss': "Utilisez Jinja2 avec autoescaping ou textContent au lieu de innerHTML/outerHTML",
        'innerhtml': "Utilisez textContent ou createTextNode au lieu de innerHTML/outerHTML",
        'outerhtml': "Utilisez textContent ou createTextNode au lieu de innerHTML/outerHTML",
        'markup()': "Activez l'auto-escaping Jinja2 et évitez Markup() sauf si nécessaire",
        'html manuel': "Utilisez des templates Jinja2 avec autoescaping activé",
        
        'ssrf': "Validez les URLs avec une whitelist de domaines autorisés - bloquez les IPs privées",
        'requête serveur': "Validez les URLs avec une whitelist de domaines autorisés",
        'server-side request': "Validez les URLs avec une whitelist de domaines autorisés",
        
        'redirect': "Validez les URLs de redirection contre une whitelist ou utilisez url_for() de Flask",
        'redirection': "Validez les URLs de redirection contre une whitelist ou utilisez url_for() de Flask",
        
        'csrf': "Ajoutez {{ csrf_token() }} dans vos formulaires ou utilisez Flask-WTF",
        'formulaire': "Ajoutez une protection CSRF avec {{ csrf_token() }} ou Flask-WTF",
        
        'sql': "Utilisez des requêtes paramétrées avec SQLAlchemy ou des prepared statements",
        'injection': "Validez et échappez toutes les entrées utilisateur avant utilisation",
        
        'dépendance': "Mettez à jour vers la dernière version stable ou appliquez les patches de sécurité",
        'vulnerable': "Mettez à jour vers une version non vulnérable de cette dépendance",
        'vulnérable': "Mettez à jour vers une version non vulnérable de cette dépendance",
        
        'test': "Ajoutez des tests unitaires et d'intégration avec pytest ou unittest",
        'ci/cd': "Ajoutez une pipeline CI/CD avec GitHub Actions ou GitLab CI",
        
        '.env': "Ajoutez .env à .gitignore pour protéger les secrets",
        'readme': "Ajoutez une documentation complète avec installation, usage et examples",
        
        'secret': "Utilisez des variables d'environnement pour stocker les secrets",
        'credential': "Utilisez des variables d'environnement pour stocker les credentials",
        'api key': "Utilisez des variables d'environnement pour stocker les clés API",
        'token': "Utilisez des variables d'environnement pour stocker les tokens",
        
        'command': "Évitez shell=True et utilisez une liste d'arguments sécurisée",
        'shell': "Évitez shell=True et utilisez une liste d'arguments sécurisée",
        'subprocess': "Évitez shell=True et utilisez une liste d'arguments sécurisée",
        
        'path': "Validez et normalisez les chemins de fichiers avec os.path.abspath()",
        'traversal': "Validez et normalisez les chemins de fichiers avec os.path.abspath()",
        'directory': "Validez et normalisez les chemins de fichiers avec os.path.abspath()",
    }
    
    for keyword, remediation in remediation_map.items():
        if keyword in title_lower:
            return remediation
    
    if severity == 'critical':
        return "URGENT - Correction immédiate requise - vulnérabilité critique exploitable"
    elif severity == 'high':
        return "Correction prioritaire - risque de sécurité élevé à traiter rapidement"
    elif severity == 'medium':
        return "Correction recommandée - améliorer la sécurité et la qualité du code"
    else:
        return "Amélioration suggérée - bonnes pratiques de développement sécurisé"


def get_smart_remediation(finding_title: str, severity: str = "medium", file_path: str = "") -> str:
    """Génère une remédiation intelligente basée sur le contexte."""
    return smart_remediation(finding_title, "security", severity)


def get_contextual_remediation(issue_type: str, severity: str = "medium") -> str:
    """Alias pour compatibilité."""
    return smart_remediation(issue_type, "security", severity)


def translate_security_message(english_text: str) -> str:
    """Traduit les messages de sécurité anglais en français."""
    if not english_text:
        return english_text
    return translate_text(english_text, deep_clean=True)
