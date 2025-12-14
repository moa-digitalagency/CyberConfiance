"""
Traductions françaises COMPLÈTES pour l'analyseur GitHub CyberConfiance.
Version finale optimisée.
"""
import re

FULL_SEMGREP_TRANSLATIONS = {
    "The password on 'admin' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Mot de passe admin défini sans validation sécurisée",
    
    "The password on 'dr_kalonji' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Mot de passe dr_kalonji défini sans validation sécurisée",
    
    "The password on 'current_user' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Mot de passe utilisateur modifié sans validation",
    
    "The password on 'user' is being set without validating the password. Call django.contrib.auth.models.check_password.":
        "Mot de passe utilisateur défini sans validation",
    
    "is being set without validating the password":
        "est défini sans validation sécurisée",
    
    "Call django.contrib.auth.models.check_password":
        "",
    
    "Running flask app with host 0.0.0.0 could expose the server publicly. This is dangerous as any computer on the network could connect. Use '127.0.0.1' instead.":
        "Serveur Flask exposé publiquement avec host=0.0.0.0 - utilisez 127.0.0.1 en développement",
    
    "Running flask app with host 0.0.0.0 could expose the server":
        "Serveur Flask exposé publiquement avec host=0.0.0.0",
    
    "Detected user input flowing into a manually constructed HTML string. You may be bypassing Jinja2's built-in HTML escaping. Use render_template() and templates with autoescaping enabled to prevent XSS.":
        "Injection d'entrée utilisateur dans HTML manuel - contournement échappement Jinja2 - risque XSS critique",
    
    "Detected user input flowing into a manually constructed HTML string. You may":
        "Injection d'entrée utilisateur dans HTML manuel - risque XSS",
    
    "User controlled data in methods like `innerHTML`, `outerHTML` or `document.write` can result in XSS. Consider using `textContent` or `createTextNode` instead.":
        "Données utilisateur dans innerHTML/outerHTML/document.write - risque XSS - utilisez textContent",
    
    "User controlled data in methods like `innerHTML`, `outerHTML` or `document.wr":
        "Données utilisateur dans innerHTML/outerHTML - risque XSS",
    
    "Detected explicitly unescaped content using 'Markup()'":
        "Contenu non échappé avec Markup()",
    
    "This bypasses HTML escaping and could lead to XSS":
        "contourne l'échappement HTML - risque XSS",
    
    "Data from request object is passed to a new server-side request. This could lead to a server-side request forgery (SSRF).":
        "Données de requête transmises à une requête serveur - risque SSRF",
    
    "User data flows into the host portion of this manually-constructed URL. This could lead to SSRF.":
        "Données utilisateur injectées dans l'URL - risque SSRF",
    
    "Data from request is passed to redirect(). This is an open redirect and could be used to redirect users to malicious sites.":
        "Redirection ouverte détectée - risque de phishing",
    
    ". Call django": "",
    ". Call werkzeug": "",
    ". This is dangerous": "",
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
    
    cleaned = re.sub(r'\. Ca.*$', '', cleaned)
    cleaned = re.sub(r'\. You.*$', '', cleaned)
    cleaned = re.sub(r'\. This.*$', '', cleaned)
    cleaned = re.sub(r'\. Use.*$', '', cleaned)
    
    return cleaned.strip()


def translate_text(text: str, deep_clean: bool = True) -> str:
    """Traduit un texte anglais en français avec nettoyage profond."""
    if not text or not isinstance(text, str):
        return text
    
    if text in FULL_SEMGREP_TRANSLATIONS:
        return FULL_SEMGREP_TRANSLATIONS[text]
    
    translated = text
    
    translations_sorted = sorted(
        FULL_SEMGREP_TRANSLATIONS.items(),
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


def get_smart_remediation(finding_title: str, severity: str = "medium", file_path: str = "") -> str:
    """Génère une remédiation intelligente basée sur le contexte."""
    title_lower = finding_title.lower()
    
    if any(word in title_lower for word in ['password', 'mot de passe']):
        return "Utilisez werkzeug.security.generate_password_hash() pour le stockage et check_password_hash() pour la validation"
    
    if any(word in title_lower for word in ['flask', 'host', '0.0.0.0']):
        return "En développement utilisez host='127.0.0.1', en production utilisez un reverse proxy (nginx/Apache)"
    
    if any(word in title_lower for word in ['xss', 'innerhtml', 'outerhtml', 'html string', 'markup']):
        return "Utilisez Jinja2 avec autoescaping activé ou textContent/createTextNode au lieu de innerHTML"
    
    if any(word in title_lower for word in ['ssrf', 'server-side request']):
        return "Validez les URLs avec une whitelist de domaines autorisés et bloquez les IPs privées"
    
    if any(word in title_lower for word in ['sql', 'injection']):
        return "Utilisez des requêtes paramétrées avec SQLAlchemy ou des prepared statements"
    
    if any(word in title_lower for word in ['redirect', 'redirection']):
        return "Validez les URLs de redirection contre une whitelist ou utilisez url_for() de Flask"
    
    if any(word in title_lower for word in ['secret', 'credential', 'api key', 'token']):
        return "Utilisez des variables d'environnement pour stocker les secrets"
    
    if any(word in title_lower for word in ['command', 'shell', 'subprocess']):
        return "Évitez shell=True et utilisez une liste d'arguments sécurisée"
    
    if any(word in title_lower for word in ['path', 'traversal', 'directory']):
        return "Validez et normalisez les chemins de fichiers avec os.path.abspath()"
    
    if any(word in title_lower for word in ['csrf']):
        return "Implémentez une protection CSRF avec des tokens"
    
    if severity == 'critical':
        return "Correction urgente requise - vulnérabilité critique exploitable"
    elif severity == 'high':
        return "Correction prioritaire - risque de sécurité élevé"
    elif severity == 'medium':
        return "Correction recommandée - améliorer la sécurité du code"
    else:
        return "Amélioration suggérée pour les meilleures pratiques de sécurité"


def get_contextual_remediation(issue_type: str, severity: str = "medium") -> str:
    """Alias pour compatibilité."""
    return get_smart_remediation(issue_type, severity)


def translate_security_message(english_text: str) -> str:
    """Traduit les messages de sécurité anglais en français."""
    if not english_text:
        return english_text
    return translate_text(english_text, deep_clean=True)
