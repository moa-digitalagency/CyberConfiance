"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Configuration de l'internationalisation avec Flask-Babel.
"""

from flask import session, request
from flask_babel import Babel

def get_locale():
    """Get user's preferred language from session, cookie, or browser"""
    if 'language' in session:
        return session['language']
    
    return request.accept_languages.best_match(['en', 'fr']) or 'fr'

def init_babel(app):
    """Initialize Flask-Babel with the app"""
    babel = Babel(app)
    babel.init_app(app, locale_selector=get_locale)
    return babel
