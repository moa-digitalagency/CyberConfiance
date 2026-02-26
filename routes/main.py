"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier main.py du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify, send_file, make_response, send_from_directory, current_app
from flask_login import login_required
from services import ContentService
from models import Contact, User
from utils.metadata_collector import get_client_ip
from utils.logger import get_logger
import __init__ as app_module
import json
import os
from datetime import datetime
import traceback

logger = get_logger(__name__)
db = app_module.db

bp = Blueprint('main', __name__)

# Simple in-memory cache for sitemap
sitemap_cache = {
    'content': None,
    'expires_at': None
}
SITEMAP_CACHE_TIMEOUT = 3600  # 1 hour

@bp.route('/')
def index():
    latest_news = ContentService.get_latest_news(limit=2)
    resources = ContentService.get_all_resources()[:2]
    return render_template('index.html', news=latest_news, resources=resources)

@bp.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if name and email and subject and message:
            from services.prompt import PromptAnalyzerService
            from utils.metadata_collector import collect_request_metadata, generate_incident_id
            from flask import session
            
            prompt_analyzer = PromptAnalyzerService()
            combined_text = f"{name}\n{subject}\n{message}"
            analysis = prompt_analyzer.analyze_prompt(combined_text, analyze_urls=True)
            
            if analysis.get('threat_detected'):
                threat_level = analysis.get('threat_level', 'unknown')
                metadata = collect_request_metadata()
                incident_id = generate_incident_id()
                
                from models import ThreatLog
                threat_log = ThreatLog(  # type: ignore
                    incident_id=incident_id,
                    threat_type=f"contact_form_{threat_level}",
                    threat_details=f"Injection/menace detectee dans le formulaire de contact. "
                                  f"Injection: {analysis.get('injection_detected')}, "
                                  f"Code: {analysis.get('code_detected')}, "
                                  f"Obfuscation: {analysis.get('obfuscation_detected')}",
                    ip_address=metadata['ip_address'],
                    user_agent=metadata['user_agent'],
                    platform=metadata['platform'],
                    device_type=metadata['device_type'],
                    vpn_detected=metadata['vpn_detected'],
                    metadata_json=metadata
                )
                db.session.add(threat_log)
                db.session.commit()
                
                session['threat_incident_id'] = incident_id
                return redirect(url_for('request_forms.security_threat', incident_id=incident_id))
            
            ContentService.save_contact(name, email, subject, message)
            flash('Votre message a été envoyé avec succès!', 'success')
            return redirect(url_for('main.contact'))
        else:
            flash('Veuillez remplir tous les champs.', 'error')
    
    return render_template('contact.html')


@bp.route('/newsletter', methods=['POST'])
def newsletter():
    email = request.form.get('email')
    
    if not email:
        flash('Veuillez fournir une adresse email.', 'error')
        return redirect(url_for('main.index'))
    
    try:
        from models import Newsletter
        existing = Newsletter.query.filter_by(email=email).first()
        
        if existing:
            if existing.subscribed:
                flash('Vous êtes déjà inscrit à notre newsletter !', 'info')
            else:
                existing.subscribed = True
                existing.unsubscribed_at = None
                db.session.commit()
                flash('Votre inscription à la newsletter a été réactivée !', 'success')
        else:
            newsletter_entry = Newsletter(  # type: ignore
                email=email,
                ip_address=get_client_ip(request),
                user_agent=request.headers.get('User-Agent', '')[:500]
            )
            db.session.add(newsletter_entry)
            db.session.commit()
            flash('Merci pour votre inscription à notre newsletter !', 'success')
    except Exception as e:
        logger.error(f"Erreur lors de l'inscription newsletter: {str(e)}")
        db.session.rollback()
        flash('Une erreur est survenue. Veuillez réessayer.', 'error')
    
    return redirect(url_for('main.index'))


@bp.route('/set-language', methods=['POST'])
@bp.route('/set-language/<lang>')
def set_language(lang=None):
    """Set users preferred language"""
    from urllib.parse import urlparse
    
    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        lang = data.get('language', 'fr')
        
        if lang in ['en', 'fr']:
            session['language'] = lang
            session.permanent = True
            return jsonify({'success': True, 'language': lang})
        
        return jsonify({'success': False, 'error': 'Invalid language'}), 400
    
    if lang and lang in ['en', 'fr']:
        session['language'] = lang
        session.permanent = True
    
    referrer = request.referrer
    if referrer:
        referrer_host = urlparse(referrer).netloc
        current_host = request.host
        
        if referrer_host and referrer_host == current_host:
            return redirect(referrer)
    
    return redirect(url_for('main.index'))


@bp.route('/robots.txt')
def robots():
    """Generate dynamic robots.txt for search engines and AI crawlers"""
    domain = request.host_url.rstrip('/')
    
    robots_content = f"""# =============================================================================
# Robots.txt pour CyberConfiance
# Plateforme de sensibilisation a la cybersecurite
# By MOA Digital Agency LLC - www.myoneart.com
# =============================================================================

# ... (Standard Content) ...
User-agent: *
Allow: /
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /login
Disallow: /logout
Disallow: /request/
Disallow: /quiz/results/
Disallow: /generate-*
Disallow: /export-*
Crawl-delay: 1

Sitemap: {domain}/sitemap.xml
"""
    
    response = make_response(robots_content)
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    response.headers['Cache-Control'] = 'public, max-age=86400'
    return response

@bp.route('/sitemap.xml')
def sitemap():
    """Generate dynamic XML sitemap for SEO - CyberConfiance"""
    # Check cache first
    now = datetime.utcnow()
    if sitemap_cache['content'] and sitemap_cache['expires_at'] and now < sitemap_cache['expires_at']:
        response = make_response(sitemap_cache['content'])
        response.headers['Content-Type'] = 'application/xml; charset=utf-8'
        response.headers['Cache-Control'] = f'public, max-age={SITEMAP_CACHE_TIMEOUT}'
        return response

    from models import News, Rule, Tool, AttackType, Scenario, GlossaryTerm
    
    domain = request.host_url.rstrip('/')
    today = now.strftime('%Y-%m-%d')
    
    pages = []
    
    # Pages principales avec priorite elevee
    main_routes = [
        ('/', '1.0', 'daily', 'Accueil'),
        ('/apropos', '0.6', 'monthly', 'A propos'),
        ('/contact', '0.6', 'monthly', 'Contact'),
    ]
    
    # Outils d'analyse - priorite tres elevee (produits phares)
    tools_routes = [
        ('/outils/analyseur-qrcode', '1.0', 'weekly', 'Analyseur QR Code Anti-Quishing'),
        ('/outils/analyseur-prompt', '1.0', 'weekly', 'Analyseur Prompt Anti-Injection'),
        ('/outils/analyseur-liens', '0.9', 'weekly', 'Analyseur de Liens'),
        ('/outils/analyseur-securite', '0.9', 'weekly', 'Analyseur de Securite'),
        ('/outils/analyseur-fuite', '0.9', 'weekly', 'Analyseur de Fuites Email'),
        ('/outils/analyseur-github', '0.9', 'weekly', 'Analyseur GitHub Code'),
        ('/outils/analyseur-metadonnee', '0.9', 'weekly', 'Analyseur de Metadonnees'),
        ('/outils/types-attaques', '0.8', 'weekly', 'Types d Attaques'),
        ('/quiz', '0.9', 'weekly', 'Quiz Cybersecurite'),
    ]
    
    # Pages de contenu educatif
    content_routes = [
        ('/rules', '0.8', 'weekly', 'Regles de Securite'),
        ('/scenarios', '0.8', 'weekly', 'Scenarios d Attaque'),
        ('/tools', '0.8', 'weekly', 'Outils Recommandes'),
        ('/glossary', '0.7', 'weekly', 'Glossaire Cybersecurite'),
        ('/resources', '0.7', 'weekly', 'Ressources'),
        ('/news', '0.9', 'daily', 'Actualites Cybersecurite'),
    ]
    
    # Ajouter les routes principales
    for path, priority, changefreq, title in main_routes + tools_routes + content_routes:
        pages.append({
            'loc': domain + path,
            'priority': priority,
            'changefreq': changefreq,
            'lastmod': today
        })
    
    # Ajouter les actualites dynamiques
    try:
        news_items = News.query.filter_by(is_published=True).order_by(News.created_at.desc()).limit(100).all()
        for item in news_items:
            pages.append({
                'loc': f"{domain}/news/{item.id}",
                'priority': '0.7',
                'changefreq': 'monthly',
                'lastmod': item.created_at.strftime('%Y-%m-%d') if item.created_at else today
            })
    except Exception:
        pass
    
    # Ajouter les regles de securite
    try:
        rules = Rule.query.all()
        for rule in rules:
            pages.append({
                'loc': f"{domain}/rules/{rule.id}",
                'priority': '0.6',
                'changefreq': 'monthly',
                'lastmod': today
            })
    except Exception:
        pass
    
    # Ajouter les scenarios
    try:
        scenarios = Scenario.query.all()
        for scenario in scenarios:
            pages.append({
                'loc': f"{domain}/scenarios/{scenario.id}",
                'priority': '0.6',
                'changefreq': 'monthly',
                'lastmod': today
            })
    except Exception:
        pass
    
    # Ajouter les types d'attaque
    try:
        attack_types = AttackType.query.all()
        for attack in attack_types:
            pages.append({
                'loc': f"{domain}/outils/types-attaques/{attack.id}",
                'priority': '0.6',
                'changefreq': 'monthly',
                'lastmod': today
            })
    except Exception:
        pass
    
    # Generer le XML
    sitemap_xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    sitemap_xml += '<!-- Sitemap CyberConfiance - By MOA Digital Agency LLC -->\n'
    sitemap_xml += '<!-- www.myoneart.com -->\n'
    sitemap_xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n'
    sitemap_xml += '        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n'
    sitemap_xml += '        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9\n'
    sitemap_xml += '                            http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">\n'
    
    for page in pages:
        sitemap_xml += '  <url>\n'
        sitemap_xml += f'    <loc>{page["loc"]}</loc>\n'
        sitemap_xml += f'    <lastmod>{page["lastmod"]}</lastmod>\n'
        sitemap_xml += f'    <changefreq>{page["changefreq"]}</changefreq>\n'
        sitemap_xml += f'    <priority>{page["priority"]}</priority>\n'
        sitemap_xml += '  </url>\n'
    
    sitemap_xml += '</urlset>'
    
    # Update cache
    from datetime import timedelta
    sitemap_cache['content'] = sitemap_xml
    sitemap_cache['expires_at'] = now + timedelta(seconds=SITEMAP_CACHE_TIMEOUT)

    response = make_response(sitemap_xml)
    response.headers['Content-Type'] = 'application/xml; charset=utf-8'
    response.headers['Cache-Control'] = f'public, max-age={SITEMAP_CACHE_TIMEOUT}'
    return response


@bp.route('/.well-known/security.txt')
def security_txt():
    """Serve security.txt file"""
    return send_from_directory(os.path.join(current_app.root_path, 'static', '.well-known'), 'security.txt')
