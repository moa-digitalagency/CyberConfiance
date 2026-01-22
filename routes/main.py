"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Routes principales: page d'accueil, contact, analyseurs, quiz.
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, session, jsonify, send_file, make_response
from flask_login import login_required
from services import ContentService, HaveIBeenPwnedService, QuizService
from services.security import SecurityAnalyzerService
from services.pdf import PDFReportService
from services.qrcode import QRCodeAnalyzerService
from services.prompt import PromptAnalyzerService
from services.github.analyzer import GitHubCodeAnalyzerService
from models import Contact, User, BreachAnalysis, SecurityAnalysis, QRCodeAnalysis, PromptAnalysis, GitHubCodeAnalysis
from utils.document_code_generator import ensure_unique_code
from utils.metadata_collector import get_client_ip
import __init__ as app_module
import json
import os
import requests
import io
from datetime import datetime
db = app_module.db

bp = Blueprint('main', __name__)

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

@bp.route('/outils/types-attaques')
def attack_types():
    all_attacks = ContentService.get_all_attack_types()
    return render_template('outils/attack_types.html', attacks=all_attacks)

@bp.route('/outils/analyseur-liens', methods=['GET', 'POST'])
def link_analyzer():
    analyzed_url = None
    redirects = None
    final_url = None
    redirect_count = 0
    
    if request.method == 'POST':
        url = request.form.get('url')
        
        if not url:
            flash('Veuillez fournir une URL à analyser.', 'error')
            return redirect(url_for('main.link_analyzer'))
        
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url
        
        from urllib.parse import urlparse
        import ipaddress
        import socket
        
        def is_safe_url(check_url):
            try:
                parsed = urlparse(check_url)
                if parsed.scheme not in ['http', 'https']:
                    return False
                
                if parsed.username or parsed.password:
                    return False
                
                hostname = parsed.hostname
                if not hostname:
                    return False
                
                if hostname.lower() in ['localhost', '127.0.0.1', '0.0.0.0', '::1', '0:0:0:0:0:0:0:1']:
                    return False
                
                if hostname == '169.254.169.254':
                    return False
                
                if hostname.startswith('169.254.'):
                    return False
                
                if hostname.endswith('.local') or hostname.endswith('.internal'):
                    return False
                
                if not hostname.replace('-', '').replace('.', '').replace('_', '').isalnum():
                    return False
                
                try:
                    addr_info = socket.getaddrinfo(hostname, None)
                    for info in addr_info:
                        resolved_ip_str = info[4][0]
                        if '%' in resolved_ip_str:
                            resolved_ip_str = resolved_ip_str.split('%')[0]
                        
                        ip = ipaddress.ip_address(resolved_ip_str)
                        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                            return False
                except (socket.gaierror, ValueError, OSError):
                    return False
                
                return True
            except Exception:
                return False
        
        if not is_safe_url(url):
            flash('Cette URL n\'est pas autorisée pour des raisons de sécurité.', 'error')
            return redirect(url_for('main.link_analyzer'))
        
        try:
            analyzed_url = url
            redirects = []
            current_url = url
            max_redirects = 10
            redirect_count = 0
            
            while redirect_count < max_redirects:
                if not is_safe_url(current_url):
                    redirects.append({
                        'url': current_url,
                        'error': 'URL bloquée pour des raisons de sécurité'
                    })
                    break
                
                try:
                    response = requests.get(current_url, allow_redirects=False, timeout=10, headers={'User-Agent': 'CyberConfiance-Link-Analyzer'})
                    
                    redirects.append({
                        'url': current_url,
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    })
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        next_url = response.headers.get('Location')
                        if not next_url:
                            break
                        
                        if not next_url.startswith('http'):
                            from urllib.parse import urljoin
                            next_url = urljoin(current_url, next_url)
                        
                        current_url = next_url
                        redirect_count += 1
                    else:
                        break
                        
                except requests.exceptions.RequestException as e:
                    redirects.append({
                        'url': current_url,
                        'error': str(e)
                    })
                    break
            
            final_url = current_url
                                 
        except Exception as e:
            flash(f'Erreur lors de l\'analyse: {str(e)}', 'error')
            return redirect(url_for('main.link_analyzer'))
    
    return render_template('outils/link_analyzer.html',
                         analyzed_url=analyzed_url,
                         redirects=redirects,
                         final_url=final_url,
                         redirect_count=redirect_count)

@bp.route('/outils/analyseur-securite', methods=['GET', 'POST'])
def security_analyzer():
    results = None
    analysis_id = None
    
    if request.method == 'POST':
        try:
            input_value = request.form.get('input_value', '').strip()
            input_type = request.form.get('input_type', 'hash')
            uploaded_file = request.files.get('file')
            
            if uploaded_file and uploaded_file.filename:
                input_type = 'file'
            
            if not input_value and not uploaded_file:
                flash('Veuillez fournir une valeur à analyser.', 'error')
                return redirect(url_for('main.security_analyzer'))
            
            if input_value or uploaded_file:
                analyzer = SecurityAnalyzerService()
                if input_type == 'file' and uploaded_file:
                    from services.file_upload_service import FileUploadService
                    upload_result = FileUploadService.process_upload(uploaded_file)
                    if upload_result.get('success'):
                        results = upload_result.get('scan_result', {})
                        input_value = f"{uploaded_file.filename} (Hash: {upload_result.get('file_hash', 'N/A')[:16]}...)"
                        temp_path = upload_result.get('temp_path')
                        if temp_path and os.path.exists(temp_path):
                            os.remove(temp_path)
                    else:
                        results = {'error': True, 'message': upload_result.get('error', 'Upload failed')}
                        input_value = uploaded_file.filename
                else:
                    results = analyzer.analyze(input_value, input_type)
                
                try:
                    import json
                    sanitized_results = json.loads(json.dumps(results, default=str))
                    
                    analysis_record = SecurityAnalysis(  # type: ignore
                        input_value=input_value,
                        input_type=input_type,
                        analysis_results=sanitized_results,
                        threat_detected=results.get('threat_detected', False),
                        threat_level=results.get('threat_level'),
                        malicious_count=results.get('malicious', 0),
                        total_engines=results.get('total', 0),
                        document_code=ensure_unique_code(SecurityAnalysis),
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get('User-Agent', '')
                    )
                    db.session.add(analysis_record)
                    db.session.commit()
                    analysis_id = analysis_record.id
                except Exception as e:
                    print(f"[ERROR] Error saving security analysis: {str(e)}")
                    db.session.rollback()
        except Exception as e:
            print(f"[ERROR] Critical error in security_analyzer: {str(e)}")
            db.session.rollback()
    
    return render_template('outils/security_analyzer.html', 
                         results=results, 
                         analysis_id=analysis_id)

@bp.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if request.method == 'POST':
        answers = {}
        quiz_data = QuizService.load_quiz_data()
        
        for question in quiz_data['questions']:
            question_id = str(question['id'])
            answer = request.form.get(f'question_{question_id}')
            if answer:
                answers[question_id] = answer
        
        scores = QuizService.calculate_scores(answers)
        
        session['quiz_data'] = {
            'scores': scores,
            'answers': answers,
            'overall_score': scores['overall_score']
        }
        
        return render_template('outils/quiz_email.html')
    
    quiz_data = QuizService.load_quiz_data()
    return render_template('outils/quiz.html', quiz_data=quiz_data)

@bp.route('/quiz/submit-email', methods=['POST'])
def quiz_submit_email():
    email = request.form.get('email')
    
    if not email:
        flash('Veuillez fournir une adresse email.', 'error')
        return redirect(url_for('main.quiz'))
    
    quiz_data = session.get('quiz_data', {})
    if not quiz_data:
        flash('Session expirée. Veuillez reprendre le quiz.', 'error')
        return redirect(url_for('main.quiz'))
    
    scores = quiz_data.get('scores', {})
    overall_score = quiz_data.get('overall_score', 50)
    answers = quiz_data.get('answers', {})
    
    hibp_result = HaveIBeenPwnedService.check_email_breach(email)
    
    hibp_summary = {
        'breach_count': hibp_result.get('count', 0),
        'breaches': [],
        'error': hibp_result.get('error')
    }
    
    if not hibp_result.get('error') and hibp_result.get('breaches'):
        for breach in hibp_result.get('breaches', [])[:10]:
            hibp_summary['breaches'].append({
                'name': breach.get('Name', 'Inconnu'),
                'date': breach.get('BreachDate', ''),
                'data_classes': breach.get('DataClasses', []),
                'pwn_count': breach.get('PwnCount', 0)
            })
    
    try:
        from models import QuizResult
        quiz_result = QuizResult(  # type: ignore
            email=email,
            overall_score=overall_score,
            category_scores=scores,
            answers=answers,
            hibp_summary=hibp_summary,
            document_code=ensure_unique_code(QuizResult),
            ip_address=get_client_ip(request),
            user_agent=request.headers.get('User-Agent', '')[:500]
        )
        db.session.add(quiz_result)
        db.session.commit()
        
        session.pop('quiz_data', None)
        
        return redirect(url_for('main.quiz_result_detail', result_id=quiz_result.id))
    except Exception as e:
        print(f"Erreur lors de l'enregistrement du résultat: {str(e)}")
        db.session.rollback()
        flash('Une erreur est survenue lors de l\'enregistrement de vos résultats.', 'error')
        return redirect(url_for('main.quiz'))

@bp.route('/quiz/results/<int:result_id>')
def quiz_result_detail(result_id):
    from models import QuizResult
    print(f"[DEBUG] Loading QuizResult ID={result_id}")
    quiz_result = QuizResult.query.get_or_404(result_id)
    print(f"[OK] QuizResult loaded: email={quiz_result.email}")
    
    recommendations = QuizService.get_recommendations(
        quiz_result.overall_score,
        quiz_result.answers
    )
    
    hibp_recommendations = HaveIBeenPwnedService.get_breach_recommendations(
        quiz_result.hibp_summary.get('breach_count', 0) if quiz_result.hibp_summary else 0
    )
    
    data_scenarios = HaveIBeenPwnedService.get_data_breach_scenarios()
    
    return render_template('outils/quiz_results.html',
                         quiz_result=quiz_result,
                         scores=quiz_result.category_scores,
                         recommendations=recommendations,
                         email=quiz_result.email,
                         result_id=quiz_result.id,
                         hibp_result=quiz_result.hibp_summary,
                         hibp_recommendations=hibp_recommendations,
                         data_scenarios=data_scenarios)

@bp.route('/quiz/all-results')
def quiz_all_results():
    from models import QuizResult
    all_results = QuizResult.query.order_by(QuizResult.created_at.desc()).all()
    return render_template('outils/quiz_all_results.html', results=all_results)

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
        print(f"Erreur lors de l'inscription newsletter: {str(e)}")
        db.session.rollback()
        flash('Une erreur est survenue. Veuillez réessayer.', 'error')
    
    return redirect(url_for('main.index'))

@bp.route('/analyze-breach', methods=['POST'])
def analyze_breach():
    try:
        email = request.form.get('email')
        
        if not email:
            flash('Veuillez fournir une adresse email.', 'error')
            return redirect(url_for('main.index'))
        
        result = HaveIBeenPwnedService.check_email_breach(email)
        
        if result.get('error'):
            print(f"[!] Analyse de fuite échouée pour {email}: {result['error']}")
            
            recommendations = {
                'level': 'error',
                'title': 'Service temporairement indisponible',
                'message': result['error'],
                'recommendations': [
                    'Le service d\'analyse de fuites de données est actuellement indisponible.',
                    'Veuillez contacter l\'administrateur du site si le problème persiste.',
                    'En attendant, nous vous recommandons d\'utiliser des mots de passe forts et uniques pour chaque service.',
                    'Activez l\'authentification à deux facteurs (2FA) sur tous vos comptes importants.'
                ]
            }
            data_scenarios = HaveIBeenPwnedService.get_data_breach_scenarios()
            return render_template('breach_analysis.html', 
                                 email=email,
                                 result={'breaches': [], 'count': 0, 'error': result['error']}, 
                                 recommendations=recommendations,
                                 data_scenarios=data_scenarios,
                                 analysis_id=None)
        
        recommendations = HaveIBeenPwnedService.get_breach_recommendations(result['count'])
        data_scenarios = HaveIBeenPwnedService.get_data_breach_scenarios()
        
        analysis_id = None
        try:
            breach_names = [breach.get('Name', 'Inconnu') for breach in result.get('breaches', [])]
            
            breaches_data_sanitized = {
                'breaches': result.get('breaches', []),
                'count': result.get('count', 0),
                'email': email
            }
            
            analysis = BreachAnalysis(  # type: ignore
                email=email,
                breach_count=result.get('count', 0),
                risk_level=recommendations.get('level', 'unknown'),
                breaches_found=','.join(breach_names),
                breaches_data=breaches_data_sanitized,
                document_code=ensure_unique_code(BreachAnalysis),
                ip_address=get_client_ip(request),
                user_agent=request.headers.get('User-Agent', '')[:500]
            )
            db.session.add(analysis)
            db.session.commit()
            analysis_id = analysis.id
            print(f"[OK] Analyse enregistrée: {email} - {result.get('count', 0)} breach(es) - ID: {analysis_id}")
        except Exception as e:
            print(f"[!] Erreur lors de l'enregistrement de l'analyse: {str(e)}")
            db.session.rollback()
        
        return render_template('breach_analysis.html', 
                             email=email,
                             result=result, 
                             recommendations=recommendations,
                             data_scenarios=data_scenarios,
                             analysis_id=analysis_id)
    except Exception as e:
        print(f"[ERROR] Critical error in analyze_breach: {str(e)}")
        db.session.rollback()
        flash('Erreur critique lors de l\'analyse. Veuillez réessayer.', 'error')
        return redirect(url_for('main.index'))

@bp.route('/set-language', methods=['POST'])
@bp.route('/set-language/<lang>')
def set_language(lang=None):
    """Set user's preferred language"""
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


@bp.route("/generate-breach-pdf/<int:analysis_id>")
def generate_breach_pdf(analysis_id):
    """Generate and download breach analysis PDF"""
    breach = BreachAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()  # type: ignore
    
    if breach.pdf_report and breach.pdf_generated_at:
        pdf_bytes = breach.pdf_report
    else:
        pdf_service = PDFReportService()
        breach_result = breach.breaches_data or {"breaches": [], "count": breach.breach_count}
        pdf_bytes = pdf_service.generate_breach_report(breach, breach_result, user_ip)
        
        breach.pdf_report = pdf_bytes
        breach.pdf_generated_at = datetime.utcnow()
        db.session.commit()
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"rapport_fuite_{breach.email}_{breach.id}.pdf"
    )

@bp.route("/generate-security-pdf/<int:analysis_id>")
def generate_security_pdf(analysis_id):
    """Generate and download security analysis PDF"""
    analysis = SecurityAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()  # type: ignore
    
    if analysis.pdf_report and analysis.pdf_generated_at:
        pdf_bytes = analysis.pdf_report
    else:
        pdf_service = PDFReportService()
        breach_analysis = analysis.breach_analysis if analysis.breach_analysis_id else None
        pdf_bytes = pdf_service.generate_security_analysis_report(analysis, breach_analysis, user_ip)
        
        analysis.pdf_report = pdf_bytes
        analysis.pdf_generated_at = datetime.utcnow()
        db.session.commit()
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"rapport_securite_{analysis.input_type}_{analysis.id}.pdf"
    )

@bp.route("/generate-quiz-pdf/<int:result_id>")
def generate_quiz_pdf(result_id):
    """Generate and download quiz results PDF"""
    from models import QuizResult
    from services.quiz import QuizService
    quiz_result = QuizResult.query.get_or_404(result_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()  # type: ignore
    
    if quiz_result.pdf_report and quiz_result.pdf_generated_at:
        pdf_bytes = quiz_result.pdf_report
    else:
        answers = quiz_result.answers
        recommendations = QuizService.get_recommendations(quiz_result.overall_score, answers)
        
        pdf_service = PDFReportService()
        pdf_bytes = pdf_service.generate_quiz_report(quiz_result, recommendations, user_ip)
        
        quiz_result.pdf_report = pdf_bytes
        quiz_result.pdf_generated_at = datetime.utcnow()
        db.session.commit()
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"rapport_quiz_{quiz_result.email}_{quiz_result.id}.pdf"
    )

@bp.route("/export-breach-pdf/<int:breach_id>")
def export_breach_pdf(breach_id):
    """Export breach analysis as PDF (legacy route)"""
    from services.pdf import PDFReportService
    from models import BreachAnalysis
    
    breach = BreachAnalysis.query.get_or_404(breach_id)
    
    if breach.pdf_report and breach.pdf_generated_at:
        pdf_bytes = breach.pdf_report
    else:
        pdf_service = PDFReportService()
        breach_result = breach.breaches_data or {"breaches": [], "count": breach.breach_count}
        pdf_bytes = pdf_service.generate_breach_report(breach, breach_result, get_client_ip(request))
        
        breach.pdf_report = pdf_bytes
        breach.pdf_generated_at = datetime.utcnow()
        db.session.commit()
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"rapport_fuite_{breach.email}_{breach.id}.pdf"
    )

@bp.route("/export-security-pdf/<int:analysis_id>")
def export_security_pdf(analysis_id):
    """Export security analysis as PDF"""
    from services.pdf import PDFReportService
    from models import SecurityAnalysis, BreachAnalysis
    
    analysis = SecurityAnalysis.query.get_or_404(analysis_id)
    
    if analysis.pdf_report and analysis.pdf_generated_at:
        pdf_bytes = analysis.pdf_report
    else:
        pdf_service = PDFReportService()
        breach = BreachAnalysis.query.get(analysis.breach_analysis_id) if analysis.breach_analysis_id else None
        pdf_bytes = pdf_service.generate_security_analysis_report(analysis, breach, get_client_ip(request))
        
        analysis.pdf_report = pdf_bytes
        analysis.pdf_generated_at = datetime.utcnow()
        db.session.commit()
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"rapport_securite_{analysis.input_type}_{analysis.id}.pdf"
    )

@bp.route('/robots.txt')
def robots():
    """Generate dynamic robots.txt for search engines and AI crawlers"""
    domain = request.host_url.rstrip('/')
    
    robots_content = f"""# =============================================================================
# Robots.txt pour CyberConfiance
# Plateforme de sensibilisation a la cybersecurite
# By MOA Digital Agency LLC - www.myoneart.com
# =============================================================================

# -----------------------------------------------------------------------------
# MOTEURS DE RECHERCHE STANDARDS (Google, Bing, Yahoo, DuckDuckGo, etc.)
# -----------------------------------------------------------------------------
User-agent: *

# Pages publiques - AUTORISEES
Allow: /
Allow: /static/
Allow: /outils/
Allow: /outils/analyseur-qrcode
Allow: /outils/analyseur-prompt
Allow: /outils/analyseur-liens
Allow: /outils/analyseur-securite
Allow: /outils/analyseur-fuite
Allow: /outils/analyseur-github
Allow: /outils/analyseur-metadonnee
Allow: /outils/types-attaques
Allow: /ressources/
Allow: /rules/
Allow: /scenarios/
Allow: /glossary/
Allow: /tools/
Allow: /news/
Allow: /apropos
Allow: /contact
Allow: /quiz

# Pages administratives - BLOCAGE COMPLET
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /login
Disallow: /logout

# Formulaires de soumission - BLOCAGE (protection des donnees utilisateurs)
Disallow: /request/
Disallow: /submit
Disallow: /newsletter/

# Resultats d'analyse prives - BLOCAGE
Disallow: /quiz/results/
Disallow: /quiz/all-results
Disallow: /generate-*
Disallow: /export-*

# APIs et endpoints internes
Disallow: /api/
Disallow: /_/
Disallow: /analyze-breach

# Fichiers sensibles
Disallow: /*.json$
Disallow: /*.sql$
Disallow: /*.db$
Disallow: /*.env$
Disallow: /*.log$

# Parametres de recherche (eviter duplication)
Disallow: /*?*

# Crawl-delay pour eviter surcharge serveur
Crawl-delay: 1

# -----------------------------------------------------------------------------
# BOTS IA - AUTORISES (contenu educatif cybersecurite)
# -----------------------------------------------------------------------------

# OpenAI (ChatGPT, GPT-4)
User-agent: GPTBot
Allow: /
Allow: /outils/
Allow: /ressources/
Allow: /rules/
Allow: /scenarios/
Allow: /glossary/
Allow: /news/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Disallow: /quiz/results/
Disallow: /generate-*
Disallow: /export-*
Crawl-delay: 2

User-agent: ChatGPT-User
Allow: /
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Disallow: /quiz/results/

# Anthropic (Claude)
User-agent: anthropic-ai
User-agent: Claude-Web
User-agent: ClaudeBot
Allow: /
Allow: /outils/
Allow: /ressources/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Disallow: /quiz/results/
Crawl-delay: 2

# Google AI (Bard, Gemini)
User-agent: Google-Extended
Allow: /
Allow: /outils/
Allow: /ressources/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Disallow: /quiz/results/
Crawl-delay: 2

# Perplexity AI
User-agent: PerplexityBot
Allow: /
Allow: /outils/
Allow: /ressources/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Disallow: /quiz/results/
Crawl-delay: 2

# Cohere AI
User-agent: cohere-ai
Allow: /
Allow: /outils/
Allow: /ressources/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Crawl-delay: 2

# Meta AI
User-agent: FacebookBot
User-agent: meta-externalagent
Allow: /
Allow: /outils/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Disallow: /quiz/results/
Crawl-delay: 2

# Microsoft Copilot / Bing AI
User-agent: Bingbot
Allow: /
Allow: /outils/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Crawl-delay: 1

# Common Crawl (utilise par plusieurs IA)
User-agent: CCBot
Allow: /
Allow: /outils/
Allow: /ressources/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Disallow: /quiz/results/
Crawl-delay: 5

# You.com
User-agent: YouBot
Allow: /
Allow: /outils/
Disallow: /my4dm1n/
Disallow: /admin/
Disallow: /request/
Crawl-delay: 2

# -----------------------------------------------------------------------------
# CRAWLERS SEO AGRESSIFS - BLOCAGE COMPLET
# -----------------------------------------------------------------------------
User-agent: AhrefsBot
Disallow: /

User-agent: SemrushBot
Disallow: /

User-agent: MJ12bot
Disallow: /

User-agent: DotBot
Disallow: /

User-agent: BLEXBot
Disallow: /

User-agent: DataForSeoBot
Disallow: /

User-agent: Bytespider
Disallow: /

User-agent: PetalBot
Disallow: /

User-agent: SeznamBot
Disallow: /

# -----------------------------------------------------------------------------
# SCRAPERS MALVEILLANTS - BLOCAGE
# -----------------------------------------------------------------------------
User-agent: MegaIndex.ru
Disallow: /

User-agent: Sogou
Disallow: /

User-agent: Yandex
Disallow: /

User-agent: Baidu
Disallow: /

# -----------------------------------------------------------------------------
# SITEMAP
# -----------------------------------------------------------------------------
Sitemap: {domain}/sitemap.xml
"""
    
    response = make_response(robots_content)
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    response.headers['Cache-Control'] = 'public, max-age=86400'
    return response

@bp.route('/sitemap.xml')
def sitemap():
    """Generate dynamic XML sitemap for SEO - CyberConfiance"""
    from models import News, Rule, Tool, AttackType, Scenario, GlossaryTerm
    
    domain = request.host_url.rstrip('/')
    today = datetime.utcnow().strftime('%Y-%m-%d')
    
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
    
    response = make_response(sitemap_xml)
    response.headers['Content-Type'] = 'application/xml; charset=utf-8'
    response.headers['Cache-Control'] = 'public, max-age=3600'
    return response


@bp.route('/outils/analyseur-qrcode', methods=['GET', 'POST'])
def qrcode_analyzer():
    import base64
    
    results = None
    analysis_id = None
    
    if request.method == 'POST':
        try:
            image_data = None
            filename = 'camera_capture.jpg'
            
            camera_capture = request.form.get('camera_capture', '').strip()
            if camera_capture and camera_capture.startswith('data:image'):
                try:
                    header, encoded = camera_capture.split(',', 1)
                    image_data = base64.b64decode(encoded)
                    
                    if 'png' in header:
                        filename = 'camera_capture.png'
                    elif 'jpeg' in header or 'jpg' in header:
                        filename = 'camera_capture.jpg'
                    elif 'webp' in header:
                        filename = 'camera_capture.webp'
                    
                    if len(image_data) > 10 * 1024 * 1024:
                        flash('L\'image capturee est trop volumineuse. Taille maximale: 10 MB.', 'error')
                        return redirect(url_for('main.qrcode_analyzer'))
                except Exception as e:
                    flash(f'Erreur lors du traitement de l\'image capturee: {str(e)}', 'error')
                    return redirect(url_for('main.qrcode_analyzer'))
            else:
                uploaded_file = request.files.get('qrcode_image')
                
                if not uploaded_file or not uploaded_file.filename:
                    flash('Veuillez capturer ou selectionner une image contenant un QR code.', 'error')
                    return redirect(url_for('main.qrcode_analyzer'))
                
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
                file_ext = uploaded_file.filename.rsplit('.', 1)[-1].lower() if '.' in uploaded_file.filename else ''
                
                if file_ext not in allowed_extensions:
                    flash('Format d\'image non supporte. Utilisez PNG, JPG, GIF, BMP ou WebP.', 'error')
                    return redirect(url_for('main.qrcode_analyzer'))
                
                image_data = uploaded_file.read()
                filename = uploaded_file.filename
                
                if len(image_data) > 10 * 1024 * 1024:
                    flash('L\'image est trop volumineuse. Taille maximale: 10 MB.', 'error')
                    return redirect(url_for('main.qrcode_analyzer'))
            
            analyzer = QRCodeAnalyzerService()
            try:
                results = analyzer.analyze_qr_image(image_data, filename)
            except Exception as e:
                results = {
                    'success': False,
                    'error': f"Erreur lors de l'analyse: {str(e)}"
                }
            
            if results and results.get('success') and results.get('extracted_url'):
                try:
                    threat_level = results.get('threat_level', 'safe')
                    
                    qr_analysis = QRCodeAnalysis(  # type: ignore
                        original_filename=filename,
                        extracted_url=results.get('extracted_url'),
                        final_url=results.get('final_url'),
                        redirect_chain=results.get('redirect_chain', []),
                        redirect_count=results.get('redirect_count', 0),
                        threat_detected=results.get('threat_detected', False),
                        threat_level=threat_level,
                        threat_details=results.get('issues', []),
                        blacklist_matches=results.get('blacklist_result'),
                        suspicious_patterns=results.get('issues', []),
                        js_redirects_detected=len(results.get('js_redirects', [])) > 0,
                        analysis_results=results,
                        document_code=ensure_unique_code(QRCodeAnalysis),
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get('User-Agent', '')[:500]
                    )
                    db.session.add(qr_analysis)
                    db.session.commit()
                    analysis_id = qr_analysis.id
                except Exception as e:
                    db.session.rollback()
                    print(f"[ERROR] Failed to save QR analysis: {e}")
            
        except Exception as e:
            flash(f'Erreur lors de l\'analyse: {str(e)}', 'error')
            return redirect(url_for('main.qrcode_analyzer'))
    
    return render_template('outils/qrcode_analyzer.html', results=results, analysis_id=analysis_id)


@bp.route('/outils/analyseur-prompt', methods=['GET', 'POST'])
def prompt_analyzer():
    results = None
    analysis_id = None
    
    if request.method == 'POST':
        try:
            prompt_text = request.form.get('prompt_text', '').strip()
            
            if not prompt_text:
                flash('Veuillez entrer un texte à analyser.', 'error')
                return redirect(url_for('main.prompt_analyzer'))
            
            if len(prompt_text) > 50000:
                flash('Le texte est trop long. Taille maximale: 50 000 caractères.', 'error')
                return redirect(url_for('main.prompt_analyzer'))
            
            analyzer = PromptAnalyzerService()
            try:
                results = analyzer.analyze_prompt(prompt_text)
            except Exception as e:
                results = {
                    'success': False,
                    'error': f"Erreur lors de l'analyse: {str(e)}"
                }
            
            if results and results.get('success'):
                try:
                    prompt_analysis = PromptAnalysis(  # type: ignore
                        prompt_text=prompt_text[:10000],
                        prompt_length=len(prompt_text),
                        threat_detected=results.get('threat_detected', False),
                        threat_level=results.get('threat_level', 'safe'),
                        injection_detected=results.get('injection_detected', False),
                        code_detected=results.get('code_detected', False),
                        obfuscation_detected=results.get('obfuscation_detected', False),
                        dangerous_patterns=results.get('issues', []),
                        analysis_results=results,
                        cleaned_text=results.get('cleaned_text', '')[:10000] if results.get('cleaned_text') else None,
                        detected_issues=results.get('issues', []),
                        document_code=ensure_unique_code(PromptAnalysis),
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get('User-Agent', '')[:500]
                    )
                    db.session.add(prompt_analysis)
                    db.session.commit()
                    analysis_id = prompt_analysis.id
                except Exception as e:
                    db.session.rollback()
                    print(f"[ERROR] Failed to save prompt analysis: {e}")
            
        except Exception as e:
            flash(f'Erreur lors de l\'analyse: {str(e)}', 'error')
            return redirect(url_for('main.prompt_analyzer'))
    
    return render_template('outils/prompt_analyzer.html', results=results, analysis_id=analysis_id)


@bp.route("/generate-qrcode-pdf/<int:analysis_id>")
def generate_qrcode_pdf(analysis_id):
    analysis = QRCodeAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()  # type: ignore
    
    if analysis.pdf_report and analysis.pdf_generated_at:
        pdf_bytes = analysis.pdf_report
    else:
        pdf_service = PDFReportService()
        pdf_bytes = pdf_service.generate_qrcode_analysis_report(analysis, user_ip)
        
        analysis.pdf_report = pdf_bytes
        analysis.pdf_generated_at = datetime.utcnow()
        db.session.commit()
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"rapport_qrcode_{analysis.id}.pdf"
    )


@bp.route("/generate-prompt-pdf/<int:analysis_id>")
def generate_prompt_pdf(analysis_id):
    analysis = PromptAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    if analysis.pdf_report and analysis.pdf_generated_at:
        pdf_bytes = analysis.pdf_report
    else:
        pdf_service = PDFReportService()
        pdf_bytes = pdf_service.generate_prompt_analysis_report(analysis, user_ip)
        
        analysis.pdf_report = pdf_bytes
        analysis.pdf_generated_at = datetime.utcnow()
        db.session.commit()
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"rapport_prompt_{analysis.id}.pdf"
    )


@bp.route('/outils/analyseur-fuite', methods=['GET', 'POST'])
def breach_analyzer():
    """Redirect to the main breach analysis page with the preferred presentation"""
    if request.method == 'POST':
        return redirect(url_for('main.analyze_breach'), code=307)
    return render_template('outils/breach_analyzer.html', results=None, analysis_id=None)


@bp.route('/outils/analyseur-github', methods=['GET', 'POST'])
def github_analyzer():
    results = None
    analysis_id = None
    
    if request.method == 'POST':
        try:
            repo_url = request.form.get('repo_url', '').strip()
            branch = request.form.get('branch', 'main').strip() or 'main'
            
            if not repo_url:
                flash('Veuillez entrer une URL de depot GitHub.', 'error')
                return redirect(url_for('main.github_analyzer'))
            
            if 'github.com' not in repo_url:
                flash('Seuls les depots GitHub sont supportes.', 'error')
                return redirect(url_for('main.github_analyzer'))
            
            analyzer = GitHubCodeAnalyzerService()
            results = analyzer.analyze(repo_url, branch)
            
            if results and not results.get('error'):
                try:
                    github_analysis = GitHubCodeAnalysis(  # type: ignore
                        repo_url=repo_url,
                        repo_name=results.get('repo_name'),
                        repo_owner=results.get('repo_owner'),
                        branch=results.get('branch'),
                        commit_hash=results.get('commit_hash'),
                        overall_score=results.get('overall_score', 0),
                        security_score=results.get('security_score', 0),
                        risk_level=results.get('risk_level'),
                        security_findings=results.get('security_findings', []),
                        dependency_findings=results.get('dependency_findings', []),
                        architecture_findings=results.get('architecture_findings', []),
                        performance_findings=results.get('performance_findings', []),
                        git_hygiene_findings=results.get('git_hygiene_findings', []),
                        documentation_findings=results.get('documentation_findings', []),
                        toxic_ai_patterns=results.get('toxic_ai_patterns', []),
                        code_quality_findings=results.get('code_quality_findings', []),
                        total_files_analyzed=results.get('total_files_analyzed', 0),
                        total_lines_analyzed=results.get('total_lines_analyzed', 0),
                        total_directories=results.get('total_directories', 0),
                        file_types_distribution=results.get('file_types_distribution', {}),
                        total_issues_found=results.get('total_issues_found', 0),
                        critical_issues=results.get('critical_issues', 0),
                        high_issues=results.get('high_issues', 0),
                        medium_issues=results.get('medium_issues', 0),
                        low_issues=results.get('low_issues', 0),
                        languages_detected=results.get('languages_detected', {}),
                        frameworks_detected=results.get('frameworks_detected', []),
                        analysis_summary=results.get('analysis_summary'),
                        status='completed',
                        analysis_duration=results.get('analysis_duration'),
                        document_code=ensure_unique_code(GitHubCodeAnalysis),
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get('User-Agent', '')[:500]
                    )
                    db.session.add(github_analysis)
                    db.session.commit()
                    analysis_id = github_analysis.id
                except Exception as e:
                    db.session.rollback()
                    print(f"[ERROR] Failed to save GitHub analysis: {e}")
            
        except Exception as e:
            flash(f'Erreur lors de l\'analyse: {str(e)}', 'error')
            return redirect(url_for('main.github_analyzer'))
    
    return render_template('outils/github_analyzer.html', results=results, analysis_id=analysis_id)


@bp.route("/generate-github-pdf/<int:analysis_id>")
def generate_github_pdf(analysis_id):
    analysis = GitHubCodeAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()  # type: ignore
    
    if analysis.pdf_report and analysis.pdf_generated_at:
        pdf_bytes = analysis.pdf_report
    else:
        pdf_service = PDFReportService()
        pdf_bytes = pdf_service.generate_github_analysis_report(analysis, user_ip)
        
        analysis.pdf_report = pdf_bytes
        analysis.pdf_generated_at = datetime.utcnow()
        db.session.commit()
    
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"rapport_github_{analysis.repo_name}_{analysis.id}.pdf"
    )
