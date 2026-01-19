"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Routes des outils d'analyse: liens, QR codes, prompts, GitHub, fuites email.
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, session, send_file, Response
from services import ContentService, HaveIBeenPwnedService, QuizService
from services.security import SecurityAnalyzerService
from services.pdf import PDFReportService
from services.qrcode import QRCodeAnalyzerService
from services.prompt import PromptAnalyzerService
from services.github.analyzer import GitHubCodeAnalyzerService
from services.metadata import MetadataAnalyzerService
from models import BreachAnalysis, SecurityAnalysis, QRCodeAnalysis, PromptAnalysis, GitHubCodeAnalysis, MetadataAnalysis
from utils.document_code_generator import ensure_unique_code
from utils.metadata_collector import get_client_ip
import __init__ as app_module
import os
import requests
import io
from datetime import datetime
db = app_module.db

bp = Blueprint('outils', __name__)


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
            return redirect(url_for('outils.link_analyzer'))
        
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
            return redirect(url_for('outils.link_analyzer'))
        
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
            return redirect(url_for('outils.link_analyzer'))
    
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
                return redirect(url_for('outils.security_analyzer'))
            
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
                    
                    analysis_record = SecurityAnalysis(
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
        return redirect(url_for('outils.quiz'))
    
    quiz_data = session.get('quiz_data', {})
    if not quiz_data:
        flash('Session expirée. Veuillez reprendre le quiz.', 'error')
        return redirect(url_for('outils.quiz'))
    
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
        quiz_result = QuizResult(
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
        
        return redirect(url_for('outils.quiz_result_detail', result_id=quiz_result.id))
    except Exception as e:
        print(f"Erreur lors de l'enregistrement du résultat: {str(e)}")
        db.session.rollback()
        flash('Une erreur est survenue lors de l\'enregistrement de vos résultats.', 'error')
        return redirect(url_for('outils.quiz'))


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
            
            analysis = BreachAnalysis(
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


@bp.route("/generate-breach-pdf/<int:analysis_id>")
def generate_breach_pdf(analysis_id):
    breach = BreachAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
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
    analysis = SecurityAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
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
    from models import QuizResult
    from services.quiz import QuizService
    quiz_result = QuizResult.query.get_or_404(result_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
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
                        return redirect(url_for('outils.qrcode_analyzer'))
                except Exception as e:
                    flash(f'Erreur lors du traitement de l\'image capturee: {str(e)}', 'error')
                    return redirect(url_for('outils.qrcode_analyzer'))
            else:
                uploaded_file = request.files.get('qrcode_image')
                
                if not uploaded_file or not uploaded_file.filename:
                    flash('Veuillez capturer ou selectionner une image contenant un QR code.', 'error')
                    return redirect(url_for('outils.qrcode_analyzer'))
                
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
                file_ext = uploaded_file.filename.rsplit('.', 1)[-1].lower() if '.' in uploaded_file.filename else ''
                
                if file_ext not in allowed_extensions:
                    flash('Format d\'image non supporte. Utilisez PNG, JPG, GIF, BMP ou WebP.', 'error')
                    return redirect(url_for('outils.qrcode_analyzer'))
                
                image_data = uploaded_file.read()
                filename = uploaded_file.filename
                
                if len(image_data) > 10 * 1024 * 1024:
                    flash('L\'image est trop volumineuse. Taille maximale: 10 MB.', 'error')
                    return redirect(url_for('outils.qrcode_analyzer'))
            
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
                    
                    qr_analysis = QRCodeAnalysis(
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
            return redirect(url_for('outils.qrcode_analyzer'))
    
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
                return redirect(url_for('outils.prompt_analyzer'))
            
            if len(prompt_text) > 50000:
                flash('Le texte est trop long. Taille maximale: 50 000 caractères.', 'error')
                return redirect(url_for('outils.prompt_analyzer'))
            
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
                    prompt_analysis = PromptAnalysis(
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
            return redirect(url_for('outils.prompt_analyzer'))
    
    return render_template('outils/prompt_analyzer.html', results=results, analysis_id=analysis_id)


@bp.route("/generate-qrcode-pdf/<int:analysis_id>")
def generate_qrcode_pdf(analysis_id):
    analysis = QRCodeAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
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
    if request.method == 'POST':
        return redirect(url_for('outils.analyze_breach'), code=307)
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
                return redirect(url_for('outils.github_analyzer'))
            
            if 'github.com' not in repo_url:
                flash('Seuls les depots GitHub sont supportes.', 'error')
                return redirect(url_for('outils.github_analyzer'))
            
            analyzer = GitHubCodeAnalyzerService()
            results = analyzer.analyze(repo_url, branch)
            
            if results and not results.get('error'):
                try:
                    github_analysis = GitHubCodeAnalysis(
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
            return redirect(url_for('outils.github_analyzer'))
    
    return render_template('outils/github_analyzer.html', results=results, analysis_id=analysis_id)


@bp.route("/generate-github-pdf/<int:analysis_id>")
def generate_github_pdf(analysis_id):
    analysis = GitHubCodeAnalysis.query.get_or_404(analysis_id)
    
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
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


@bp.route('/outils/analyseur-metadonnee', methods=['GET', 'POST'])
def metadata_analyzer():
    results = None
    analysis_id = None
    
    MAX_FILE_SIZE = 200 * 1024 * 1024
    
    if request.method == 'POST':
        action = request.form.get('action', 'analyze')
        
        if 'file' not in request.files:
            flash('Veuillez selectionner un fichier a analyser.', 'error')
            return redirect(url_for('outils.metadata_analyzer'))
        
        file = request.files['file']
        
        if file.filename == '':
            flash('Aucun fichier selectionne.', 'error')
            return redirect(url_for('outils.metadata_analyzer'))
        
        try:
            file_data = file.read()
            filename = file.filename
            
            if len(file_data) > MAX_FILE_SIZE:
                flash('Le fichier est trop volumineux. Taille maximale: 200 Mo.', 'error')
                return redirect(url_for('outils.metadata_analyzer'))
            
            file_type = MetadataAnalyzerService.get_file_type(filename)
            if not file_type:
                flash('Type de fichier non supporte. Formats acceptes: Images (JPG, PNG, GIF, WebP, TIFF, HEIC), Videos (MP4, MOV, AVI, MKV), Audio (MP3, WAV, FLAC).', 'error')
                return redirect(url_for('outils.metadata_analyzer'))
            
            if action == 'analyze':
                results = MetadataAnalyzerService.analyze_file(file_data, filename)
                
                if results.get('success'):
                    try:
                        clean_data, clean_filename = MetadataAnalyzerService.remove_metadata(file_data, filename)
                        
                        metadata_analysis = MetadataAnalysis(
                            original_filename=filename,
                            file_type=results.get('file_type'),
                            file_size=results.get('file_size'),
                            mime_type=file.content_type,
                            metadata_found=results.get('metadata'),
                            metadata_count=results.get('metadata_count', 0),
                            privacy_risk_level=results.get('privacy_risk'),
                            sensitive_data_found=results.get('sensitive_data'),
                            gps_data=results.get('gps_data'),
                            camera_info=results.get('camera_info'),
                            software_info=results.get('software_info'),
                            datetime_info=results.get('datetime_info'),
                            author_info=results.get('author_info'),
                            original_file=file_data,
                            cleaned_file=clean_data if clean_data else None,
                            cleaned_filename=clean_filename if clean_data else None,
                            document_code=ensure_unique_code(MetadataAnalysis),
                            ip_address=get_client_ip(request),
                            user_agent=request.headers.get('User-Agent', '')[:500]
                        )
                        db.session.add(metadata_analysis)
                        db.session.commit()
                        analysis_id = metadata_analysis.id
                        return redirect(url_for('outils.metadata_results', analysis_id=analysis_id))
                    except Exception as e:
                        db.session.rollback()
                        print(f"[ERROR] Failed to save metadata analysis: {e}")
                else:
                    flash(results.get('error', 'Erreur lors de l\'analyse'), 'error')
                    
            elif action == 'clean':
                clean_analysis_id = request.form.get('analysis_id')
                if clean_analysis_id:
                    return redirect(url_for('outils.metadata_download_clean', analysis_id=clean_analysis_id))
                
                clean_data, clean_filename = MetadataAnalyzerService.remove_metadata(file_data, filename)
                
                if clean_data:
                    file_ext = os.path.splitext(filename)[1].lower()
                    mime_types = {
                        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
                        '.png': 'image/png', '.gif': 'image/gif',
                        '.webp': 'image/webp', '.tiff': 'image/tiff', '.tif': 'image/tiff',
                        '.mp4': 'video/mp4', '.mov': 'video/quicktime',
                        '.avi': 'video/x-msvideo', '.mkv': 'video/x-matroska',
                        '.mp3': 'audio/mpeg', '.wav': 'audio/wav',
                        '.flac': 'audio/flac', '.m4a': 'audio/mp4'
                    }
                    mime_type = mime_types.get(file_ext, 'application/octet-stream')
                    
                    return Response(
                        clean_data,
                        mimetype=mime_type,
                        headers={
                            'Content-Disposition': f'attachment; filename="{clean_filename}"',
                            'Content-Length': len(clean_data)
                        }
                    )
                else:
                    flash(f'Erreur: {clean_filename}', 'error')
                    return redirect(url_for('outils.metadata_analyzer'))
                    
        except Exception as e:
            flash(f'Erreur lors du traitement: {str(e)}', 'error')
            return redirect(url_for('outils.metadata_analyzer'))
    
    return render_template('outils/metadata_analyzer.html', results=results, analysis_id=analysis_id)


@bp.route('/outils/analyseur-metadonnee/<int:analysis_id>/pdf')
def metadata_analysis_pdf(analysis_id):
    from services.pdf import PDFReportService
    from datetime import datetime
    
    analysis = MetadataAnalysis.query.get_or_404(analysis_id)
    
    if analysis.pdf_report:
        return Response(
            analysis.pdf_report,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="rapport_metadonnees_{analysis.id}.pdf"',
                'Content-Length': len(analysis.pdf_report)
            }
        )
    
    pdf_service = PDFReportService()
    ip_address = get_client_ip(request)
    
    try:
        pdf_bytes = pdf_service.generate_metadata_analysis_report(analysis, ip_address)
        
        analysis.pdf_report = pdf_bytes
        analysis.pdf_generated_at = datetime.utcnow()
        db.session.commit()
        
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="rapport_metadonnees_{analysis.id}.pdf"',
                'Content-Length': len(pdf_bytes)
            }
        )
    except Exception as e:
        print(f"[ERROR] Failed to generate metadata PDF: {e}")
        import traceback
        traceback.print_exc()
        flash('Erreur lors de la generation du rapport PDF.', 'error')
        return redirect(url_for('outils.metadata_analyzer'))


@bp.route('/outils/analyseur-metadonnee/<int:analysis_id>/telecharger')
def metadata_download_clean(analysis_id):
    analysis = MetadataAnalysis.query.get_or_404(analysis_id)
    
    filename = analysis.original_filename or 'fichier'
    base, ext = os.path.splitext(filename)
    clean_filename = f"{base}_nettoye{ext}"
    
    mime_types = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png', '.gif': 'image/gif',
        '.webp': 'image/webp', '.tiff': 'image/tiff', '.tif': 'image/tiff',
        '.mp4': 'video/mp4', '.mov': 'video/quicktime',
        '.avi': 'video/x-msvideo', '.mkv': 'video/x-matroska',
        '.mp3': 'audio/mpeg', '.wav': 'audio/wav',
        '.flac': 'audio/flac', '.m4a': 'audio/mp4'
    }
    mime_type = mime_types.get(ext.lower(), 'application/octet-stream')
    
    if analysis.cleaned_file:
        return Response(
            analysis.cleaned_file,
            mimetype=mime_type,
            headers={
                'Content-Disposition': f'attachment; filename="{clean_filename}"',
                'Content-Length': len(analysis.cleaned_file)
            }
        )
    
    if analysis.original_file:
        try:
            clean_data, _ = MetadataAnalyzerService.remove_metadata(analysis.original_file, filename)
            if clean_data:
                analysis.cleaned_file = clean_data
                analysis.cleaned_filename = clean_filename
                db.session.commit()
                
                return Response(
                    clean_data,
                    mimetype=mime_type,
                    headers={
                        'Content-Disposition': f'attachment; filename="{clean_filename}"',
                        'Content-Length': len(clean_data)
                    }
                )
        except Exception as e:
            print(f"[ERROR] Failed to clean metadata on-the-fly: {e}")
    
    flash('Le fichier original n\'est plus disponible. Veuillez refaire une analyse.', 'warning')
    return redirect(url_for('outils.metadata_analyzer'))


@bp.route('/outils/analyseur-metadonnee/<int:analysis_id>/resultats')
def metadata_results(analysis_id):
    analysis = MetadataAnalysis.query.get_or_404(analysis_id)
    return render_template('outils/metadata_results.html', analysis=analysis)


@bp.route('/outils/analyseur-metadonnee/<int:analysis_id>/pdf-resume')
def metadata_analysis_pdf_summary(analysis_id):
    from services.pdf import PDFReportService
    from datetime import datetime
    
    analysis = MetadataAnalysis.query.get_or_404(analysis_id)
    
    pdf_service = PDFReportService()
    ip_address = get_client_ip(request)
    
    try:
        pdf_bytes = pdf_service.generate_metadata_analysis_report(analysis, ip_address, report_type='summary')
        
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="rapport_resume_metadonnees_{analysis.id}.pdf"',
                'Content-Length': len(pdf_bytes)
            }
        )
    except Exception as e:
        print(f"[ERROR] Failed to generate metadata summary PDF: {e}")
        import traceback
        traceback.print_exc()
        flash('Erreur lors de la generation du rapport PDF.', 'error')
        return redirect(url_for('outils.metadata_results', analysis_id=analysis_id))


@bp.route('/outils/analyseur-metadonnee/<int:analysis_id>/pdf-complet')
def metadata_analysis_pdf_complete(analysis_id):
    from services.pdf import PDFReportService
    from datetime import datetime
    
    analysis = MetadataAnalysis.query.get_or_404(analysis_id)
    
    if analysis.pdf_report:
        return Response(
            analysis.pdf_report,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="rapport_complet_metadonnees_{analysis.id}.pdf"',
                'Content-Length': len(analysis.pdf_report)
            }
        )
    
    pdf_service = PDFReportService()
    ip_address = get_client_ip(request)
    
    try:
        pdf_bytes = pdf_service.generate_metadata_analysis_report(analysis, ip_address, report_type='complete')
        
        analysis.pdf_report = pdf_bytes
        analysis.pdf_generated_at = datetime.utcnow()
        db.session.commit()
        
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="rapport_complet_metadonnees_{analysis.id}.pdf"',
                'Content-Length': len(pdf_bytes)
            }
        )
    except Exception as e:
        print(f"[ERROR] Failed to generate metadata complete PDF: {e}")
        import traceback
        traceback.print_exc()
        flash('Erreur lors de la generation du rapport PDF.', 'error')
        return redirect(url_for('outils.metadata_results', analysis_id=analysis_id))
