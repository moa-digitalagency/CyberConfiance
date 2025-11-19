from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, logout_user, login_required
from services import ContentService, HaveIBeenPwnedService, QuizService
from services.security_analyzer import SecurityAnalyzerService
from models import Contact, User, BreachAnalysis, SecurityAnalysis
import __init__ as app_module
import json
import requests
db = app_module.db

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    latest_news = ContentService.get_latest_news(limit=2)
    resources = ContentService.get_all_resources()[:2]
    return render_template('index.html', news=latest_news, resources=resources)

@bp.route('/about')
def about():
    return render_template('about.html')

@bp.route('/rules')
def rules():
    all_rules = ContentService.get_all_rules()
    return render_template('rules.html', rules=all_rules)

@bp.route('/rules/<int:rule_id>')
def rule_detail(rule_id):
    from models import Rule
    rule = Rule.query.get_or_404(rule_id)
    return render_template('rule_detail.html', rule=rule)

@bp.route('/scenarios')
def scenarios():
    all_scenarios = ContentService.get_all_scenarios()
    return render_template('scenarios.html', scenarios=all_scenarios)

@bp.route('/tools')
def tools():
    all_tools = ContentService.get_all_tools()
    return render_template('tools.html', tools=all_tools)

@bp.route('/glossary')
def glossary():
    terms = ContentService.get_glossary_terms()
    return render_template('glossary.html', terms=terms)

@bp.route('/resources')
def resources():
    all_resources = ContentService.get_all_resources()
    return render_template('resources.html', resources=all_resources)

@bp.route('/news')
def news():
    category_filter = request.args.get('category', None)
    
    if category_filter and category_filter != 'Toutes':
        from models import News
        filtered_news = News.query.filter_by(category=category_filter).order_by(News.created_at.desc()).limit(50).all()
    else:
        filtered_news = ContentService.get_latest_news(limit=50)
    
    from models import News
    categories = db.session.query(News.category).distinct().all()
    categories = [cat[0] for cat in categories if cat[0]]
    categories.sort()
    
    return render_template('news.html', news=filtered_news, categories=categories, selected_category=category_filter)

@bp.route('/news/<int:news_id>')
def news_detail(news_id):
    from models import News
    article = News.query.get_or_404(news_id)
    return render_template('news_detail.html', article=article)

@bp.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        if name and email and subject and message:
            ContentService.save_contact(name, email, subject, message)
            flash('Votre message a été envoyé avec succès!', 'success')
            return redirect(url_for('main.contact'))
        else:
            flash('Veuillez remplir tous les champs.', 'error')
    
    return render_template('contact.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Connexion réussie!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.index'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
    
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Déconnexion réussie.', 'success')
    return redirect(url_for('main.index'))

@bp.route('/services/sensibilisation')
def service_sensibilisation():
    return render_template('services/sensibilisation.html')

@bp.route('/programme/<slug>')
def programme_detail(slug):
    programmes = {
        'ateliers-communautaires': 'programmes/ateliers_communautaires.html',
        'campagnes-reseaux-sociaux': 'programmes/campagnes_reseaux_sociaux.html',
        'webinaires-videos': 'programmes/webinaires_videos.html',
        'guides-pratiques': 'programmes/guides_pratiques.html',
        'formations-entreprises': 'programmes/formations_entreprises.html',
        'partenariats-educatifs': 'programmes/partenariats_educatifs.html'
    }
    
    template = programmes.get(slug, 'programme_detail.html')
    return render_template(template)

@bp.route('/services/factchecking')
def service_factchecking():
    return render_template('services/factchecking.html')

@bp.route('/services/cyberconsultation')
def service_cyberconsultation():
    return render_template('services/cyberconsultation.html')

@bp.route('/outils/methodologie-osint')
def osint_methodology():
    return render_template('outils/methodologie_osint.html')

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
        
        def is_safe_url(check_url):
            try:
                parsed = urlparse(check_url)
                if parsed.scheme not in ['http', 'https']:
                    return False
                
                hostname = parsed.hostname
                if not hostname:
                    return False
                
                if hostname in ['localhost', '127.0.0.1', '0.0.0.0']:
                    return False
                
                if hostname.startswith('169.254.'):
                    return False
                
                try:
                    ip = ipaddress.ip_address(hostname)
                    if ip.is_private or ip.is_loopback or ip.is_link_local:
                        return False
                except ValueError:
                    pass
                
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
    
    if request.method == 'POST':
        input_value = request.form.get('input_value', '').strip()
        input_type = request.form.get('input_type', 'hash')
        
        if not input_value:
            flash('Veuillez fournir une valeur à analyser.', 'error')
            return redirect(url_for('main.security_analyzer'))
        
        analyzer = SecurityAnalyzerService()
        results = analyzer.analyze(input_value, input_type)
        
        try:
            analysis_record = SecurityAnalysis(
                input_value=input_value,
                input_type=input_type,
                analysis_results=results,
                threat_detected=results.get('threat_detected', False),
                threat_level=results.get('threat_level'),
                malicious_count=results.get('malicious', 0),
                total_engines=results.get('total', 0),
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            db.session.add(analysis_record)
            db.session.commit()
        except Exception as e:
            print(f"Error saving security analysis: {str(e)}")
    
    return render_template('outils/security_analyzer.html', results=results)

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
        quiz_result = QuizResult(
            email=email,
            overall_score=overall_score,
            category_scores=scores,
            answers=answers,
            hibp_summary=hibp_summary,
            ip_address=request.remote_addr,
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
    quiz_result = QuizResult.query.get_or_404(result_id)
    
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
                             data_scenarios=data_scenarios)
    
    recommendations = HaveIBeenPwnedService.get_breach_recommendations(result['count'])
    data_scenarios = HaveIBeenPwnedService.get_data_breach_scenarios()
    
    try:
        breach_names = [breach.get('Name', 'Inconnu') for breach in result.get('breaches', [])]
        analysis = BreachAnalysis(
            email=email,
            breach_count=result.get('count', 0),
            risk_level=recommendations.get('level', 'unknown'),
            breaches_found=json.dumps(breach_names),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500]
        )
        db.session.add(analysis)
        db.session.commit()
        print(f"[OK] Analyse enregistrée: {email} - {result.get('count', 0)} breach(es)")
    except Exception as e:
        print(f"[!] Erreur lors de l'enregistrement de l'analyse: {str(e)}")
        db.session.rollback()
    
    return render_template('breach_analysis.html', 
                         email=email,
                         result=result, 
                         recommendations=recommendations,
                         data_scenarios=data_scenarios)
