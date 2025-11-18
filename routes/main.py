from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_user, logout_user, login_required
from services import ContentService, HaveIBeenPwnedService, QuizService
from models import Contact, User, BreachAnalysis
import __init__ as app_module
import json
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
    all_news = ContentService.get_latest_news(limit=50)
    return render_template('news.html', news=all_news)

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

@bp.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'submit_quiz':
            answers = {}
            quiz_data = QuizService.load_quiz_data()
            
            for question in quiz_data['questions']:
                question_id = str(question['id'])
                answer = request.form.get(f'question_{question_id}')
                if answer:
                    answers[question_id] = answer
            
            scores = QuizService.calculate_scores(answers)
            recommendations = QuizService.get_recommendations(scores['overall_score'], answers)
            
            session['quiz_results'] = {
                'scores': scores,
                'recommendations': recommendations,
                'answers': answers
            }
            
            return render_template('outils/quiz_results.html',
                                 scores=scores,
                                 recommendations=recommendations)
        
        elif action == 'analyze_email':
            email = request.form.get('email')
            
            if not email:
                flash('Veuillez fournir une adresse email.', 'error')
                return redirect(url_for('main.quiz'))
            
            quiz_results = session.get('quiz_results', {})
            scores = quiz_results.get('scores', {})
            recommendations = quiz_results.get('recommendations', {})
            
            hibp_result = HaveIBeenPwnedService.check_email_breach(email)
            
            if not hibp_result.get('error'):
                try:
                    breach_names = [breach.get('Name', 'Inconnu') for breach in hibp_result.get('breaches', [])]
                    analysis = BreachAnalysis(
                        email=email,
                        breach_count=hibp_result.get('count', 0),
                        risk_level=recommendations.get('level', {}).get('key', 'unknown'),
                        breaches_found=json.dumps(breach_names),
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent', '')[:500]
                    )
                    db.session.add(analysis)
                    db.session.commit()
                except Exception as e:
                    print(f"⚠️ Erreur lors de l'enregistrement de l'analyse: {str(e)}")
                    db.session.rollback()
            
            hibp_recommendations = HaveIBeenPwnedService.get_breach_recommendations(hibp_result.get('count', 0))
            
            return render_template('outils/quiz_results.html',
                                 scores=scores,
                                 recommendations=recommendations,
                                 email=email,
                                 hibp_result=hibp_result,
                                 hibp_recommendations=hibp_recommendations)
    
    quiz_data = QuizService.load_quiz_data()
    return render_template('outils/quiz.html', quiz_data=quiz_data)

@bp.route('/analyze-breach', methods=['POST'])
def analyze_breach():
    email = request.form.get('email')
    
    if not email:
        flash('Veuillez fournir une adresse email.', 'error')
        return redirect(url_for('main.index'))
    
    result = HaveIBeenPwnedService.check_email_breach(email)
    
    if result.get('error'):
        print(f"⚠️ Analyse de fuite échouée pour {email}: {result['error']}")
        
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
        print(f"✅ Analyse enregistrée: {email} - {result.get('count', 0)} breach(es)")
    except Exception as e:
        print(f"⚠️ Erreur lors de l'enregistrement de l'analyse: {str(e)}")
        db.session.rollback()
    
    return render_template('breach_analysis.html', 
                         email=email,
                         result=result, 
                         recommendations=recommendations,
                         data_scenarios=data_scenarios)
