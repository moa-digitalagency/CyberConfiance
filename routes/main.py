from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required
from services import ContentService, HaveIBeenPwnedService
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

@bp.route('/services/factchecking')
def service_factchecking():
    return render_template('services/factchecking.html')

@bp.route('/services/cyberconsultation')
def service_cyberconsultation():
    return render_template('services/cyberconsultation.html')

@bp.route('/outils/methodologie-osint')
def osint_methodology():
    return render_template('outils/methodologie_osint.html')

@bp.route('/analyze-breach', methods=['POST'])
def analyze_breach():
    email = request.form.get('email')
    
    if not email:
        flash('Veuillez fournir une adresse email.', 'error')
        return redirect(url_for('main.index'))
    
    result = HaveIBeenPwnedService.check_email_breach(email)
    
    if result.get('error'):
        # Log détaillé pour l'admin (console serveur)
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
    
    # DEBUG: Voir ce qui est envoyé au template
    print(f"DEBUG - result.get('breaches'): {bool(result.get('breaches'))}")
    print(f"DEBUG - result['count']: {result.get('count', 0)}")
    print(f"DEBUG - Nombre de breaches: {len(result.get('breaches', []))}")
    
    # DEBUG: Voir les DataClasses de la première breach
    if result.get('breaches'):
        first_breach = result['breaches'][0]
        print(f"DEBUG - Première breach: {first_breach.get('Name')}")
        print(f"DEBUG - DataClasses disponibles: {bool(first_breach.get('DataClasses'))}")
        if first_breach.get('DataClasses'):
            print(f"DEBUG - Types de données: {first_breach.get('DataClasses')}")
    
    # Log détaillé pour l'admin (console serveur uniquement)
    if result.get('breaches'):
        print(f"\n{'='*80}")
        print(f"📊 ANALYSE DE FUITE - {email}")
        print(f"   Nombre de fuites détectées: {result['count']}")
        print(f"{'='*80}")
        for i, breach in enumerate(result['breaches'][:10], 1):
            print(f"\n{i}. {breach.get('Name', 'Inconnu')}")
            print(f"   Date: {breach.get('BreachDate', 'Non spécifiée')}")
            if breach.get('DataClasses'):
                print(f"   Données compromises: {', '.join(breach.get('DataClasses', []))}")
            if breach.get('PwnCount'):
                print(f"   Comptes affectés: {breach['PwnCount']:,}")
        if result['count'] > 10:
            print(f"\n... et {result['count'] - 10} autre(s) fuite(s)")
        print(f"{'='*80}\n")
    
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
