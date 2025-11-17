from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required
from services import ContentService
from models import Contact, User
import __init__ as app_module
db = app_module.db

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    latest_news = ContentService.get_latest_news(limit=3)
    rules = ContentService.get_all_rules()[:6]
    return render_template('index.html', news=latest_news, rules=rules)

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
