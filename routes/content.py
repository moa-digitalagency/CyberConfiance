from flask import Blueprint, render_template, request
from services import ContentService
import __init__ as app_module

db = app_module.db

bp = Blueprint('content', __name__)

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
