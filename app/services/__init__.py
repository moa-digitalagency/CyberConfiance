from app.models import Article, Rule, Tool, Scenario, Resource, News, Contact, GlossaryTerm
from app import db

class ContentService:
    @staticmethod
    def get_published_articles():
        return Article.query.filter_by(published=True).order_by(Article.created_at.desc()).all()
    
    @staticmethod
    def get_all_rules():
        return Rule.query.order_by(Rule.order).all()
    
    @staticmethod
    def get_all_tools():
        return Tool.query.order_by(Tool.name).all()
    
    @staticmethod
    def get_all_scenarios():
        return Scenario.query.order_by(Scenario.created_at.desc()).all()
    
    @staticmethod
    def get_all_resources():
        return Resource.query.order_by(Resource.created_at.desc()).all()
    
    @staticmethod
    def get_latest_news(limit=10):
        return News.query.order_by(News.published_date.desc()).limit(limit).all()
    
    @staticmethod
    def get_glossary_terms():
        return GlossaryTerm.query.order_by(GlossaryTerm.term).all()
    
    @staticmethod
    def save_contact(name, email, subject, message):
        contact = Contact(name=name, email=email, subject=subject, message=message)
        db.session.add(contact)
        db.session.commit()
        return contact
