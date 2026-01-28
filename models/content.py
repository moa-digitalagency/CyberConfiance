"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier content.py du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com

"""

"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Modeles de contenu: Article, Rule, Tool, Scenario, Resource, News, GlossaryTerm, AttackType.
"""

from datetime import datetime
from models.base import db


class Article(db.Model):
    __tablename__ = 'articles'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    author = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    published = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Article {self.title}>'


class Rule(db.Model):
    __tablename__ = 'rules'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    icon = db.Column(db.String(50))
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Rule {self.title}>'


class Tool(db.Model):
    __tablename__ = 'tools'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    type = db.Column(db.String(50))
    url = db.Column(db.String(500))
    use_case = db.Column(db.Text)
    dangers = db.Column(db.Text)
    related_rules = db.Column(db.String(100))
    related_scenarios = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Tool {self.name}>'
    
    def get_related_rule_ids(self):
        if not self.related_rules:
            return []
        return [int(x.strip()) for x in self.related_rules.split(',') if x.strip().isdigit()]
    
    def get_related_scenario_ids(self):
        if not self.related_scenarios:
            return []
        return [int(x.strip()) for x in self.related_scenarios.split(',') if x.strip().isdigit()]


class Scenario(db.Model):
    __tablename__ = 'scenarios'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    threat_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    solution = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Scenario {self.title}>'


class Resource(db.Model):
    __tablename__ = 'resources'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    url = db.Column(db.String(500), nullable=False)
    resource_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Resource {self.title}>'


class News(db.Model):
    __tablename__ = 'news'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='Général')
    source = db.Column(db.String(200))
    url = db.Column(db.String(500))
    published_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<News {self.title}>'


class GlossaryTerm(db.Model):
    __tablename__ = 'glossary'
    
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(200), nullable=False)
    definition = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<GlossaryTerm {self.term}>'


class AttackType(db.Model):
    __tablename__ = 'attack_types'
    
    id = db.Column(db.Integer, primary_key=True)
    name_en = db.Column(db.String(200), nullable=False)
    name_fr = db.Column(db.String(200), nullable=False)
    description_fr = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    prevention = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<AttackType {self.name_fr}>'
