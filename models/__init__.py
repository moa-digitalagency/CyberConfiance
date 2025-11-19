import __init__ as app_module
db = app_module.db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_role(self, role):
        """Check if user has specific role"""
        return self.role == role
    
    def is_admin_role(self):
        """Check if user is admin"""
        return self.role == 'admin'
    
    def is_moderator_role(self):
        """Check if user is moderator or admin"""
        return self.role in ['admin', 'moderator']
    
    def __repr__(self):
        return f'<User {self.username}>'

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
        """Get list of related rule IDs"""
        if not self.related_rules:
            return []
        return [int(x.strip()) for x in self.related_rules.split(',') if x.strip().isdigit()]
    
    def get_related_scenario_ids(self):
        """Get list of related scenario IDs"""
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

class Contact(db.Model):
    __tablename__ = 'contacts'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='new')
    
    def __repr__(self):
        return f'<Contact {self.name}>'

class GlossaryTerm(db.Model):
    __tablename__ = 'glossary'
    
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(200), nullable=False)
    definition = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<GlossaryTerm {self.term}>'

class BreachAnalysis(db.Model):
    __tablename__ = 'breach_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    breach_count = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20))
    breaches_found = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<BreachAnalysis {self.email} - {self.breach_count} breaches>'

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

class QuizResult(db.Model):
    __tablename__ = 'quiz_results'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    overall_score = db.Column(db.Integer, nullable=False)
    category_scores = db.Column(db.JSON, nullable=False)
    answers = db.Column(db.JSON, nullable=False)
    hibp_summary = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    
    def __repr__(self):
        return f'<QuizResult {self.email} - Score: {self.overall_score}%>'

class SecurityAnalysis(db.Model):
    __tablename__ = 'security_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    input_value = db.Column(db.String(500), nullable=False)
    input_type = db.Column(db.String(20), nullable=False)
    analysis_results = db.Column(db.JSON)
    threat_detected = db.Column(db.Boolean, default=False)
    threat_level = db.Column(db.String(20))
    malicious_count = db.Column(db.Integer, default=0)
    total_engines = db.Column(db.Integer, default=0)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<SecurityAnalysis {self.input_type}: {self.input_value[:50]}>'

class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action_type = db.Column(db.String(100), nullable=False)
    action_detail = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    extra_data = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='activity_logs')
    
    def __repr__(self):
        return f'<ActivityLog {self.action_type} - {self.created_at}>'

class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    extra_data = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='security_logs')

    
    def __repr__(self):
        return f'<SecurityLog {self.event_type} - {self.severity}>'

class Newsletter(db.Model):
    __tablename__ = 'newsletter'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    subscribed = db.Column(db.Boolean, default=True)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    unsubscribed_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Newsletter {self.email}>'

class SiteSettings(db.Model):
    __tablename__ = 'site_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20), default='string')
    description = db.Column(db.Text)
    category = db.Column(db.String(50))
    is_public = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    updater = db.relationship('User', backref='settings_updates')
    
    def __repr__(self):
        return f'<SiteSettings {self.key}>'

class SEOMetadata(db.Model):
    __tablename__ = 'seo_metadata'
    
    id = db.Column(db.Integer, primary_key=True)
    page_path = db.Column(db.String(200), unique=True, nullable=False)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    keywords = db.Column(db.Text)
    og_title = db.Column(db.String(200))
    og_description = db.Column(db.Text)
    og_image = db.Column(db.String(500))
    canonical_url = db.Column(db.String(500))
    robots = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    updater = db.relationship('User', backref='seo_updates')
    
    def __repr__(self):
        return f'<SEOMetadata {self.page_path}>'
