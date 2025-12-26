"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Modeles d'analyse: BreachAnalysis, SecurityAnalysis, QRCodeAnalysis, PromptAnalysis, QuizResult, GitHubCodeAnalysis.
"""

from datetime import datetime
from models.base import db


class BreachAnalysis(db.Model):
    __tablename__ = 'breach_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    breach_count = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20))
    breaches_found = db.Column(db.Text)
    breaches_data = db.Column(db.JSON)
    document_code = db.Column(db.String(20), unique=True, index=True)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    pdf_report = db.Column(db.LargeBinary)
    pdf_generated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<BreachAnalysis {self.email} - {self.breach_count} breaches>'


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
    breach_analysis_id = db.Column(db.Integer, db.ForeignKey('breach_analyses.id'), nullable=True)
    document_code = db.Column(db.String(20), unique=True, index=True)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    pdf_report = db.Column(db.LargeBinary)
    pdf_generated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    breach_analysis = db.relationship('BreachAnalysis', backref='security_analyses')
    
    def __repr__(self):
        return f'<SecurityAnalysis {self.input_type}: {self.input_value[:50]}>'


class QRCodeAnalysis(db.Model):
    __tablename__ = 'qrcode_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(500))
    extracted_url = db.Column(db.String(2000))
    final_url = db.Column(db.String(2000))
    redirect_chain = db.Column(db.JSON)
    redirect_count = db.Column(db.Integer, default=0)
    threat_detected = db.Column(db.Boolean, default=False)
    threat_level = db.Column(db.String(20))
    threat_details = db.Column(db.JSON)
    blacklist_matches = db.Column(db.JSON)
    suspicious_patterns = db.Column(db.JSON)
    js_redirects_detected = db.Column(db.Boolean, default=False)
    analysis_results = db.Column(db.JSON)
    document_code = db.Column(db.String(20), unique=True, index=True)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    pdf_report = db.Column(db.LargeBinary)
    pdf_generated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<QRCodeAnalysis {self.id} - {self.extracted_url[:50] if self.extracted_url else "No URL"}>'


class PromptAnalysis(db.Model):
    __tablename__ = 'prompt_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    prompt_text = db.Column(db.Text, nullable=False)
    prompt_length = db.Column(db.Integer)
    threat_detected = db.Column(db.Boolean, default=False)
    threat_level = db.Column(db.String(20))
    injection_detected = db.Column(db.Boolean, default=False)
    code_detected = db.Column(db.Boolean, default=False)
    obfuscation_detected = db.Column(db.Boolean, default=False)
    dangerous_patterns = db.Column(db.JSON)
    analysis_results = db.Column(db.JSON)
    cleaned_text = db.Column(db.Text)
    detected_issues = db.Column(db.JSON)
    document_code = db.Column(db.String(20), unique=True, index=True)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    pdf_report = db.Column(db.LargeBinary)
    pdf_generated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PromptAnalysis {self.id} - Threat: {self.threat_detected}>'


class QuizResult(db.Model):
    __tablename__ = 'quiz_results'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    overall_score = db.Column(db.Integer, nullable=False)
    category_scores = db.Column(db.JSON, nullable=False)
    answers = db.Column(db.JSON, nullable=False)
    hibp_summary = db.Column(db.JSON)
    document_code = db.Column(db.String(20), unique=True, index=True)
    pdf_report = db.Column(db.LargeBinary)
    pdf_generated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    
    def __repr__(self):
        return f'<QuizResult {self.email} - Score: {self.overall_score}%>'


class GitHubCodeAnalysis(db.Model):
    __tablename__ = 'github_code_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    repo_url = db.Column(db.String(500), nullable=False)
    repo_name = db.Column(db.String(200))
    repo_owner = db.Column(db.String(100))
    branch = db.Column(db.String(100), default='main')
    commit_hash = db.Column(db.String(50))
    
    overall_score = db.Column(db.Float, default=0.0)
    security_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20))
    
    security_findings = db.Column(db.JSON)
    dependency_findings = db.Column(db.JSON)
    architecture_findings = db.Column(db.JSON)
    performance_findings = db.Column(db.JSON)
    git_hygiene_findings = db.Column(db.JSON)
    documentation_findings = db.Column(db.JSON)
    toxic_ai_patterns = db.Column(db.JSON)
    code_quality_findings = db.Column(db.JSON)
    
    total_files_analyzed = db.Column(db.Integer, default=0)
    total_lines_analyzed = db.Column(db.Integer, default=0)
    total_directories = db.Column(db.Integer, default=0)
    file_types_distribution = db.Column(db.JSON)
    total_issues_found = db.Column(db.Integer, default=0)
    critical_issues = db.Column(db.Integer, default=0)
    high_issues = db.Column(db.Integer, default=0)
    medium_issues = db.Column(db.Integer, default=0)
    low_issues = db.Column(db.Integer, default=0)
    
    languages_detected = db.Column(db.JSON)
    frameworks_detected = db.Column(db.JSON)
    analysis_summary = db.Column(db.Text)
    
    status = db.Column(db.String(20), default='pending')
    error_message = db.Column(db.Text)
    analysis_duration = db.Column(db.Float)
    
    document_code = db.Column(db.String(20), unique=True, index=True)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(500))
    pdf_report = db.Column(db.LargeBinary)
    pdf_generated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<GitHubCodeAnalysis {self.repo_name} - Score: {self.overall_score}>'
