"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier __init__.py du projet CyberConfiance
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

Exports de tous les modeles de donnees SQLAlchemy.
"""

from models.base import db
from models.user import User
from models.content import Article, Rule, Tool, Scenario, Resource, News, GlossaryTerm, AttackType
from models.contact import Contact, Newsletter
from models.analysis import (
    BreachAnalysis, SecurityAnalysis, QRCodeAnalysis, 
    PromptAnalysis, QuizResult, GitHubCodeAnalysis, MetadataAnalysis
)
from models.logs import ActivityLog, SecurityLog, ThreatLog
from models.settings import SiteSettings, SEOMetadata
from models.request import RequestSubmission

__all__ = [
    'db',
    'User',
    'Article', 'Rule', 'Tool', 'Scenario', 'Resource', 'News', 'GlossaryTerm', 'AttackType',
    'Contact', 'Newsletter',
    'BreachAnalysis', 'SecurityAnalysis', 'QRCodeAnalysis', 'PromptAnalysis', 'QuizResult', 'GitHubCodeAnalysis', 'MetadataAnalysis',
    'ActivityLog', 'SecurityLog', 'ThreatLog',
    'SiteSettings', 'SEOMetadata',
    'RequestSubmission'
]
