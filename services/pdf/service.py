"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Orchestrateur de rapports PDF forensiques.
"""

from services.pdf.base import PDFReportBase
from services.pdf.breach_report import BreachReportMixin
from services.pdf.security_report import SecurityReportMixin
from services.pdf.qrcode_report import QRCodeReportMixin
from services.pdf.github_report import GitHubReportMixin
from services.pdf.quiz_report import QuizReportMixin
from services.pdf.metadata_report import MetadataReportMixin


class PDFReportService(
    PDFReportBase,
    BreachReportMixin,
    SecurityReportMixin,
    QRCodeReportMixin,
    GitHubReportMixin,
    QuizReportMixin,
    MetadataReportMixin
):
    """Service pour générer des rapports PDF forensiques professionnels
    
    This class combines all PDF report generation functionality through mixins:
    - PDFReportBase: Common utilities, colors, and helper methods
    - BreachReportMixin: generate_breach_report
    - SecurityReportMixin: generate_security_analysis_report, generate_prompt_analysis_report
    - QRCodeReportMixin: generate_qrcode_analysis_report
    - GitHubReportMixin: generate_github_analysis_report
    - QuizReportMixin: generate_quiz_report
    - MetadataReportMixin: generate_metadata_analysis_report
    """
    pass
