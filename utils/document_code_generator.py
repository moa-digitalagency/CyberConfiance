"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier document_code_generator.py du projet CyberConfiance
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

Generateur de codes uniques pour les documents et QR codes de verification.
"""

import secrets
import string
import qrcode
from io import BytesIO
from models import db

def generate_unique_code(length=8, prefix='DOC'):
    """
    Generate a unique alphanumeric code for documents
    
    Args:
        length (int): Length of the random part (default: 8)
        prefix (str): Prefix for the code (default: 'DOC')
    
    Returns:
        str: Unique document code (e.g., DOC-A7B9C3D1)
    """
    alphabet = string.ascii_uppercase + string.digits
    random_part = ''.join(secrets.choice(alphabet) for _ in range(length))
    return f"{prefix}-{random_part}"


def ensure_unique_code(model_class):
    """
    Generate a document code and ensure it's unique in the database
    
    Args:
        model_class: The SQLAlchemy model class (BreachAnalysis, SecurityAnalysis, QuizResult)
    
    Returns:
        str: A unique document code
    """
    max_attempts = 20
    for attempt in range(max_attempts):
        length = 8 if attempt < 10 else 10 + (attempt - 10)
        code = generate_unique_code(length=length)
        
        existing = model_class.query.filter_by(document_code=code).first()
        if not existing:
            return code
    
    raise RuntimeError(f"Failed to generate unique document code after {max_attempts} attempts")


def generate_qr_code(data, box_size=5, border=1):
    """
    Generate a QR code image as bytes
    
    Args:
        data (str): The data to encode in the QR code
        box_size (int): Size of each box in pixels (default: 5)
        border (int): Border size in boxes (default: 1)
    
    Returns:
        bytes: PNG image data of the QR code
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_buffer = BytesIO()
    img.save(img_buffer, format='PNG')
    img_bytes = img_buffer.getvalue()
    
    return img_bytes
