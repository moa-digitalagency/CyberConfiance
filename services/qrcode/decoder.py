"""
 * Nom de l'application : CyberConfiance
 * Description : Fichier decoder.py du projet CyberConfiance
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

Decodeur multi-techniques QR avec support pyzbar.
"""

import io
from ctypes import cdll
import ctypes.util
from PIL import Image
from utils.logger import get_logger

logger = get_logger(__name__)

ZBAR_LIB_PATH = "/nix/store/lcjf0hd46s7b16vr94q3bcas7yg05c3c-zbar-0.23.93-lib/lib/libzbar.so.0"

_original_find_library = ctypes.util.find_library

def _patched_find_library(name):
    if name == 'zbar':
        return ZBAR_LIB_PATH
    return _original_find_library(name)

ctypes.util.find_library = _patched_find_library

try:
    cdll.LoadLibrary(ZBAR_LIB_PATH)
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except (ImportError, OSError) as e:
    PYZBAR_AVAILABLE = False
    def pyzbar_decode(image):
        return None
    logger.warning(f"pyzbar not available: {e}")


def decode_qr_from_image(image_data):
    try:
        if isinstance(image_data, bytes):
            image = Image.open(io.BytesIO(image_data))
        else:
            image = Image.open(image_data)
        
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        result = _decode_with_opencv(image)
        if result:
            return result, None
        
        if PYZBAR_AVAILABLE:
            result = _decode_with_pyzbar(image)
            if result:
                return result, None
        
        return None, "Aucun QR code detecte dans l'image"
        
    except Exception as e:
        return None, f"Erreur lors du decodage: {str(e)}"


def _decode_with_opencv(pil_image):
    """Try to decode QR code using OpenCV's QRCodeDetector"""
    try:
        import cv2
        import numpy as np
        
        img_array = np.array(pil_image)
        img_cv = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
        
        detector = cv2.QRCodeDetector()
        
        data, bbox, _ = detector.detectAndDecode(img_cv)
        if data:
            return data
        
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        data, bbox, _ = detector.detectAndDecode(gray)
        if data:
            return data
        
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        data, bbox, _ = detector.detectAndDecode(enhanced)
        if data:
            return data
        
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        data, bbox, _ = detector.detectAndDecode(binary)
        if data:
            return data
        
        inverted = cv2.bitwise_not(binary)
        data, bbox, _ = detector.detectAndDecode(inverted)
        if data:
            return data
        
        adaptive = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        data, bbox, _ = detector.detectAndDecode(adaptive)
        if data:
            return data
        
        kernel = np.array([[-1,-1,-1], [-1,9,-1], [-1,-1,-1]])
        sharpened = cv2.filter2D(gray, -1, kernel)
        data, bbox, _ = detector.detectAndDecode(sharpened)
        if data:
            return data
        
        height, width = gray.shape
        if width > 1000 or height > 1000:
            scale = 800 / max(width, height)
            resized = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
            data, bbox, _ = detector.detectAndDecode(resized)
            if data:
                return data
        
        if width < 300 or height < 300:
            scale = 2.0
            upscaled = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
            data, bbox, _ = detector.detectAndDecode(upscaled)
            if data:
                return data
        
        return None
    except Exception as e:
        logger.error(f"OpenCV QR detection failed: {e}")
        return None


def _decode_with_pyzbar(pil_image):
    """Fallback to pyzbar with multiple preprocessing attempts"""
    if not PYZBAR_AVAILABLE:
        return None
    
    try:
        from PIL import ImageEnhance, ImageFilter
        
        decoded = pyzbar_decode(pil_image)
        if decoded:
            for obj in decoded:
                if obj.type == 'QRCODE':
                    return obj.data.decode('utf-8')
            return decoded[0].data.decode('utf-8')
        
        gray = pil_image.convert('L')
        decoded = pyzbar_decode(gray)
        if decoded:
            for obj in decoded:
                if obj.type == 'QRCODE':
                    return obj.data.decode('utf-8')
            return decoded[0].data.decode('utf-8')
        
        enhancer = ImageEnhance.Contrast(gray)
        for factor in [1.5, 2.0, 2.5]:
            enhanced = enhancer.enhance(factor)
            decoded = pyzbar_decode(enhanced)
            if decoded:
                for obj in decoded:
                    if obj.type == 'QRCODE':
                        return obj.data.decode('utf-8')
                return decoded[0].data.decode('utf-8')
        
        sharpened = gray.filter(ImageFilter.SHARPEN)
        decoded = pyzbar_decode(sharpened)
        if decoded:
            for obj in decoded:
                if obj.type == 'QRCODE':
                    return obj.data.decode('utf-8')
            return decoded[0].data.decode('utf-8')
        
        threshold = 128
        binary = gray.point(lambda x: 255 if x > threshold else 0, mode='1')
        decoded = pyzbar_decode(binary)
        if decoded:
            for obj in decoded:
                if obj.type == 'QRCODE':
                    return obj.data.decode('utf-8')
            return decoded[0].data.decode('utf-8')
        
        from PIL import ImageOps
        inverted = ImageOps.invert(gray)
        decoded = pyzbar_decode(inverted)
        if decoded:
            for obj in decoded:
                if obj.type == 'QRCODE':
                    return obj.data.decode('utf-8')
            return decoded[0].data.decode('utf-8')
        
        return None
    except Exception as e:
        logger.error(f"Pyzbar detection failed: {e}")
        return None
