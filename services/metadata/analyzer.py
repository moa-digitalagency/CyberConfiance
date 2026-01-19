"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Service d'analyse et de suppression des metadonnees pour images et videos.
Supporte: JPEG, PNG, GIF, TIFF, WebP, MP4, MOV, AVI, MKV, MP3, WAV, etc.
"""

import os
import io
import subprocess
import tempfile
import json
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import exifread
import piexif
from mutagen import File as MutagenFile
from mutagen.mp4 import MP4
from mutagen.id3 import ID3
from datetime import datetime


class MetadataAnalyzerService:
    
    SUPPORTED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.tiff', '.tif', '.webp', '.bmp', '.heic', '.heif'}
    SUPPORTED_VIDEO_EXTENSIONS = {'.mp4', '.mov', '.avi', '.mkv', '.wmv', '.flv', '.webm', '.m4v', '.3gp'}
    SUPPORTED_AUDIO_EXTENSIONS = {'.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a'}
    
    METADATA_TRANSLATIONS = {
        'Make': 'Marque',
        'Model': 'Modele',
        'Software': 'Logiciel',
        'DateTime': 'Date et Heure',
        'DateTimeOriginal': 'Date de Prise de Vue',
        'DateTimeDigitized': 'Date de Numerisation',
        'Artist': 'Artiste',
        'Author': 'Auteur',
        'Creator': 'Createur',
        'Copyright': 'Droits d\'Auteur',
        'OwnerName': 'Nom du Proprietaire',
        'CameraOwnerName': 'Proprietaire de l\'Appareil',
        'GPSLatitude': 'Latitude GPS',
        'GPSLongitude': 'Longitude GPS',
        'GPSAltitude': 'Altitude GPS',
        'GPSLatitudeRef': 'Reference Latitude',
        'GPSLongitudeRef': 'Reference Longitude',
        'ExposureTime': 'Temps d\'Exposition',
        'FNumber': 'Ouverture (f/)',
        'ISOSpeedRatings': 'Sensibilite ISO',
        'FocalLength': 'Longueur Focale',
        'FocalLengthIn35mmFilm': 'Focale Equivalente 35mm',
        'Flash': 'Flash',
        'WhiteBalance': 'Balance des Blancs',
        'ExposureMode': 'Mode d\'Exposition',
        'MeteringMode': 'Mode de Mesure',
        'Orientation': 'Orientation',
        'ResolutionUnit': 'Unite de Resolution',
        'XResolution': 'Resolution Horizontale',
        'YResolution': 'Resolution Verticale',
        'ImageWidth': 'Largeur de l\'Image',
        'ImageHeight': 'Hauteur de l\'Image',
        'ImageLength': 'Longueur de l\'Image',
        'BitsPerSample': 'Bits par Echantillon',
        'ColorSpace': 'Espace Colorimetrique',
        'Compression': 'Compression',
        'LensModel': 'Modele d\'Objectif',
        'LensMake': 'Marque d\'Objectif',
        'CameraSerialNumber': 'Numero de Serie',
        'BodySerialNumber': 'Numero de Serie du Boitier',
        'ShutterSpeedValue': 'Vitesse d\'Obturation',
        'ApertureValue': 'Valeur d\'Ouverture',
        'BrightnessValue': 'Luminosite',
        'ExposureBiasValue': 'Correction d\'Exposition',
        'MaxApertureValue': 'Ouverture Maximale',
        'SubjectDistance': 'Distance du Sujet',
        'LightSource': 'Source de Lumiere',
        'SceneType': 'Type de Scene',
        'DigitalZoomRatio': 'Zoom Numerique',
        'Contrast': 'Contraste',
        'Saturation': 'Saturation',
        'Sharpness': 'Nettete',
        'ImageDescription': 'Description de l\'Image',
        'UserComment': 'Commentaire Utilisateur',
        'ExifVersion': 'Version EXIF',
        'ComponentsConfiguration': 'Configuration des Composants',
        'FlashpixVersion': 'Version Flashpix',
        'PixelXDimension': 'Dimension X en Pixels',
        'PixelYDimension': 'Dimension Y en Pixels',
        'CreateDate': 'Date de Creation',
        'ModifyDate': 'Date de Modification',
        'FileSize': 'Taille du Fichier',
        'FileType': 'Type de Fichier',
        'MIMEType': 'Type MIME',
        'Duration': 'Duree',
        'BitRate': 'Debit Binaire',
        'AudioBitRate': 'Debit Audio',
        'VideoBitRate': 'Debit Video',
        'FrameRate': 'Images par Seconde',
        'VideoCodec': 'Codec Video',
        'AudioCodec': 'Codec Audio',
        'SampleRate': 'Frequence d\'Echantillonnage',
        'Channels': 'Canaux Audio',
        'Title': 'Titre',
        'Album': 'Album',
        'Genre': 'Genre',
        'Year': 'Annee',
        'Track': 'Piste',
        'Comment': 'Commentaire',
        'Encoder': 'Encodeur',
        'EncodedBy': 'Encode Par',
        'Location': 'Localisation',
        'City': 'Ville',
        'Country': 'Pays',
        'State': 'Etat/Province',
        'Width': 'Largeur',
        'Height': 'Hauteur',
        'Bit Depth': 'Profondeur de Bits',
        'Sample Rate': 'Frequence d\'Echantillonnage',
    }
    
    SENSITIVE_TAGS = {
        'gps': ['GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'GPS GPSLatitude', 'GPS GPSLongitude', 
                'GPSLatitudeRef', 'GPSLongitudeRef', 'GPS GPSLatitudeRef', 'GPS GPSLongitudeRef',
                'GPSInfo', 'GPS Position'],
        'personal': ['Artist', 'Author', 'Creator', 'Copyright', 'OwnerName', 'CameraOwnerName',
                     'Image Artist', 'XMP:Creator', 'IPTC:By-line', 'XMP:Rights'],
        'device': ['Make', 'Model', 'Software', 'CameraSerialNumber', 'LensModel', 'LensMake',
                   'Image Make', 'Image Model', 'EXIF LensModel', 'BodySerialNumber'],
        'datetime': ['DateTimeOriginal', 'CreateDate', 'ModifyDate', 'DateTimeDigitized',
                     'EXIF DateTimeOriginal', 'EXIF DateTimeDigitized', 'Image DateTime'],
        'location': ['LocationName', 'City', 'Country', 'State', 'Province', 'XMP:Location']
    }
    
    @classmethod
    def get_file_type(cls, filename):
        ext = os.path.splitext(filename.lower())[1]
        if ext in cls.SUPPORTED_IMAGE_EXTENSIONS:
            return 'image'
        elif ext in cls.SUPPORTED_VIDEO_EXTENSIONS:
            return 'video'
        elif ext in cls.SUPPORTED_AUDIO_EXTENSIONS:
            return 'audio'
        return None
    
    @classmethod
    def analyze_file(cls, file_data, filename):
        file_type = cls.get_file_type(filename)
        
        if not file_type:
            return {
                'success': False,
                'error': f"Type de fichier non supporte. Extensions supportees: Images ({', '.join(cls.SUPPORTED_IMAGE_EXTENSIONS)}), Videos ({', '.join(cls.SUPPORTED_VIDEO_EXTENSIONS)}), Audio ({', '.join(cls.SUPPORTED_AUDIO_EXTENSIONS)})"
            }
        
        result = {
            'success': True,
            'filename': filename,
            'file_type': file_type,
            'file_size': len(file_data),
            'metadata': {},
            'metadata_count': 0,
            'sensitive_data': [],
            'privacy_risk': 'low',
            'gps_data': None,
            'camera_info': None,
            'software_info': None,
            'datetime_info': None,
            'author_info': None,
            'categories': {}
        }
        
        try:
            if file_type == 'image':
                metadata = cls._analyze_image(file_data, filename)
            elif file_type == 'video':
                metadata = cls._analyze_video(file_data, filename)
            elif file_type == 'audio':
                metadata = cls._analyze_audio(file_data, filename)
            else:
                metadata = {}
            
            result['metadata'] = metadata
            result['metadata_count'] = len(metadata)
            
            sensitive_data, privacy_risk = cls._assess_privacy_risk(metadata)
            result['sensitive_data'] = sensitive_data
            result['privacy_risk'] = privacy_risk
            
            result['gps_data'] = cls._extract_gps_data(metadata)
            result['camera_info'] = cls._extract_camera_info(metadata)
            result['software_info'] = cls._extract_software_info(metadata)
            result['datetime_info'] = cls._extract_datetime_info(metadata)
            result['author_info'] = cls._extract_author_info(metadata)
            
            result['categories'] = cls._categorize_metadata(metadata)
            
        except Exception as e:
            result['error'] = str(e)
            result['success'] = False
        
        return result
    
    @classmethod
    def _analyze_image(cls, file_data, filename):
        metadata = {}
        
        try:
            img_io = io.BytesIO(file_data)
            tags = exifread.process_file(img_io, details=True)
            
            for tag, value in tags.items():
                if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                    try:
                        str_value = str(value)
                        if len(str_value) < 1000:
                            metadata[tag] = str_value
                    except:
                        pass
        except Exception as e:
            metadata['_exifread_error'] = str(e)
        
        try:
            img_io = io.BytesIO(file_data)
            img = Image.open(img_io)
            
            metadata['_image_format'] = img.format
            metadata['_image_mode'] = img.mode
            metadata['_image_size'] = f"{img.width}x{img.height}"
            
            if hasattr(img, '_getexif') and img._getexif():
                exif_data = img._getexif()
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name == 'GPSInfo':
                        gps_data = {}
                        for gps_tag_id, gps_value in value.items():
                            gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                            try:
                                gps_data[gps_tag_name] = str(gps_value)
                            except:
                                pass
                        metadata['GPSInfo'] = gps_data
                    else:
                        try:
                            str_value = str(value)
                            if len(str_value) < 1000:
                                metadata[f'PIL_{tag_name}'] = str_value
                        except:
                            pass
            
            if img.info:
                for key, value in img.info.items():
                    if key not in ('icc_profile', 'exif'):
                        try:
                            str_value = str(value)
                            if len(str_value) < 1000:
                                metadata[f'_info_{key}'] = str_value
                        except:
                            pass
                            
        except Exception as e:
            metadata['_pil_error'] = str(e)
        
        try:
            with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1], delete=False) as tmp:
                tmp.write(file_data)
                tmp_path = tmp.name
            
            try:
                result = subprocess.run(
                    ['exiftool', '-json', '-all', tmp_path],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0 and result.stdout:
                    exiftool_data = json.loads(result.stdout)
                    if exiftool_data and len(exiftool_data) > 0:
                        for key, value in exiftool_data[0].items():
                            if key not in ('SourceFile', 'Directory', 'FileName'):
                                try:
                                    str_value = str(value)
                                    if len(str_value) < 1000:
                                        metadata[f'ExifTool_{key}'] = str_value
                                except:
                                    pass
            finally:
                os.unlink(tmp_path)
        except Exception as e:
            metadata['_exiftool_error'] = str(e)
        
        return metadata
    
    @classmethod
    def _analyze_video(cls, file_data, filename):
        metadata = {}
        
        try:
            with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1], delete=False) as tmp:
                tmp.write(file_data)
                tmp_path = tmp.name
            
            try:
                audio_file = MutagenFile(tmp_path)
                if audio_file:
                    if hasattr(audio_file, 'tags') and audio_file.tags:
                        for key in audio_file.tags.keys():
                            try:
                                value = audio_file.tags[key]
                                str_value = str(value)
                                if len(str_value) < 1000:
                                    metadata[f'Mutagen_{key}'] = str_value
                            except:
                                pass
                    
                    if hasattr(audio_file, 'info'):
                        info = audio_file.info
                        if hasattr(info, 'length'):
                            metadata['_duration'] = f"{info.length:.2f} seconds"
                        if hasattr(info, 'bitrate'):
                            metadata['_bitrate'] = f"{info.bitrate} bps"
                        if hasattr(info, 'sample_rate'):
                            metadata['_sample_rate'] = f"{info.sample_rate} Hz"
            except:
                pass
            
            try:
                result = subprocess.run(
                    ['exiftool', '-json', '-all', tmp_path],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout:
                    exiftool_data = json.loads(result.stdout)
                    if exiftool_data and len(exiftool_data) > 0:
                        for key, value in exiftool_data[0].items():
                            if key not in ('SourceFile', 'Directory', 'FileName'):
                                try:
                                    str_value = str(value)
                                    if len(str_value) < 1000:
                                        metadata[f'ExifTool_{key}'] = str_value
                                except:
                                    pass
            except:
                pass
            
            try:
                result = subprocess.run(
                    ['ffprobe', '-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', tmp_path],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout:
                    ffprobe_data = json.loads(result.stdout)
                    
                    if 'format' in ffprobe_data:
                        fmt = ffprobe_data['format']
                        metadata['_format_name'] = fmt.get('format_name', '')
                        metadata['_format_long_name'] = fmt.get('format_long_name', '')
                        if 'duration' in fmt:
                            metadata['_duration'] = f"{float(fmt['duration']):.2f} seconds"
                        if 'size' in fmt:
                            metadata['_file_size'] = f"{int(fmt['size'])} bytes"
                        if 'bit_rate' in fmt:
                            metadata['_bit_rate'] = f"{int(fmt['bit_rate'])} bps"
                        
                        if 'tags' in fmt:
                            for key, value in fmt['tags'].items():
                                metadata[f'FFprobe_{key}'] = str(value)
                    
                    if 'streams' in ffprobe_data:
                        for i, stream in enumerate(ffprobe_data['streams']):
                            codec_type = stream.get('codec_type', 'unknown')
                            metadata[f'_stream_{i}_type'] = codec_type
                            metadata[f'_stream_{i}_codec'] = stream.get('codec_name', '')
                            
                            if codec_type == 'video':
                                metadata['_video_width'] = stream.get('width', '')
                                metadata['_video_height'] = stream.get('height', '')
                                metadata['_video_codec'] = stream.get('codec_name', '')
                            elif codec_type == 'audio':
                                metadata['_audio_codec'] = stream.get('codec_name', '')
                                metadata['_audio_channels'] = stream.get('channels', '')
                            
                            if 'tags' in stream:
                                for key, value in stream['tags'].items():
                                    metadata[f'FFprobe_stream{i}_{key}'] = str(value)
            except:
                pass
            
            os.unlink(tmp_path)
            
        except Exception as e:
            metadata['_error'] = str(e)
        
        return metadata
    
    @classmethod
    def _analyze_audio(cls, file_data, filename):
        metadata = {}
        
        try:
            with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1], delete=False) as tmp:
                tmp.write(file_data)
                tmp_path = tmp.name
            
            try:
                audio_file = MutagenFile(tmp_path)
                if audio_file:
                    if hasattr(audio_file, 'tags') and audio_file.tags:
                        for key in audio_file.tags.keys():
                            try:
                                value = audio_file.tags[key]
                                str_value = str(value)
                                if len(str_value) < 1000:
                                    metadata[f'Audio_{key}'] = str_value
                            except:
                                pass
                    
                    if hasattr(audio_file, 'info'):
                        info = audio_file.info
                        if hasattr(info, 'length'):
                            metadata['_duration'] = f"{info.length:.2f} seconds"
                        if hasattr(info, 'bitrate'):
                            metadata['_bitrate'] = f"{info.bitrate} bps"
                        if hasattr(info, 'sample_rate'):
                            metadata['_sample_rate'] = f"{info.sample_rate} Hz"
                        if hasattr(info, 'channels'):
                            metadata['_channels'] = str(info.channels)
            except:
                pass
            
            try:
                result = subprocess.run(
                    ['exiftool', '-json', '-all', tmp_path],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0 and result.stdout:
                    exiftool_data = json.loads(result.stdout)
                    if exiftool_data and len(exiftool_data) > 0:
                        for key, value in exiftool_data[0].items():
                            if key not in ('SourceFile', 'Directory', 'FileName'):
                                try:
                                    str_value = str(value)
                                    if len(str_value) < 1000:
                                        metadata[f'ExifTool_{key}'] = str_value
                                except:
                                    pass
            except:
                pass
            
            os.unlink(tmp_path)
            
        except Exception as e:
            metadata['_error'] = str(e)
        
        return metadata
    
    @classmethod
    def _assess_privacy_risk(cls, metadata):
        sensitive_data = []
        risk_score = 0
        
        metadata_str = ' '.join([f"{k} {v}" for k, v in metadata.items()]).lower()
        
        for tag in cls.SENSITIVE_TAGS['gps']:
            if tag.lower() in metadata_str:
                sensitive_data.append({'type': 'GPS', 'tag': tag, 'risk': 'high'})
                risk_score += 30
        
        for tag in cls.SENSITIVE_TAGS['personal']:
            if tag.lower() in metadata_str:
                sensitive_data.append({'type': 'Personnel', 'tag': tag, 'risk': 'medium'})
                risk_score += 15
        
        for tag in cls.SENSITIVE_TAGS['device']:
            if tag.lower() in metadata_str:
                sensitive_data.append({'type': 'Appareil', 'tag': tag, 'risk': 'medium'})
                risk_score += 10
        
        for tag in cls.SENSITIVE_TAGS['datetime']:
            if tag.lower() in metadata_str:
                sensitive_data.append({'type': 'Date/Heure', 'tag': tag, 'risk': 'low'})
                risk_score += 5
        
        for tag in cls.SENSITIVE_TAGS['location']:
            if tag.lower() in metadata_str:
                sensitive_data.append({'type': 'Localisation', 'tag': tag, 'risk': 'high'})
                risk_score += 25
        
        if risk_score >= 50:
            privacy_risk = 'high'
        elif risk_score >= 20:
            privacy_risk = 'medium'
        else:
            privacy_risk = 'low'
        
        return sensitive_data, privacy_risk
    
    @classmethod
    def _translate_key(cls, key):
        clean_key = key
        for prefix in ['EXIF ', 'Image ', 'PIL_', 'ExifTool_', 'FFprobe_', 'Audio_', 'GPS ']:
            if clean_key.startswith(prefix):
                clean_key = clean_key[len(prefix):]
                break
        
        if clean_key in cls.METADATA_TRANSLATIONS:
            return cls.METADATA_TRANSLATIONS[clean_key]
        
        words = []
        current_word = []
        for char in clean_key:
            if char.isupper() and current_word:
                words.append(''.join(current_word))
                current_word = [char]
            elif char in ('_', '-', ' '):
                if current_word:
                    words.append(''.join(current_word))
                    current_word = []
            else:
                current_word.append(char)
        if current_word:
            words.append(''.join(current_word))
        
        return ' '.join(word.capitalize() for word in words if word)
    
    @classmethod
    def _extract_gps_data(cls, metadata):
        gps_data = {}
        
        for key, value in metadata.items():
            key_lower = key.lower()
            if 'gps' in key_lower or 'latitude' in key_lower or 'longitude' in key_lower:
                translated_key = cls._translate_key(key)
                gps_data[translated_key] = value
        
        if 'GPSInfo' in metadata and isinstance(metadata['GPSInfo'], dict):
            for k, v in metadata['GPSInfo'].items():
                translated_key = cls._translate_key(k)
                gps_data[translated_key] = v
        
        return gps_data if gps_data else None
    
    @classmethod
    def _extract_camera_info(cls, metadata):
        camera_info = {}
        
        camera_keys = ['make', 'model', 'lens', 'serial', 'camera', 'exposure', 'aperture', 
                       'iso', 'focal', 'flash', 'shutter', 'f-number', 'fnumber']
        
        for key, value in metadata.items():
            key_lower = key.lower()
            if any(ck in key_lower for ck in camera_keys):
                translated_key = cls._translate_key(key)
                camera_info[translated_key] = value
        
        return camera_info if camera_info else None
    
    @classmethod
    def _extract_software_info(cls, metadata):
        software_info = {}
        
        software_keys = ['software', 'creator', 'tool', 'program', 'application', 'processor', 'encoder']
        
        for key, value in metadata.items():
            key_lower = key.lower()
            if any(sk in key_lower for sk in software_keys):
                translated_key = cls._translate_key(key)
                software_info[translated_key] = value
        
        return software_info if software_info else None
    
    @classmethod
    def _extract_datetime_info(cls, metadata):
        datetime_info = {}
        
        datetime_keys = ['date', 'time', 'created', 'modified', 'original']
        
        for key, value in metadata.items():
            key_lower = key.lower()
            if any(dk in key_lower for dk in datetime_keys):
                translated_key = cls._translate_key(key)
                datetime_info[translated_key] = value
        
        return datetime_info if datetime_info else None
    
    @classmethod
    def _extract_author_info(cls, metadata):
        author_info = {}
        
        author_keys = ['author', 'artist', 'creator', 'owner', 'copyright', 'rights', 'by-line']
        
        for key, value in metadata.items():
            key_lower = key.lower()
            if any(ak in key_lower for ak in author_keys):
                translated_key = cls._translate_key(key)
                author_info[translated_key] = value
        
        return author_info if author_info else None
    
    @classmethod
    def _categorize_metadata(cls, metadata):
        categories = {
            'Informations Fichier': {},
            'Informations Image/Video': {},
            'Appareil Photo/Camera': {},
            'GPS/Localisation': {},
            'Dates et Heures': {},
            'Auteur/Copyright': {},
            'Logiciel': {},
            'Autres': {}
        }
        
        for key, value in metadata.items():
            translated_key = cls._translate_key(key)
            
            if key.startswith('_'):
                display_key = cls._translate_key(key.lstrip('_'))
                categories['Informations Fichier'][display_key] = value
            elif any(k in key.lower() for k in ['gps', 'latitude', 'longitude', 'location', 'city', 'country']):
                categories['GPS/Localisation'][translated_key] = value
            elif any(k in key.lower() for k in ['make', 'model', 'lens', 'camera', 'exposure', 'aperture', 'iso', 'focal']):
                categories['Appareil Photo/Camera'][translated_key] = value
            elif any(k in key.lower() for k in ['date', 'time', 'created', 'modified']):
                categories['Dates et Heures'][translated_key] = value
            elif any(k in key.lower() for k in ['author', 'artist', 'creator', 'owner', 'copyright']):
                categories['Auteur/Copyright'][translated_key] = value
            elif any(k in key.lower() for k in ['software', 'tool', 'program', 'application', 'encoder']):
                categories['Logiciel'][translated_key] = value
            elif any(k in key.lower() for k in ['width', 'height', 'resolution', 'dimension', 'codec', 'format', 'bitrate']):
                categories['Informations Image/Video'][translated_key] = value
            else:
                categories['Autres'][translated_key] = value
        
        return {k: v for k, v in categories.items() if v}
    
    @classmethod
    def remove_metadata(cls, file_data, filename):
        file_type = cls.get_file_type(filename)
        
        if not file_type:
            return None, "Type de fichier non supporte"
        
        tmp_in_path = None
        tmp_out_path = None
        
        try:
            with tempfile.NamedTemporaryFile(suffix=os.path.splitext(filename)[1], delete=False) as tmp_in:
                tmp_in.write(file_data)
                tmp_in_path = tmp_in.name
            
            base, ext = os.path.splitext(filename)
            clean_filename = f"{base}_nettoye{ext}"
            
            tmp_out_path = tempfile.mktemp(suffix=ext)
            
            try:
                result = subprocess.run(
                    ['exiftool', '-all=', '-o', tmp_out_path, tmp_in_path],
                    capture_output=True, text=True, timeout=120
                )
                
                if result.returncode == 0 and os.path.exists(tmp_out_path) and os.path.getsize(tmp_out_path) > 0:
                    with open(tmp_out_path, 'rb') as f:
                        clean_data = f.read()
                    
                    os.unlink(tmp_in_path)
                    os.unlink(tmp_out_path)
                    return clean_data, clean_filename
                
                if file_type == 'image' and ext.lower() not in ['.heic', '.heif']:
                    try:
                        img = Image.open(io.BytesIO(file_data))
                        clean_img = Image.new(img.mode, img.size)
                        clean_img.paste(img)
                        
                        output = io.BytesIO()
                        if ext.lower() in ['.jpg', '.jpeg']:
                            clean_img.save(output, format='JPEG', quality=95)
                        elif ext.lower() == '.png':
                            clean_img.save(output, format='PNG')
                        elif ext.lower() == '.gif':
                            clean_img.save(output, format='GIF')
                        elif ext.lower() == '.webp':
                            clean_img.save(output, format='WEBP', quality=95)
                        else:
                            clean_img.save(output, format=img.format or 'JPEG')
                        
                        os.unlink(tmp_in_path)
                        if os.path.exists(tmp_out_path):
                            os.unlink(tmp_out_path)
                        
                        return output.getvalue(), clean_filename
                    except Exception:
                        pass
                
                elif file_type == 'video':
                    result = subprocess.run(
                        ['ffmpeg', '-i', tmp_in_path, '-map_metadata', '-1', 
                         '-c:v', 'copy', '-c:a', 'copy', '-y', tmp_out_path],
                        capture_output=True, text=True, timeout=300
                    )
                    if result.returncode == 0 and os.path.exists(tmp_out_path):
                        with open(tmp_out_path, 'rb') as f:
                            clean_data = f.read()
                        os.unlink(tmp_in_path)
                        os.unlink(tmp_out_path)
                        return clean_data, clean_filename
                        
                elif file_type == 'audio':
                    result = subprocess.run(
                        ['ffmpeg', '-i', tmp_in_path, '-map_metadata', '-1',
                         '-c:a', 'copy', '-y', tmp_out_path],
                        capture_output=True, text=True, timeout=120
                    )
                    if result.returncode == 0 and os.path.exists(tmp_out_path):
                        with open(tmp_out_path, 'rb') as f:
                            clean_data = f.read()
                        os.unlink(tmp_in_path)
                        os.unlink(tmp_out_path)
                        return clean_data, clean_filename
                
                raise Exception("Impossible de nettoyer les metadonnees avec les outils disponibles")
                
            except Exception as e:
                raise e
                
        except Exception as e:
            return None, f"Erreur lors de la suppression des metadonnees: {str(e)}"
        finally:
            if tmp_in_path and os.path.exists(tmp_in_path):
                try:
                    os.unlink(tmp_in_path)
                except:
                    pass
            if tmp_out_path and os.path.exists(tmp_out_path):
                try:
                    os.unlink(tmp_out_path)
                except:
                    pass
