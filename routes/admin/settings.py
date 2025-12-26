"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Parametres du site et metadonnees SEO (admin).
"""

from flask import render_template, request, redirect, url_for, flash
from flask_login import current_user
from models import db, SiteSettings, SEOMetadata
from utils.logging_utils import log_activity
from routes.admin import bp, admin_required
import os
from werkzeug.utils import secure_filename

@bp.route('/settings/site', methods=['GET', 'POST'])
@admin_required
def site_settings():
    """Paramètres du site (configuration technique uniquement)"""
    technical_categories = ['general', 'appearance', 'system', 'advanced', 'seo']
    
    if request.method == 'POST':
        processed_keys = set()
        for key in request.form:
            if key.startswith('setting_'):
                setting_key = key.replace('setting_', '')
                if setting_key in processed_keys:
                    continue
                processed_keys.add(setting_key)
                
                setting = SiteSettings.query.filter_by(key=setting_key).first()
                if setting and setting.category in technical_categories:
                    if setting.value_type == 'boolean':
                        values = request.form.getlist(key)
                        setting.value = 'true' if 'true' in values else 'false'
                    else:
                        setting.value = request.form.get(key)
                    setting.updated_by = current_user.id
        
        for key in request.files:
            if key.startswith('image_'):
                setting_key = key.replace('image_', '')
                file = request.files[key]
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
                    if ext in ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico']:
                        new_filename = f"{setting_key}_{os.urandom(8).hex()}.{ext}"
                        upload_path = os.path.join('static', 'img', 'uploads')
                        os.makedirs(upload_path, exist_ok=True)
                        file_path = os.path.join(upload_path, new_filename)
                        file.save(file_path)
                        
                        setting = SiteSettings.query.filter_by(key=setting_key).first()
                        if setting:
                            setting.value = f"/static/img/uploads/{new_filename}"
                            setting.updated_by = current_user.id
        
        db.session.commit()
        log_activity('ADMIN_SETTINGS_UPDATE', 'Mise à jour paramètres site', success=True)
        flash('Paramètres mis à jour avec succès', 'success')
        return redirect(url_for('admin_panel.site_settings'))
    
    settings = SiteSettings.query.filter(SiteSettings.category.in_(technical_categories)).all()
    log_activity('ADMIN_SETTINGS_VIEW', 'Consultation paramètres site')
    
    return render_template('admin/site_settings.html', settings=settings)

@bp.route('/settings/seo', methods=['GET', 'POST'])
@bp.route('/settings/seo/add', methods=['POST'])
@admin_required
def seo_settings():
    """Paramètres SEO"""
    if request.method == 'POST':
        page_path = request.form.get('page_path')
        seo = SEOMetadata.query.filter_by(page_path=page_path).first()
        
        if not seo:
            seo = SEOMetadata()
            seo.page_path = page_path
            db.session.add(seo)
        
        seo.title = request.form.get('title')
        seo.description = request.form.get('description')
        seo.keywords = request.form.get('keywords')
        seo.og_title = request.form.get('og_title')
        seo.og_description = request.form.get('og_description')
        seo.og_image = request.form.get('og_image')
        seo.canonical_url = request.form.get('canonical_url')
        seo.robots = request.form.get('robots')
        seo.is_active = request.form.get('is_active') == 'on'
        seo.updated_by = current_user.id
        
        db.session.commit()
        log_activity('ADMIN_SEO_UPDATE', f'Mise à jour SEO pour {page_path}', success=True)
        flash(f'Paramètres SEO pour {page_path} mis à jour', 'success')
        return redirect(url_for('admin_panel.seo_settings'))
    
    seo_pages = SEOMetadata.query.all()
    log_activity('ADMIN_SEO_VIEW', 'Consultation paramètres SEO')
    
    return render_template('admin/seo_settings.html', seo_pages=seo_pages)

@bp.route('/settings/seo/edit/<int:seo_id>', methods=['GET', 'POST'])
@admin_required
def seo_edit(seo_id):
    """Éditer une entrée SEO spécifique"""
    seo = SEOMetadata.query.get_or_404(seo_id)
    
    if request.method == 'POST':
        seo.page_path = request.form.get('page_path')
        seo.title = request.form.get('title')
        seo.description = request.form.get('description')
        seo.keywords = request.form.get('keywords')
        seo.og_title = request.form.get('og_title')
        seo.og_description = request.form.get('og_description')
        seo.canonical_url = request.form.get('canonical_url')
        seo.robots = request.form.get('robots')
        seo.is_active = request.form.get('is_active') == 'on'
        seo.updated_by = current_user.id
        
        og_image_file = request.files.get('og_image_file')
        if og_image_file and og_image_file.filename:
            filename = secure_filename(og_image_file.filename)
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            if ext in ['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp']:
                page_path_safe = (seo.page_path or '').replace('/', '_').strip('_')
                new_filename = f"og_{page_path_safe}_{os.urandom(4).hex()}.{ext}"
                upload_path = os.path.join('static', 'img', 'og')
                os.makedirs(upload_path, exist_ok=True)
                file_path = os.path.join(upload_path, new_filename)
                og_image_file.save(file_path)
                seo.og_image = f"/static/img/og/{new_filename}"
            else:
                flash('Format d\'image non supporté. Utilisez PNG, JPG, GIF, SVG ou WebP.', 'warning')
        else:
            og_image_url = request.form.get('og_image')
            if og_image_url:
                seo.og_image = og_image_url
        
        db.session.commit()
        log_activity('ADMIN_SEO_UPDATE', f'Mise à jour SEO pour {seo.page_path}', success=True)
        flash(f'Paramètres SEO pour {seo.page_path} mis à jour avec succès', 'success')
        return redirect(url_for('admin_panel.seo_settings'))
    
    log_activity('ADMIN_SEO_EDIT_VIEW', f'Édition SEO #{seo_id}')
    return render_template('admin/seo_edit.html', seo=seo)

@bp.route('/settings/seo/delete/<int:seo_id>', methods=['POST'])
@admin_required
def seo_delete(seo_id):
    """Supprimer une entrée SEO"""
    seo = SEOMetadata.query.get_or_404(seo_id)
    page_path = seo.page_path
    
    try:
        db.session.delete(seo)
        db.session.commit()
        log_activity('ADMIN_SEO_DELETE', f'Suppression SEO pour {page_path}', success=True)
        flash(f'Entrée SEO pour {page_path} supprimée', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erreur lors de la suppression: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel.seo_settings'))
