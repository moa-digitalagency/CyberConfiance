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

Gestion du contenu admin: blog, newsletter, contacts.
"""

from flask import render_template, request, redirect, url_for, flash
from flask_login import current_user
from models import (db, QuizResult, SecurityAnalysis, BreachAnalysis, 
                    SiteSettings, News, Newsletter, Contact)
from utils.logging_utils import log_activity
from datetime import datetime
from sqlalchemy import desc, text, literal
from routes.admin import bp, admin_required, moderator_required

@bp.route('/blog')
@moderator_required
def blog_management():
    """Gestion des articles de blog"""
    log_activity('ADMIN_BLOG_VIEW', 'Consultation gestion blog')
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    category = request.args.get('category', '')
    source = request.args.get('source', '')
    
    query = News.query
    
    if category:
        query = query.filter(News.category == category)
    
    if source:
        query = query.filter(News.source == source)
    
    articles = query.order_by(desc(News.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    categories = db.session.query(News.category).distinct().all()
    categories = [cat[0] for cat in categories if cat[0]]
    sources = db.session.query(News.source).distinct().all()
    sources = [src[0] for src in sources if src[0]]
    
    return render_template('admin/blog.html', articles=articles, categories=categories, sources=sources, selected_category=category, selected_source=source)

@bp.route('/newsletter')
@moderator_required
def newsletter_management():
    """Liste des inscriptions newsletter"""
    log_activity('ADMIN_NEWSLETTER_VIEW', 'Consultation inscriptions newsletter')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    subscribed_only = request.args.get('subscribed', 'true')
    
    query = Newsletter.query
    
    if subscribed_only == 'true':
        query = query.filter(Newsletter.subscribed == True)
    
    subscriptions = query.order_by(desc(Newsletter.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    total_subscribed = Newsletter.query.filter(Newsletter.subscribed == True).count()
    
    return render_template('admin/newsletter.html', subscriptions=subscriptions, total_subscribed=total_subscribed, subscribed_only=subscribed_only)

@bp.route('/contacts')
@moderator_required
def contact_management():
    """Liste des messages de contact"""
    log_activity('ADMIN_CONTACTS_VIEW', 'Consultation messages contact')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    status = request.args.get('status', '')
    
    query = Contact.query
    
    if status:
        query = query.filter(Contact.status == status)
    
    contacts = query.order_by(desc(Contact.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/contacts.html', contacts=contacts, status=status)

@bp.route('/contacts/<int:contact_id>')
@moderator_required
def contact_detail(contact_id):
    """Voir les détails d'un message de contact"""
    contact = Contact.query.get_or_404(contact_id)
    log_activity('ADMIN_CONTACT_DETAIL_VIEW', f'Consultation détails contact #{contact_id}')
    return render_template('admin/contact_detail.html', contact=contact)

@bp.route('/contacts/<int:contact_id>/delete', methods=['POST'])
@moderator_required
def delete_contact(contact_id):
    """Supprimer un message de contact"""
    contact = Contact.query.get_or_404(contact_id)
    try:
        db.session.delete(contact)
        db.session.commit()
        log_activity('ADMIN_CONTACT_DELETE', f'Suppression contact #{contact_id}')
        flash('Message de contact supprimé avec succès.', 'success')
    except Exception as e:
        db.session.rollback()
        log_activity('ADMIN_CONTACT_DELETE_ERROR', f'Erreur suppression contact #{contact_id}: {str(e)}')
        flash(f'Erreur lors de la suppression: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel.contact_management'))

@bp.route('/contacts/send', methods=['POST'])
@moderator_required
def send_contact_message():
    """Envoyer un message aux contacts sélectionnés"""
    recipients = request.form.get('recipients', '')
    subject = request.form.get('subject', '')
    message = request.form.get('message', '')
    
    if not recipients or not subject or not message:
        flash('Tous les champs sont requis', 'danger')
        return redirect(url_for('admin_panel.contact_management'))
    
    log_activity('ADMIN_CONTACT_MESSAGE_SEND', f'Envoi message à {recipients}', success=True)
    flash(f'Message envoyé à {recipients} (fonctionnalité de démonstration - implémentez l\'envoi d\'emails réel)', 'success')
    
    return redirect(url_for('admin_panel.contact_management'))

@bp.route('/content')
@moderator_required
def content_management():
    """Liste des pages dont le contenu peut être édité"""
    log_activity('ADMIN_CONTENT_MANAGEMENT_VIEW', 'Consultation gestion contenu')
    
    pages = [
        {'slug': 'home', 'name': 'Page d\'accueil'},
        {'slug': 'about', 'name': 'À propos'},
        {'slug': 'services', 'name': 'Services (général)'},
        {'slug': 'services_sensibilisation', 'name': 'Service Sensibilisation'},
        {'slug': 'services_factchecking', 'name': 'Service Fact-checking'},
        {'slug': 'services_cyberconsultation', 'name': 'Service Cyber-consultation'},
        {'slug': 'contact', 'name': 'Contact'},
        {'slug': 'news', 'name': 'Actualités'}
    ]
    
    return render_template('admin/content.html', pages=pages)

@bp.route('/content/edit/<page>', methods=['GET', 'POST'])
@moderator_required
def edit_page_content(page):
    """Édition du contenu d'une page"""
    page_names = {
        'home': 'Page d\'accueil',
        'about': 'À propos',
        'services': 'Services (général)',
        'services_sensibilisation': 'Service Sensibilisation',
        'services_factchecking': 'Service Fact-checking',
        'services_cyberconsultation': 'Service Cyber-consultation',
        'contact': 'Contact',
        'news': 'Actualités'
    }
    
    if page not in page_names:
        flash('Page non trouvée', 'danger')
        return redirect(url_for('admin_panel.content_management'))
    
    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('setting_'):
                setting_key = key.replace('setting_', '')
                setting = SiteSettings.query.filter_by(key=setting_key, category=page).first()
                if setting:
                    setting.value = value
                    setting.updated_by = current_user.id
                else:
                    setting = SiteSettings()
                    setting.key = setting_key
                    setting.value = value
                    setting.category = page
                    setting.updated_by = current_user.id
                    db.session.add(setting)
        
        db.session.commit()
        log_activity('ADMIN_PAGE_CONTENT_UPDATE', f'Mise à jour contenu page {page}', success=True)
        flash(f'Contenu de la page {page_names[page]} mis à jour avec succès', 'success')
        return redirect(url_for('admin_panel.edit_page_content', page=page))
    
    settings = SiteSettings.query.filter_by(category=page).all()
    log_activity('ADMIN_PAGE_CONTENT_VIEW', f'Consultation contenu page {page}')
    
    return render_template('admin/edit_page_content.html', 
                         page=page, 
                         page_name=page_names[page], 
                         settings=settings)

@bp.route('/news/new', methods=['GET', 'POST'])
@moderator_required
def news_new():
    """Créer un nouvel article"""
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            content = request.form.get('content')
            category = request.form.get('category', 'Général')
            source = request.form.get('source', '')
            url = request.form.get('url', '')
            published_date_str = request.form.get('published_date')
            
            if not title or not content:
                flash('Le titre et le contenu sont obligatoires', 'danger')
                return redirect(url_for('admin_panel.news_new'))
            
            news = News()
            news.title = title
            news.content = content
            news.category = category
            news.source = source
            news.url = url
            
            if published_date_str:
                try:
                    news.published_date = datetime.strptime(published_date_str, '%Y-%m-%d')
                except:
                    news.published_date = datetime.utcnow()
            else:
                news.published_date = datetime.utcnow()
            
            db.session.add(news)
            db.session.commit()
            
            log_activity('ADMIN_NEWS_CREATE', f'Création article: {title}', success=True)
            flash('Article créé avec succès', 'success')
            return redirect(url_for('admin_panel.blog_management'))
        except Exception as e:
            db.session.rollback()
            log_activity('ADMIN_NEWS_CREATE', f'Erreur création article', success=False, error_message=str(e))
            flash(f'Erreur lors de la création: {str(e)}', 'danger')
            return redirect(url_for('admin_panel.news_new'))
    
    return render_template('admin/news_form.html', news=None, action='new')

@bp.route('/news/edit/<int:id>', methods=['GET', 'POST'])
@moderator_required
def news_edit(id):
    """Éditer un article existant"""
    news = News.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            news.title = request.form.get('title')
            news.content = request.form.get('content')
            news.category = request.form.get('category', 'Général')
            news.source = request.form.get('source', '')
            news.url = request.form.get('url', '')
            published_date_str = request.form.get('published_date')
            
            if not news.title or not news.content:
                flash('Le titre et le contenu sont obligatoires', 'danger')
                return redirect(url_for('admin_panel.news_edit', id=id))
            
            if published_date_str:
                try:
                    news.published_date = datetime.strptime(published_date_str, '%Y-%m-%d')
                except:
                    pass
            
            db.session.commit()
            
            log_activity('ADMIN_NEWS_UPDATE', f'Modification article: {news.title}', success=True)
            flash('Article modifié avec succès', 'success')
            return redirect(url_for('admin_panel.blog_management'))
        except Exception as e:
            db.session.rollback()
            log_activity('ADMIN_NEWS_UPDATE', f'Erreur modification article', success=False, error_message=str(e))
            flash(f'Erreur lors de la modification: {str(e)}', 'danger')
            return redirect(url_for('admin_panel.news_edit', id=id))
    
    return render_template('admin/news_form.html', news=news, action='edit')

@bp.route('/news/delete/<int:id>', methods=['POST'])
@moderator_required
def news_delete(id):
    """Supprimer un article"""
    try:
        news = News.query.get_or_404(id)
        title = news.title
        
        db.session.delete(news)
        db.session.commit()
        
        log_activity('ADMIN_NEWS_DELETE', f'Suppression article: {title}', success=True)
        flash('Article supprimé avec succès', 'success')
    except Exception as e:
        db.session.rollback()
        log_activity('ADMIN_NEWS_DELETE', f'Erreur suppression article', success=False, error_message=str(e))
        flash(f'Erreur lors de la suppression: {str(e)}', 'danger')
    
    return redirect(url_for('admin_panel.blog_management'))

@bp.route('/documents')
@admin_required
def documents_management():
    """Gestion de tous les documents générés"""
    log_activity('ADMIN_DOCUMENTS_VIEW', 'Consultation gestion documents')
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    search_code = request.args.get('search', '')
    doc_type = request.args.get('type', 'all')
    
    from models import RequestSubmission

    queries = []
    
    # QuizResult
    if doc_type == 'all' or doc_type == 'quiz':
        q1 = db.session.query(
            QuizResult.id,
            QuizResult.document_code,
            QuizResult.email.label('identifier'),
            QuizResult.created_at.label('created_at'),
            literal('Quiz').label('type_label'),
            literal('quiz').label('source_type')
        ).filter(QuizResult.document_code.isnot(None))
        if search_code:
            q1 = q1.filter(QuizResult.document_code.contains(search_code))
        queries.append(q1)

    # BreachAnalysis
    if doc_type == 'all' or doc_type == 'breach':
        q2 = db.session.query(
            BreachAnalysis.id,
            BreachAnalysis.document_code,
            BreachAnalysis.email.label('identifier'),
            BreachAnalysis.created_at.label('created_at'),
            literal('Analyse de fuite').label('type_label'),
            literal('breach').label('source_type')
        ).filter(BreachAnalysis.document_code.isnot(None))
        if search_code:
            q2 = q2.filter(BreachAnalysis.document_code.contains(search_code))
        queries.append(q2)

    # SecurityAnalysis
    if doc_type == 'all' or doc_type == 'security':
        q3 = db.session.query(
            SecurityAnalysis.id,
            SecurityAnalysis.document_code,
            SecurityAnalysis.input_value.label('identifier'),
            SecurityAnalysis.created_at.label('created_at'),
            literal('Analyse de sécurité').label('type_label'),
            literal('security').label('source_type')
        ).filter(SecurityAnalysis.document_code.isnot(None))
        if search_code:
            q3 = q3.filter(SecurityAnalysis.document_code.contains(search_code))
        queries.append(q3)

    # RequestSubmission
    if doc_type == 'all' or doc_type == 'request':
        q4 = db.session.query(
            RequestSubmission.id,
            RequestSubmission.document_code,
            RequestSubmission.contact_email.label('identifier'),
            RequestSubmission.created_at.label('created_at'),
            literal('Demande').label('type_label'),
            literal('request').label('source_type')
        ).filter(RequestSubmission.document_code.isnot(None))
        if search_code:
            q4 = q4.filter(RequestSubmission.document_code.contains(search_code))
        queries.append(q4)
    
    documents = []
    total_docs = 0
    
    if queries:
        # Union all queries
        final_query = queries[0].union_all(*queries[1:])

        # Order by created_at desc
        final_query = final_query.order_by(desc(text('created_at')))

        # Count total using subquery
        total_docs = db.session.query(final_query.subquery()).count()

        # Paginate
        paginated_results = final_query.limit(per_page).offset((page - 1) * per_page).all()

        for row in paginated_results:
            doc = {
                'type': row.type_label,
                'code': row.document_code,
                'created_at': row.created_at,
            }

            # Identifier handling
            if row.source_type == 'security':
                 doc['email'] = row.identifier[:50] if row.identifier else ''
            elif row.source_type == 'request':
                 doc['email'] = row.identifier or 'Anonyme'
            else:
                 doc['email'] = row.identifier

            # URL generation
            # Note: Assuming route params have been fixed or are document_code.
            # I will use document_code as it's the correct way for the routes found in main.py
            if row.source_type == 'quiz':
                doc['download_url'] = url_for('main.generate_quiz_pdf', document_code=row.document_code)
            elif row.source_type == 'breach':
                doc['download_url'] = url_for('main.generate_breach_pdf', document_code=row.document_code)
            elif row.source_type == 'security':
                doc['download_url'] = url_for('main.generate_security_pdf', document_code=row.document_code)
            elif row.source_type == 'request':
                doc['detail_url'] = url_for('admin_requests.request_detail', submission_id=row.id)

            documents.append(doc)
    
    total_pages = (total_docs + per_page - 1) // per_page
    
    stats = {
        'total': total_docs,
        'quiz': QuizResult.query.filter(QuizResult.document_code.isnot(None)).count(),
        'breach': BreachAnalysis.query.filter(BreachAnalysis.document_code.isnot(None)).count(),
        'security': SecurityAnalysis.query.filter(SecurityAnalysis.document_code.isnot(None)).count(),
        'request': db.session.query(RequestSubmission).filter(RequestSubmission.document_code.isnot(None)).count()
    }
    
    return render_template('admin/documents.html',
                         documents=documents,
                         stats=stats,
                         page=page,
                         total_pages=total_pages,
                         search=search_code,
                         doc_type=doc_type)
