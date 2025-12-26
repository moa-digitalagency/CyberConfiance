"""
CyberConfiance
By MOA Digital Agency LLC
Developed by: Aisance KALONJI
Contact: moa@myoneart.com
www.myoneart.com

Routes des pages statiques: a propos, services, programmes.
"""

from flask import Blueprint, render_template

bp = Blueprint('pages', __name__)

@bp.route('/about')
def about():
    return render_template('about.html')

@bp.route('/programme/<slug>')
def programme_detail(slug):
    programmes = {
        'ateliers-communautaires': 'programmes/ateliers_communautaires.html',
        'campagnes-reseaux-sociaux': 'programmes/campagnes_reseaux_sociaux.html',
        'webinaires-videos': 'programmes/webinaires_videos.html',
        'guides-pratiques': 'programmes/guides_pratiques.html',
        'formations-entreprises': 'programmes/formations_entreprises.html',
        'partenariats-educatifs': 'programmes/partenariats_educatifs.html'
    }
    
    template = programmes.get(slug, 'programme_detail.html')
    return render_template(template)

@bp.route('/services/sensibilisation')
def service_sensibilisation():
    return render_template('services/sensibilisation.html')

@bp.route('/services/factchecking')
def service_factchecking():
    return render_template('services/factchecking.html')

@bp.route('/services/cyberconsultation')
def service_cyberconsultation():
    return render_template('services/cyberconsultation.html')

@bp.route('/outils/methodologie-osint')
def osint_methodology():
    return render_template('outils/methodologie_osint.html')
