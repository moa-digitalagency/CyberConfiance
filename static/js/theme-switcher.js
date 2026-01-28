/*
 * Nom de l'application : CyberConfiance
 * Description : Fichier theme-switcher.js du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com

*/

/**
 * CyberConfiance
 * By MOA Digital Agency LLC
 * Developed by: Aisance KALONJI
 * Contact: moa@myoneart.com
 * www.myoneart.com
 * 
 * Gestionnaire de changement de langue.
 */

const ThemeSwitcher = {
    init() {
        // Fixed dark theme - no theme switching
        this.setupEventListeners();
    },

    setLanguage(lang) {
        localStorage.setItem('language', lang);
        
        fetch('/set-language', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content
            },
            body: JSON.stringify({ language: lang })
        }).then(() => {
            window.location.reload();
        });
    },

    toggleLanguage() {
        const currentLang = localStorage.getItem('language') || 'fr';
        const newLang = currentLang === 'fr' ? 'en' : 'fr';
        this.setLanguage(newLang);
    },

    setupEventListeners() {
        const langBtn = document.getElementById('lang-toggle');

        if (langBtn) {
            langBtn.addEventListener('click', () => this.toggleLanguage());
        }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    ThemeSwitcher.init();
});
