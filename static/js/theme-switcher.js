const ThemeSwitcher = {
    init() {
        this.detectAndSetTheme();
        this.setupEventListeners();
    },

    detectAndSetTheme() {
        const savedTheme = localStorage.getItem('theme');
        const savedLang = localStorage.getItem('language');
        
        if (savedTheme) {
            this.setTheme(savedTheme);
        } else {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            this.setTheme(prefersDark ? 'dark' : 'light');
        }

        if (savedLang) {
            this.setLanguage(savedLang);
        } else {
            const browserLang = navigator.language.split('-')[0];
            this.setLanguage(['en', 'fr'].includes(browserLang) ? browserLang : 'fr');
        }
    },

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        const icon = document.getElementById('theme-icon');
        if (icon) {
            icon.className = theme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
        }

        const logoImg = document.querySelector('.logo img');
        if (logoImg) {
            const logoSetting = theme === 'dark' ? 'logo_dark_url' : 'logo_light_url';
            const logoUrl = window.siteSettings?.[logoSetting] || '/static/img/logo.png';
            logoImg.src = logoUrl;
        }
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

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
    },

    toggleLanguage() {
        const currentLang = localStorage.getItem('language') || 'fr';
        const newLang = currentLang === 'fr' ? 'en' : 'fr';
        this.setLanguage(newLang);
    },

    setupEventListeners() {
        const themeBtn = document.getElementById('theme-toggle');
        const langBtn = document.getElementById('lang-toggle');

        if (themeBtn) {
            themeBtn.addEventListener('click', () => this.toggleTheme());
        }

        if (langBtn) {
            langBtn.addEventListener('click', () => this.toggleLanguage());
        }

        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
            if (!localStorage.getItem('theme')) {
                this.setTheme(e.matches ? 'dark' : 'light');
            }
        });
    }
};

document.addEventListener('DOMContentLoaded', () => {
    ThemeSwitcher.init();
});
