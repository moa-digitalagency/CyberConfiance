// Theme Switcher
const initTheme = () => {
    const savedTheme = localStorage.getItem('theme');
    // Default to 'dark' without browser detection
    const theme = savedTheme || 'dark';
    
    document.documentElement.setAttribute('data-theme', theme);
    updateLogo(theme);
};

const toggleTheme = () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateLogo(newTheme);
};

const updateLogo = (theme) => {
    const logoImg = document.querySelector('.logo-image');
    if (logoImg) {
        const logoLight = logoImg.getAttribute('data-logo-light') || '/static/img/logo.png';
        const logoDark = logoImg.getAttribute('data-logo-dark') || '/static/img/logo.png';
        logoImg.src = theme === 'light' ? logoLight : logoDark;
    }
};

// Language Switcher
const initLanguage = () => {
    const savedLang = localStorage.getItem('language');
    if (savedLang) {
        document.documentElement.setAttribute('lang', savedLang);
    }
};

const switchLanguage = (lang) => {
    localStorage.setItem('language', lang);
    window.location.href = `/set-language/${lang}`;
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initLanguage();
    
    // Theme toggle button
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    // Language switcher buttons
    const langButtons = document.querySelectorAll('.lang-switch-btn');
    langButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            switchLanguage(btn.getAttribute('data-lang'));
        });
    });
});

// Browser theme detection disabled to prevent infinite loops
