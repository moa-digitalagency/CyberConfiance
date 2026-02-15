// Tab switching
document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', function() {
        const tab = this.dataset.tab;

        // Update buttons
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        this.classList.add('active');

        // Update content
        document.querySelectorAll('.tab-content').forEach(content => content.style.display = 'none');
        document.getElementById(tab + '-content').style.display = 'block';
    });
});

// Check URL hash on page load to open specific tab
window.addEventListener('DOMContentLoaded', function() {
    if (window.location.hash === '#osint-tab') {
        const osintButton = document.querySelector('[data-tab="osint"]');
        if (osintButton) {
            osintButton.click();
        }
    }
});

// Anonymous toggle for Cyberconsultation
document.getElementById('is_anonymous_cyber').addEventListener('change', function() {
    const contactSection = document.getElementById('contact-section-cyber');
    const inputs = contactSection.querySelectorAll('input');

    if (this.checked) {
        contactSection.style.display = 'none';
        inputs.forEach(input => {
            input.required = false;
            input.value = '';
        });
    } else {
        contactSection.style.display = 'block';
        document.getElementById('name_cyber').required = true;
        document.getElementById('email_cyber').required = true;
    }
});

// Anonymous toggle for OSINT
document.getElementById('is_anonymous_osint').addEventListener('change', function() {
    const contactSection = document.getElementById('contact-section-osint');
    const inputs = contactSection.querySelectorAll('input');

    if (this.checked) {
        contactSection.style.display = 'none';
        inputs.forEach(input => {
            input.required = false;
            input.value = '';
        });
    } else {
        contactSection.style.display = 'block';
        document.getElementById('name_osint').required = true;
        document.getElementById('email_osint').required = true;
    }
});