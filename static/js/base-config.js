document.addEventListener('DOMContentLoaded', function() {
    const body = document.body;
    window.siteSettings = {
        logo_light_url: body.getAttribute('data-logo-light'),
        logo_dark_url: body.getAttribute('data-logo-dark')
    };
});
