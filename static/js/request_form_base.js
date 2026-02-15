document.getElementById('is_anonymous').addEventListener('change', function() {
    const contactInfo = document.getElementById('contact-info');
    const inputs = contactInfo.querySelectorAll('input');

    if (this.checked) {
        contactInfo.style.display = 'none';
        inputs.forEach(input => {
            input.required = false;
            input.value = '';
        });
    } else {
        contactInfo.style.display = 'block';
        document.getElementById('name').required = true;
        document.getElementById('email').required = true;
    }
});