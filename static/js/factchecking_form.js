document.getElementById('is_anonymous').addEventListener('change', function() {
    const contactSection = document.getElementById('contact-section');
    const inputs = contactSection.querySelectorAll('input');

    if (this.checked) {
        contactSection.style.display = 'none';
        inputs.forEach(input => {
            input.required = false;
            input.value = '';
        });
    } else {
        contactSection.style.display = 'block';
        document.getElementById('name').required = true;
        document.getElementById('email').required = true;
    }
});