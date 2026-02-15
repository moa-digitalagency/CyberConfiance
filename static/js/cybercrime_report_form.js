// Anonymous toggle - checked by default
const anonymousCheckbox = document.getElementById('is_anonymous');
const contactSection = document.getElementById('contact-section');

// Set as anonymous by default
anonymousCheckbox.checked = true;

anonymousCheckbox.addEventListener('change', function() {
    const inputs = contactSection.querySelectorAll('input');

    if (this.checked) {
        // Anonymous mode
        contactSection.style.display = 'none';
        inputs.forEach(input => {
            input.required = false;
            input.value = '';
        });
    } else {
        // Contact mode
        contactSection.style.display = 'block';
    }
});