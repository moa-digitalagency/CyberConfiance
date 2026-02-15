document.getElementById('search-input').addEventListener('input', function(e) {
    const searchTerm = e.target.value.toLowerCase();
    const formGroups = document.querySelectorAll('.form-group');

    formGroups.forEach(group => {
        const searchableText = group.getAttribute('data-searchable').toLowerCase();
        group.style.display = searchableText.includes(searchTerm) ? 'block' : 'none';
    });
});

function updateFileName(input, key) {
    const filenameSpan = document.getElementById('filename_' + key);
    if (input.files && input.files[0]) {
        filenameSpan.textContent = input.files[0].name;
        filenameSpan.style.color = 'var(--accent-blue)';
    }
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
    } else {
        input.type = 'password';
    }
}