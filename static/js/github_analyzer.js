document.addEventListener('DOMContentLoaded', function() {
    const form = document.querySelector('.analyzer-form');
    const btn = document.getElementById('analyzeBtn');

    if (form && btn) {
        form.addEventListener('submit', function() {
            btn.disabled = true;
            btn.innerHTML = '<svg class="spinner" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/></svg><span>Analyse en cours... (peut prendre 30-60 secondes)</span>';
        });
    }
});