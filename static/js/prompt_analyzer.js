document.addEventListener('DOMContentLoaded', function() {
    const textarea = document.getElementById('promptText');
    const charCount = document.getElementById('charCount');

    function updateCount() {
        charCount.textContent = textarea.value.length.toLocaleString();
    }

    textarea.addEventListener('input', updateCount);
    updateCount();
});