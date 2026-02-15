document.addEventListener('DOMContentLoaded', function() {
    const typeOptions = document.querySelectorAll('input[name="input_type"]');
    const hints = document.querySelectorAll('.hint');
    const textInputGroup = document.getElementById('textInputGroup');
    const fileInputGroup = document.getElementById('fileInputGroup');
    const textInput = document.getElementById('inputValue');
    const fileInput = document.getElementById('fileInput');

    typeOptions.forEach(option => {
        option.addEventListener('change', function() {
            hints.forEach(hint => hint.classList.remove('active'));
            const hintClass = this.value + '-hint';
            const activeHint = document.querySelector('.' + hintClass);
            if (activeHint) {
                activeHint.classList.add('active');
            }

            if (this.value === 'file') {
                textInputGroup.style.display = 'none';
                fileInputGroup.style.display = 'flex';
                textInput.removeAttribute('required');
                fileInput.setAttribute('required', 'required');
            } else {
                textInputGroup.style.display = 'flex';
                fileInputGroup.style.display = 'none';
                textInput.setAttribute('required', 'required');
                fileInput.removeAttribute('required');
            }
        });
    });
});