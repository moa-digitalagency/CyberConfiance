function toggleAll(checkbox) {
    const checkboxes = document.querySelectorAll('.contact-checkbox');
    checkboxes.forEach(cb => cb.checked = checkbox.checked);
    updateReplyBtn();
}

function updateReplyBtn() {
    const checked = document.querySelectorAll('.contact-checkbox:checked');
    const replyBtn = document.getElementById('reply-btn');
    const selectedCount = document.getElementById('selected-count');
    const countText = document.getElementById('count-text');

    if (checked.length > 0) {
        replyBtn.style.display = 'inline-flex';
        selectedCount.style.display = 'inline';
        countText.textContent = checked.length;
    } else {
        replyBtn.style.display = 'none';
        selectedCount.style.display = 'none';
    }
}

function replySelected() {
    const checked = document.querySelectorAll('.contact-checkbox:checked');
    const emails = Array.from(checked).map(cb => cb.dataset.email).join(', ');
    const modal = document.getElementById('compose-modal');
    const recipientsInput = modal.querySelector('input[name="recipients"]');
    recipientsInput.value = emails;
    modal.style.display = 'block';
}

function replyToContact(email) {
    const modal = document.getElementById('compose-modal');
    const recipientsInput = modal.querySelector('input[name="recipients"]');
    recipientsInput.value = email;
    modal.style.display = 'block';
}

// Search functionality
document.getElementById('search-input').addEventListener('input', function(e) {
    const searchTerm = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('.admin-table tbody tr');

    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
    });
});