function updateFilters() {
    const category = document.getElementById('category-filter').value;
    const source = document.getElementById('source-filter').value;
    let url = '?';
    if (category) url += 'category=' + encodeURIComponent(category) + '&';
    if (source) url += 'source=' + encodeURIComponent(source);
    window.location.href = url;
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