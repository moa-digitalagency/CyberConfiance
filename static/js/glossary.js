document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('glossary-search');
    const glossaryGrid = document.getElementById('glossary-grid');
    const glossaryItems = document.querySelectorAll('.glossary-item');
    const noResults = document.getElementById('no-results');

    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase().trim();
            let visibleCount = 0;

            glossaryItems.forEach(function(item) {
                const term = item.getAttribute('data-term');
                const definition = item.getAttribute('data-definition');

                if (term.includes(searchTerm) || definition.includes(searchTerm)) {
                    item.style.display = '';
                    visibleCount++;
                } else {
                    item.style.display = 'none';
                }
            });

            if (visibleCount === 0) {
                noResults.style.display = 'block';
                glossaryGrid.style.display = 'none';
            } else {
                noResults.style.display = 'none';
                glossaryGrid.style.display = 'grid';
            }
        });
    }
});