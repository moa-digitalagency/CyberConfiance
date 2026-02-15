document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('attackSearchInput');
    const severityFilter = document.getElementById('severityFilter');
    const filterBtns = document.querySelectorAll('.filter-btn-attack');
    const resetButton = document.getElementById('resetAttackFilters');
    const attackCards = document.querySelectorAll('.attack-card-modern');
    const noResults = document.getElementById('noAttackResults');
    const attacksGrid = document.getElementById('attacksGrid');
    const resultsCount = document.getElementById('attackResultsCount');

    function filterAttacks() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedSeverity = severityFilter.value;
        const activeBtn = document.querySelector('.filter-btn-attack.active');
        const category = activeBtn ? activeBtn.dataset.category : 'all';
        let visibleCount = 0;

        attackCards.forEach(card => {
            const name = card.dataset.name || '';
            const description = card.dataset.description || '';
            const cardCategory = card.dataset.category || '';
            const cardSeverity = card.dataset.severity || '';

            let show = true;

            if (searchTerm && !name.includes(searchTerm) && !description.includes(searchTerm)) {
                show = false;
            }

            if (category !== 'all' && cardCategory !== category) {
                show = false;
            }

            if (selectedSeverity && cardSeverity !== selectedSeverity) {
                show = false;
            }

            if (show) {
                card.style.display = 'block';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        if (visibleCount === 0) {
            attacksGrid.style.display = 'none';
            noResults.style.display = 'block';
            resultsCount.textContent = '';
        } else {
            attacksGrid.style.display = 'grid';
            noResults.style.display = 'none';
            resultsCount.textContent = `${visibleCount} type${visibleCount > 1 ? 's' : ''} d'attaque${visibleCount > 1 ? 's' : ''}`;
        }
    }

    function resetFilters() {
        searchInput.value = '';
        severityFilter.value = '';
        filterBtns.forEach(btn => btn.classList.remove('active'));
        filterBtns[0].classList.add('active');
        filterAttacks();
    }

    searchInput.addEventListener('input', filterAttacks);
    severityFilter.addEventListener('change', filterAttacks);
    resetButton.addEventListener('click', resetFilters);

    filterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            filterBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            filterAttacks();
        });
    });

    filterAttacks();
});