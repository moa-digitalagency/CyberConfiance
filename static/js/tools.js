document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('searchInput');
    const typeFilter = document.getElementById('typeFilter');
    const ruleFilter = document.getElementById('ruleFilter');
    const scenarioFilter = document.getElementById('scenarioFilter');
    const resetButton = document.getElementById('resetFilters');
    const toolCards = document.querySelectorAll('.tool-card-modern');
    const resultsCount = document.getElementById('resultsCount');
    const noResults = document.getElementById('noResults');
    const toolsGrid = document.getElementById('toolsGrid');

    function filterTools() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedType = typeFilter.value;
        const selectedRule = ruleFilter.value;
        const selectedScenario = scenarioFilter.value;

        let visibleCount = 0;

        toolCards.forEach(card => {
            const name = card.dataset.name || '';
            const description = card.dataset.description || '';
            const type = card.dataset.type || '';
            const rules = card.dataset.rules || '';
            const scenarios = card.dataset.scenarios || '';

            let show = true;

            if (searchTerm && !name.includes(searchTerm) && !description.includes(searchTerm)) {
                show = false;
            }

            if (selectedType && type !== selectedType) {
                show = false;
            }

            if (selectedRule) {
                const ruleIds = rules.split(',').map(r => r.trim());
                if (!ruleIds.includes(selectedRule)) {
                    show = false;
                }
            }

            if (selectedScenario) {
                const scenarioIds = scenarios.split(',').map(s => s.trim());
                if (!scenarioIds.includes(selectedScenario)) {
                    show = false;
                }
            }

            if (show) {
                card.style.display = 'block';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        if (visibleCount === 0) {
            toolsGrid.style.display = 'none';
            noResults.style.display = 'block';
            resultsCount.textContent = '';
        } else {
            toolsGrid.style.display = 'grid';
            noResults.style.display = 'none';
            resultsCount.textContent = `${visibleCount} outil${visibleCount > 1 ? 's' : ''} trouvé${visibleCount > 1 ? 's' : ''}`;
        }
    }

    function resetFilters() {
        searchInput.value = '';
        typeFilter.value = '';
        ruleFilter.value = '';
        scenarioFilter.value = '';
        filterTools();
    }

    searchInput.addEventListener('input', filterTools);
    typeFilter.addEventListener('change', filterTools);
    ruleFilter.addEventListener('change', filterTools);
    scenarioFilter.addEventListener('change', filterTools);
    resetButton.addEventListener('click', resetFilters);

    filterTools();
});