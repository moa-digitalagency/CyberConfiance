document.addEventListener('DOMContentLoaded', function() {
    const scenarioCards = document.querySelectorAll('.scenario-card');
    const searchInput = document.getElementById('search-input');
    const severityFilter = document.getElementById('severity-filter');
    const ruleFilter = document.getElementById('rule-filter');
    const resetButton = document.getElementById('reset-filters');
    const noResults = document.getElementById('no-results');
    const scenariosGrid = document.getElementById('scenarios-grid');

    // Extraire les règles et les stocker dans les data attributes
    scenarioCards.forEach(card => {
        const descriptionDiv = card.querySelector('.scenario-description');
        const rulesContainer = card.querySelector('.scenario-rules-links');

        if (!descriptionDiv || !rulesContainer) return;

        const description = descriptionDiv.textContent;
        const match = description.match(/Règles d['']or appliquées[^:]*:\s*([0-9,\s]+)/i);

        if (match && match[1]) {
            const ruleNumbers = match[1].trim().split(/[,\s]+/).filter(n => n && !isNaN(n));

            if (ruleNumbers.length > 0) {
                // Stocker les règles dans data-rules
                card.setAttribute('data-rules', ruleNumbers.join(','));

                const paragraphs = descriptionDiv.querySelectorAll('p');
                paragraphs.forEach(p => {
                    if (p.textContent.includes("Règles d'or appliquées") || p.textContent.includes("Règles d'or appliquées")) {
                        p.remove();
                    }
                });

                let html = '<h4>Règles d\'or à appliquer :</h4><div class="rules-buttons">';
                ruleNumbers.forEach(num => {
                    html += `<a href="/rules/${num}" class="rule-link-button">Règle ${num}</a>`;
                });
                html += '</div>';
                rulesContainer.innerHTML = html;
                rulesContainer.style.display = 'block';
            }
        }
    });

    // Fonction de filtrage
    function filterScenarios() {
        const searchTerm = searchInput.value.toLowerCase().trim();
        const selectedSeverity = severityFilter.value.toLowerCase();
        const selectedRule = ruleFilter.value;
        let visibleCount = 0;

        scenarioCards.forEach(card => {
            const title = card.getAttribute('data-title') || '';
            const severity = card.getAttribute('data-severity') || '';
            const rules = card.getAttribute('data-rules') || '';
            const description = card.querySelector('.scenario-description').textContent.toLowerCase();

            const matchesSearch = !searchTerm || title.includes(searchTerm) || description.includes(searchTerm);
            const matchesSeverity = !selectedSeverity || severity === selectedSeverity;
            const matchesRule = !selectedRule || rules.split(',').includes(selectedRule);

            if (matchesSearch && matchesSeverity && matchesRule) {
                card.style.display = '';
                visibleCount++;
            } else {
                card.style.display = 'none';
            }
        });

        if (visibleCount === 0) {
            noResults.style.display = 'block';
            scenariosGrid.style.display = 'none';
        } else {
            noResults.style.display = 'none';
            scenariosGrid.style.display = 'grid';
        }
    }

    // Événements de filtrage
    searchInput.addEventListener('input', filterScenarios);
    severityFilter.addEventListener('change', filterScenarios);
    ruleFilter.addEventListener('change', filterScenarios);

    // Réinitialiser les filtres
    resetButton.addEventListener('click', function() {
        searchInput.value = '';
        severityFilter.value = '';
        ruleFilter.value = '';
        filterScenarios();
    });
});