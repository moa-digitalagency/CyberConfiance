function exportData() {
    let csv = 'Code,Prompt,Longueur,Menace,Injection,Niveau,Date\n';
    const rows = document.querySelectorAll('.admin-table tbody tr');

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 7) {
            const code = cells[0].textContent.trim();
            const prompt = cells[1].textContent.trim().replace(/"/g, '""');
            const length = cells[2].textContent.trim();
            const threat = cells[3].textContent.trim();
            const injection = cells[4].textContent.trim();
            const level = cells[5].textContent.trim();
            const date = cells[6].textContent.trim();
            csv += `"${code}","${prompt}","${length}","${threat}","${injection}","${level}","${date}"\n`;
        }
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'prompt_history_' + new Date().toISOString().split('T')[0] + '.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}