function exportData() {
    let csv = 'Type,Valeur,Menace,Niveau,Detections,Date\n';
    const rows = document.querySelectorAll('.admin-table tbody tr');

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 6) {
            const type = cells[0].textContent.trim();
            const value = cells[1].textContent.trim();
            const threat = cells[2].textContent.trim();
            const level = cells[3].textContent.trim();
            const detections = cells[4].textContent.trim();
            const date = cells[5].textContent.trim();
            csv += `"${type}","${value}","${threat}","${level}","${detections}","${date}"\n`;
        }
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security_history_' + new Date().toISOString().split('T')[0] + '.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}