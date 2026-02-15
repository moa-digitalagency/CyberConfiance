function exportData() {
    let csv = 'ID,Type,Sévérité,Description,Bloqué,IP,Date\n';
    const rows = document.querySelectorAll('.admin-table tbody tr');

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 7) {
            const values = Array.from(cells).slice(0, 7).map(cell =>
                '"' + cell.textContent.trim().replace(/"/g, '""') + '"'
            );
            csv += values.join(',') + '\n';
        }
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security_logs_' + new Date().toISOString().split('T')[0] + '.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}