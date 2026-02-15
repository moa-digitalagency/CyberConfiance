function exportData() {
    // Simple CSV export
    let csv = 'Email,Score,Date,IP\n';
    const rows = document.querySelectorAll('.admin-table tbody tr');

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 4) {
            const email = cells[0].textContent.trim();
            const score = cells[1].textContent.trim();
            const date = cells[2].textContent.trim();
            const ip = cells[3].textContent.trim();
            csv += `"${email}","${score}","${date}","${ip}"\n`;
        }
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'quiz_history_' + new Date().toISOString().split('T')[0] + '.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}