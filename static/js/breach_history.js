function exportData() {
    let csv = 'Email,Fuites,Niveau de risque,Date,IP\n';
    const rows = document.querySelectorAll('.admin-table tbody tr');

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 5) {
            const email = cells[0].textContent.trim();
            const breaches = cells[1].textContent.trim();
            const risk = cells[2].textContent.trim();
            const date = cells[3].textContent.trim();
            const ip = cells[4].textContent.trim();
            csv += `"${email}","${breaches}","${risk}","${date}","${ip}"\n`;
        }
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'breach_history_' + new Date().toISOString().split('T')[0] + '.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}