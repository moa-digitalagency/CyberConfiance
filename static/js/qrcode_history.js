function exportData() {
    let csv = 'Code,Fichier,URL,Menace,Niveau,Redirections,Date\n';
    const rows = document.querySelectorAll('.admin-table tbody tr');

    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        if (cells.length >= 7) {
            const code = cells[0].textContent.trim();
            const filename = cells[1].textContent.trim();
            const url = cells[2].textContent.trim();
            const threat = cells[3].textContent.trim();
            const level = cells[4].textContent.trim();
            const redirects = cells[5].textContent.trim();
            const date = cells[6].textContent.trim();
            csv += `"${code}","${filename}","${url}","${threat}","${level}","${redirects}","${date}"\n`;
        }
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'qrcode_history_' + new Date().toISOString().split('T')[0] + '.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}