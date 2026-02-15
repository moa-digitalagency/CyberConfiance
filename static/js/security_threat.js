function copyIncidentLink() {
    const linkInput = document.getElementById('incidentLink');
    linkInput.select();
    linkInput.setSelectionRange(0, 99999); // For mobile devices

    navigator.clipboard.writeText(linkInput.value).then(() => {
        const successMsg = document.getElementById('copySuccess');
        successMsg.style.display = 'block';
        setTimeout(() => {
            successMsg.style.display = 'none';
        }, 3000);
    }).catch(() => {
        // Fallback for older browsers
        document.execCommand('copy');
        const successMsg = document.getElementById('copySuccess');
        successMsg.style.display = 'block';
        setTimeout(() => {
            successMsg.style.display = 'none';
        }, 3000);
    });
}