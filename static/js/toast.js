document.addEventListener('DOMContentLoaded', function() {
    const toasts = document.querySelectorAll('.toast');
    if (toasts.length > 0) {
        setTimeout(function() {
            toasts.forEach(function(toast) {
                toast.style.animation = 'slideOut 0.3s ease-in';
                setTimeout(function() { toast.remove(); }, 300);
            });
        }, 5000);
    }
});
