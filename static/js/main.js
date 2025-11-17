document.addEventListener('DOMContentLoaded', function() {
    console.log('CyberConfiance loaded!');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });
    
    document.querySelectorAll('.scroll-animate').forEach(el => {
        observer.observe(el);
    });
    
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-20px)';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
    
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

// Dropdown Menu Interactions for Mobile
document.addEventListener('DOMContentLoaded', function() {
    const dropdownToggles = document.querySelectorAll('.dropdown-toggle');
    
    dropdownToggles.forEach(toggle => {
        toggle.addEventListener('click', function(e) {
            if (window.innerWidth <= 768) {
                e.preventDefault();
                const dropdown = this.closest('.dropdown');
                dropdown.classList.toggle('active');
            }
        });
    });
    
    // Close dropdowns when clicking outside
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.dropdown')) {
            document.querySelectorAll('.dropdown.active').forEach(dropdown => {
                dropdown.classList.remove('active');
            });
        }
    });
});

// Hero animated text
document.addEventListener('DOMContentLoaded', function() {
    const words = document.querySelectorAll('.hero-word');
    if (words.length === 0) return;
    
    let currentIndex = 0;
    
    function animateWords() {
        const currentWord = words[currentIndex];
        const nextIndex = (currentIndex + 1) % words.length;
        const nextWord = words[nextIndex];
        
        // Exit current word upward
        currentWord.classList.remove('active');
        currentWord.classList.add('exit-up');
        
        // Enter next word from bottom
        nextWord.classList.remove('exit-up', 'enter-down');
        nextWord.classList.add('enter-down');
        
        // Small delay then activate next word
        setTimeout(() => {
            nextWord.classList.remove('enter-down');
            nextWord.classList.add('active');
            currentWord.classList.remove('exit-up');
        }, 50);
        
        currentIndex = nextIndex;
    }
    
    // Start animation every 3 seconds
    setInterval(animateWords, 3000);
});
