document.addEventListener('DOMContentLoaded', function() {
    // Language Switching
    const enBtn = document.getElementById('en-btn');
    const ruBtn = document.getElementById('ru-btn');
    const translateElements = document.querySelectorAll('.translate');
    const navLinks = document.querySelectorAll('.nav-link');
    
    // Default language
    let currentLang = 'en';
    
    // Function to update all translatable elements
    function updateLanguage(lang) {
        currentLang = lang;
        
        // Update HTML lang attribute
        document.documentElement.setAttribute('lang', lang);
        
        // Update active button
        if (lang === 'en') {
            enBtn.classList.add('active');
            ruBtn.classList.remove('active');
        } else {
            ruBtn.classList.add('active');
            enBtn.classList.remove('active');
        }
        
        // Update all translatable elements
        translateElements.forEach(element => {
            const translatedText = element.getAttribute(`data-${lang}`);
            if (translatedText) {
                // Fade out, change text, fade in
                element.style.opacity = '0';
                setTimeout(() => {
                    element.textContent = translatedText;
                    element.style.opacity = '1';
                    // Ensure consistent font weight for both languages
                    element.style.fontWeight = '300';
                }, 400);
            }
        });
        
        // Update navigation links
        navLinks.forEach(link => {
            const translatedText = link.getAttribute(`data-${lang}`);
            if (translatedText) {
                // Subtle transition for nav links
                link.style.opacity = '0.5';
                setTimeout(() => {
                    link.textContent = translatedText;
                    link.style.opacity = '1';
                }, 300);
            }
        });
        
        // Save language preference
        localStorage.setItem('language', lang);
    }
    
    // Event listeners for language buttons
    enBtn.addEventListener('click', () => updateLanguage('en'));
    ruBtn.addEventListener('click', () => updateLanguage('ru'));
    
    // Check for saved language preference
    const savedLang = localStorage.getItem('language');
    if (savedLang) {
        updateLanguage(savedLang);
    } else {
        // Add initial transition to all elements
        translateElements.forEach(element => {
            element.style.transition = 'opacity 0.6s cubic-bezier(0.16, 1, 0.3, 1)';
            // Ensure consistent font weight initially
            element.style.fontWeight = '300';
        });
        navLinks.forEach(link => {
            link.style.transition = 'opacity 0.5s cubic-bezier(0.16, 1, 0.3, 1)';
        });
    }
    
    // Logo click handler - scroll to top
    const logoLink = document.getElementById('logo-link');
    if (logoLink) {
        logoLink.addEventListener('click', function(e) {
            e.preventDefault();
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
    
    // Smooth scrolling for navigation links with better mobile support
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            
            // Skip if it's the logo link (already handled)
            if (this.id === 'logo-link') return;
            
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                // Adjust offset based on screen size
                let headerOffset = 90;
                if (window.innerWidth <= 768) {
                    headerOffset = 70;
                }
                if (window.innerWidth <= 480) {
                    headerOffset = 60;
                }
                
                window.scrollTo({
                    top: targetElement.offsetTop - headerOffset,
                    behavior: 'smooth'
                });
                
                // Close mobile menu if implemented
                // if (window.innerWidth <= 768 && mobileMenuToggle) {
                //     closeMobileMenu();
                // }
            }
        });
    });
    
    // Header transparency on scroll
    const header = document.querySelector('header');
    let lastScrollTop = 0;
    
    window.addEventListener('scroll', () => {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        if (scrollTop > 100) {
            header.style.backgroundColor = 'rgba(255, 255, 255, 0.98)';
            header.style.boxShadow = '0 1px 5px rgba(0, 0, 0, 0.03)';
        } else {
            header.style.backgroundColor = 'rgba(255, 255, 255, 0.98)';
            header.style.boxShadow = 'none';
        }
        
        lastScrollTop = scrollTop;
    });
    
    // Animation on scroll
    const animateOnScroll = () => {
        const elements = document.querySelectorAll('.skill, .game-card, .book-card');
        
        elements.forEach(element => {
            const elementPosition = element.getBoundingClientRect().top;
            const screenPosition = window.innerHeight / 1.05;
            
            if (elementPosition < screenPosition) {
                element.classList.add('appear');
            }
        });
    };
    
    // Initial styles for animation
    document.querySelectorAll('.skill, .game-card, .book-card').forEach(element => {
        element.style.opacity = '0';
        element.style.transform = 'translateY(8px)';
        element.style.transition = 'opacity 1s cubic-bezier(0.16, 1, 0.3, 1), transform 1s cubic-bezier(0.16, 1, 0.3, 1)';
    });
    
    // Add CSS class for appeared elements
    const styleSheet = document.createElement("style");
    styleSheet.innerText = `
        .appear {
            opacity: 1 !important;
            transform: translateY(0) !important;
        }
    `;
    document.head.appendChild(styleSheet);
    
    // Stagger animation for cards
    const gameCards = document.querySelectorAll('.game-card');
    gameCards.forEach((card, index) => {
        card.style.transitionDelay = `${index * 0.12}s`;
    });
    
    const bookCards = document.querySelectorAll('.book-card');
    bookCards.forEach((card, index) => {
        card.style.transitionDelay = `${index * 0.12}s`;
    });
    
    // Run animations on scroll
    window.addEventListener('scroll', animateOnScroll);
    
    // Run once on load
    setTimeout(animateOnScroll, 150);

    // Add hover effect to all interactive elements
    const interactiveElements = document.querySelectorAll('a, button');
    interactiveElements.forEach(element => {
        element.style.transition = 'all 0.5s cubic-bezier(0.16, 1, 0.3, 1)';
    });
    
    // Prevent copying of programming language icons
    const preventCopy = () => {
        const langIcons = document.querySelectorAll('.lang-icon img');
        
        // Disable right-click
        langIcons.forEach(icon => {
            icon.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                return false;
            });
            
            // Disable dragging
            icon.setAttribute('draggable', 'false');
            
            // Prevent copy via keyboard
            icon.addEventListener('keydown', (e) => {
                if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'x')) {
                    e.preventDefault();
                    return false;
                }
            });
        });
        
        // Disable selection
        document.addEventListener('selectstart', (e) => {
            if (e.target.closest('.lang-icon')) {
                e.preventDefault();
                return false;
            }
        });
    };
    
    // Prevent copying of book covers
    const preventBookCopy = () => {
        const bookCovers = document.querySelectorAll('.book-cover img');
        
        // Disable right-click
        bookCovers.forEach(cover => {
            cover.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                return false;
            });
            
            // Disable dragging
            cover.setAttribute('draggable', 'false');
            
            // Prevent copy via keyboard
            cover.addEventListener('keydown', (e) => {
                if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'x')) {
                    e.preventDefault();
                    return false;
                }
            });
        });
        
        // Disable selection in book section
        document.addEventListener('selectstart', (e) => {
            if (e.target.closest('.book-cover')) {
                e.preventDefault();
                return false;
            }
        });
        
        // Prevent drag start
        document.addEventListener('dragstart', (e) => {
            if (e.target.closest('.book-cover img')) {
                e.preventDefault();
                return false;
            }
        });
        
        // Prevent touch actions for mobile
        bookCovers.forEach(cover => {
            cover.style.touchAction = 'none';
        });
    };
    
    // Prevent copying of game images
    const preventGameCopy = () => {
        const gameImages = document.querySelectorAll('.game-video img');
        
        // Disable right-click
        gameImages.forEach(image => {
            image.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                return false;
            });
            
            // Disable dragging
            image.setAttribute('draggable', 'false');
            
            // Prevent copy via keyboard
            image.addEventListener('keydown', (e) => {
                if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'x')) {
                    e.preventDefault();
                    return false;
                }
            });
        });
        
        // Disable selection in game section
        document.addEventListener('selectstart', (e) => {
            if (e.target.closest('.game-video')) {
                e.preventDefault();
                return false;
            }
        });
        
        // Prevent drag start
        document.addEventListener('dragstart', (e) => {
            if (e.target.closest('.game-video img')) {
                e.preventDefault();
                return false;
            }
        });
        
        // Prevent touch actions for mobile
        gameImages.forEach(image => {
            image.style.touchAction = 'none';
        });
    };
    
    preventCopy();
    preventBookCopy();
    preventGameCopy();

    // Adjust image sizes on small screens
    function adjustImagesForMobile() {
        const gameImages = document.querySelectorAll('.game-video img');
        const bookCovers = document.querySelectorAll('.book-cover img');
        
        if (window.innerWidth <= 480) {
            gameImages.forEach(img => {
                img.style.height = 'auto';
            });
            
            bookCovers.forEach(cover => {
                cover.style.height = 'auto';
            });
        }
    }
    
    // Run on load and resize
    window.addEventListener('resize', adjustImagesForMobile);
    adjustImagesForMobile();
}); 
