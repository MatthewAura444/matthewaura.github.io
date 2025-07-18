// Система безопасности для защиты от атак
const SecuritySystem = {
    // Настройки безопасности
    settings: {
        maxRequestsPerMinute: 300, // Увеличено с 100
        botDetectionThreshold: 50, // Увеличено с 30
        suspiciousPatternThreshold: 0.9, // Увеличено с 0.7
        blockingDuration: 2000, // Уменьшено с 3000
        verificationTimeout: 1500
    },
    
    // Счетчики и временные метки
    counters: {
        requests: 0,
        suspicious: 0,
        lastRequestTime: Date.now(),
        blockedIps: new Set(),
        attackDetected: false
    },
    
    // Инициализация системы безопасности
    init: function() {
        console.log('[SECURITY] System initialized');
        this.setupProtection();
        this.monitorNetwork();
        this.setupAntiTampering();
        
        // Регулярная очистка счетчиков
        setInterval(() => this.resetCounters(), 60000);
    },
    
    // Настройка базовой защиты
    setupProtection: function() {
        // Защита от XSS (валидация входных данных)
        this.sanitizeInputs();
        
        // Защита от злонамеренных действий
        this.monitorUserBehavior();
        
        // Защита от атак брутфорса
        this.preventBruteForce();
    },
    
    // Сканирование и блокировка вредоносных запросов
    monitorNetwork: function() {
        // Перехват всех исходящих запросов
        const originalFetch = window.fetch;
        const originalXHR = window.XMLHttpRequest.prototype.open;
        const security = this;
        
        // Переопределение fetch для мониторинга
        window.fetch = function(url, options) {
            if (security.isRequestBlocked()) {
                console.warn('[SECURITY] Request blocked due to suspicious activity');
                return Promise.reject(new Error('Request blocked by security system'));
            }
            
            security.counters.requests++;
            return originalFetch.apply(this, arguments);
        };
        
        // Переопределение XHR для мониторинга
        window.XMLHttpRequest.prototype.open = function(method, url) {
            if (security.isRequestBlocked()) {
                console.warn('[SECURITY] XHR request blocked due to suspicious activity');
                throw new Error('Request blocked by security system');
            }
            
            security.counters.requests++;
            return originalXHR.apply(this, arguments);
        };
    },
    
    // Проверка, должен ли запрос быть заблокирован
    isRequestBlocked: function() {
        const now = Date.now();
        const timeDiff = now - this.counters.lastRequestTime;
        
        // Обнаружение DDoS: слишком много запросов за короткое время
        if (timeDiff < 1000 && this.counters.requests > this.settings.maxRequestsPerMinute) {
            this.counters.suspicious++;
            this.triggerDefense("Potential DDoS detected", true);
            return true;
        }
        
        // Обновление временной метки
        this.counters.lastRequestTime = now;
        return this.counters.attackDetected;
    },
    
    // Активация защитного механизма
    triggerDefense: function(reason, blockUI = false) {
        console.warn(`[SECURITY] Defense activated: ${reason}`);
        this.counters.attackDetected = true;
        
        // Временная блокировка действий только при критических атаках
        if (blockUI) {
            document.documentElement.style.pointerEvents = 'none';
            
            // Восстановление через заданное время
            setTimeout(() => {
                document.documentElement.style.pointerEvents = 'auto';
                console.log('[SECURITY] UI access restored');
            }, this.settings.blockingDuration);
        }
        
        // Сброс флага атаки через заданное время
        setTimeout(() => {
            this.counters.attackDetected = false;
            console.log('[SECURITY] Defense deactivated');
        }, this.settings.blockingDuration);
    },
    
    // Сброс счетчиков безопасности
    resetCounters: function() {
        this.counters.requests = 0;
        this.counters.suspicious = 0;
    },
    
    // Мониторинг поведения пользователя для выявления ботов
    monitorUserBehavior: function() {
        let mouseMovements = 0;
        let keyPresses = 0;
        let lastActivityTime = Date.now();
        
        // Мониторинг движений мыши
        document.addEventListener('mousemove', () => {
            mouseMovements++;
            lastActivityTime = Date.now();
        }, { passive: true });
        
        // Мониторинг нажатий клавиш
        document.addEventListener('keydown', () => {
            keyPresses++;
            lastActivityTime = Date.now();
        }, { passive: true });
        
        // Периодическая проверка паттернов поведения
        setInterval(() => {
            const now = Date.now();
            
            // Проверка на естественную активность - более мягкие условия
            if ((mouseMovements === 0 && keyPresses > 50) || 
                (mouseMovements > 300 && now - lastActivityTime < 200)) {
                this.counters.suspicious++;
                
                if (this.counters.suspicious > this.settings.botDetectionThreshold) {
                    // Только логируем подозрительное поведение, не блокируем UI
                    console.warn('[SECURITY] Suspicious behavior detected, but not blocking');
                    this.counters.suspicious = 0; // Сбрасываем счетчик
                }
            }
            
            // Сброс счетчиков активности
            mouseMovements = 0;
            keyPresses = 0;
        }, 10000); // Увеличено с 5000 до 10000 мс
    },
    
    // Проверка и очистка входных данных для предотвращения XSS
    sanitizeInputs: function() {
        // Перехват всех форм и входных полей
        document.addEventListener('submit', (e) => {
            const form = e.target;
            const inputs = form.querySelectorAll('input, textarea');
            
            inputs.forEach(input => {
                const value = input.value;
                // Проверка на потенциальные XSS инъекции
                if (this.detectXSSPattern(value)) {
                    e.preventDefault();
                    this.triggerDefense("XSS attempt detected", true);
                    console.warn('[SECURITY] Potential XSS attack blocked');
                    input.value = this.sanitizeValue(value);
                }
            });
        });
    },
    
    // Проверка на наличие подозрительных XSS паттернов
    detectXSSPattern: function(value) {
        if (!value) return false;
        
        // Регулярные выражения для выявления распространенных XSS атак
        const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript\s*:/gi,
            /on\w+\s*=/gi,
            /style\s*=\s*["'].*expression\s*\(/gi,
            /data\s*:\s*text\/html/gi
        ];
        
        return xssPatterns.some(pattern => pattern.test(value));
    },
    
    // Санитизация подозрительных значений
    sanitizeValue: function(value) {
        return value
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#x27;")
            .replace(/`/g, "&#x60;")
            .replace(/\(/g, "&#40;")
            .replace(/\)/g, "&#41;");
    },
    
    // Защита от подделки запросов (CSRF)
    preventBruteForce: function() {
        let requestCount = 0;
        let lastRequestTime = Date.now();
        
        // Мониторинг запросов
        const checkRequest = () => {
            const now = Date.now();
            const timeDiff = now - lastRequestTime;
            
            // Если запросы слишком частые
            if (timeDiff < 1000) {
                requestCount++;
                
                if (requestCount > 10) {
                    this.triggerDefense("Brute force attempt detected", false); // Не блокируем UI
                    requestCount = 0;
                }
            } else {
                requestCount = 0;
            }
            
            lastRequestTime = now;
        };
        
        // Прослушивание всех кликов
        document.addEventListener('click', checkRequest, { passive: true });
    },
    
    // Защита от изменения кода страницы
    setupAntiTampering: function() {
        const originalStyles = {};
        const originalContent = {};
        
        // Сохранение оригинальных стилей важных элементов
        document.querySelectorAll('.robot-container, .nav-links, .main-nav').forEach(el => {
            originalStyles[el.className] = el.style.cssText;
            originalContent[el.className] = el.innerHTML;
        });
        
        // Проверка целостности элементов страницы
        setInterval(() => {
            document.querySelectorAll('.robot-container, .nav-links, .main-nav').forEach(el => {
                // Проверка на изменения стилей
                if (originalStyles[el.className] && 
                    originalStyles[el.className] !== el.style.cssText) {
                    console.warn('[SECURITY] Element styling was modified');
                    el.style.cssText = originalStyles[el.className];
                }
                
                // Проверка на внедрение вредоносного кода
                if (originalContent[el.className] && 
                    this.detectXSSPattern(el.innerHTML)) {
                    console.warn('[SECURITY] DOM tampering detected');
                    el.innerHTML = originalContent[el.className];
                }
            });
        }, 2000);
    }
};

// Функционал для переключения языков
function initLanguageSwitcher() {
    // Получаем кнопки переключения языков
    const langButtons = document.querySelectorAll('.lang-btn');
    
    // Проверяем, есть ли сохраненный язык в localStorage
    const savedLang = localStorage.getItem('selectedLanguage') || 'en';
    
    // Функция для изменения языка
    function changeLanguage(lang) {
        // Получаем все элементы с атрибутами data-en и data-ru
        const elements = document.querySelectorAll('[data-' + lang + ']');
        
        // Обновляем текст для каждого элемента
        elements.forEach(element => {
            const translation = element.getAttribute('data-' + lang);
            if (translation) {
                // Если элемент имеет дочерний span, обновляем только его
                const span = element.querySelector('span');
                if (span) {
                    span.textContent = translation;
                } else {
                    element.textContent = translation;
                }
            }
        });
        
        // Обновляем атрибут lang у html
        document.documentElement.lang = lang;
        
        // Сохраняем выбранный язык в localStorage
        localStorage.setItem('selectedLanguage', lang);
        
        // Обновляем активную кнопку
        langButtons.forEach(btn => {
            if (btn.getAttribute('data-lang') === lang) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }
    
    // Используем делегирование событий для обработки кликов по кнопкам
    document.querySelector('.language-switcher').addEventListener('click', function(e) {
        const btn = e.target.closest('.lang-btn');
        if (btn) {
            const lang = btn.getAttribute('data-lang');
            changeLanguage(lang);
        }
    });
    
    // Устанавливаем язык при загрузке страницы
    changeLanguage(savedLang);
}

// Улучшенное мобильное меню
function initMobileMenu() {
    // Создаем кнопку мобильного меню если её ещё нет
    if (!document.querySelector('.mobile-menu-btn')) {
        const mobileMenuBtn = document.createElement('button');
        mobileMenuBtn.className = 'mobile-menu-btn';
        mobileMenuBtn.setAttribute('aria-label', 'Toggle menu');
        mobileMenuBtn.innerHTML = '<span></span><span></span><span></span>';
        document.querySelector('.main-nav').prepend(mobileMenuBtn);
    }
    
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const navLinks = document.querySelector('.nav-links');
    
    // Добавляем обработчик для открытия/закрытия меню
    mobileMenuBtn.addEventListener('click', function(e) {
        e.stopPropagation(); // Prevent click propagation
        navLinks.classList.toggle('active');
        this.classList.toggle('active');
    });
    
    // Закрываем меню при клике на пункт меню
    navLinks.addEventListener('click', function(e) {
        if (e.target.classList.contains('nav-link')) {
            navLinks.classList.remove('active');
            mobileMenuBtn.classList.remove('active');
        }
    });
    
    // Закрываем меню при клике вне меню
    document.addEventListener('click', function(e) {
        if (navLinks.classList.contains('active') && 
            !e.target.closest('.nav-links') && 
            !e.target.closest('.mobile-menu-btn')) {
            navLinks.classList.remove('active');
            mobileMenuBtn.classList.remove('active');
        }
    });
    
    // Закрываем меню при нажатии кнопки ESC
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && navLinks.classList.contains('active')) {
            navLinks.classList.remove('active');
            mobileMenuBtn.classList.remove('active');
        }
    });
    
    // Закрываем меню при прокрутке (с небольшой задержкой)
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        clearTimeout(scrollTimeout);
        scrollTimeout = setTimeout(function() {
            if (navLinks.classList.contains('active') && window.scrollY > 100) {
                navLinks.classList.remove('active');
                mobileMenuBtn.classList.remove('active');
            }
        }, 100);
    });
}

// Улучшенная загрузка и инициализация 3D модели робота
async function initRobot() {
    try {
        // Получаем контейнер для Spline
        const splineContainer = document.getElementById('spline-container');
        if (!splineContainer) return;

        // Определяем, мобильное ли устройство
        const isMobile = window.innerWidth <= 768 || 
                         ('ontouchstart' in window) || 
                         (navigator.maxTouchPoints > 0);
        
        // Создаем экземпляр Application из Spline Runtime
        const spline = new window.SplineLoader();
        
        // Настройка качества в зависимости от устройства
        const quality = isMobile ? 'low' : 'high';
        const scale = isMobile ? 0.5 : 0.7;
        
        // Загружаем модель из локального файла с настройками для оптимальной производительности
        const app = await spline.loadFile('./scene.splinecode', {
            credentials: 'same-origin',
            background: { alpha: true }, // Прозрачный фон
            environmentPreset: 'neutral',
            rendererParams: {
                powerPreference: isMobile ? 'default' : 'high-performance',
                antialias: !isMobile, // Отключаем для мобильных устройств
                alpha: true
            },
            quality: quality // Низкое качество для мобильных устройств
        });
        
        // Добавляем canvas в контейнер
        splineContainer.appendChild(app.canvas);

        // Настраиваем сцену
        const scene = app.findObjectByName('Scene');
        if (scene) {
            // Отключаем управление камерой, чтобы робот был статичным
            app.setCamera(scene.findObjectByName('Default Camera'));
            app.disableAllControls();
        }

        // Получаем объект робота
        const robot = app.findObjectByName('Robot') || app.findObjectById('Robot');
        
        // Управляем рендерингом в зависимости от видимости
        setupVisibilityControl(app);
        
    } catch (error) {
        console.error('Ошибка при загрузке 3D модели:', error);
        // Если не удалось загрузить модель, добавляем запасной вариант
        fallbackToIframe();
    }
}

// Улучшенная настройка управления видимостью и рендерингом
function setupVisibilityControl(splineApp) {
    // Флаг для отслеживания видимости робота
    let isVisible = true;
    let renderingPaused = false;
    
    // Создаем IntersectionObserver для отслеживания видимости
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            // Обновляем статус видимости
            isVisible = entry.isIntersecting;
            
            // Управляем рендерингом в зависимости от видимости
            if (isVisible && renderingPaused) {
                // Возобновляем рендеринг
                splineApp.play();
                renderingPaused = false;
            } else if (!isVisible && !renderingPaused) {
                // Приостанавливаем рендеринг для экономии ресурсов
                splineApp.pause();
                renderingPaused = true;
            }
        });
    }, { threshold: 0.1 });
    
    // Начинаем наблюдение за контейнером робота
    observer.observe(document.querySelector('.robot-container'));
    
    // Также приостанавливаем рендеринг, когда вкладка неактивна
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            splineApp.pause();
            renderingPaused = true;
        } else if (isVisible) {
            splineApp.play();
            renderingPaused = false;
        }
    });
    
    // Приостанавливаем рендеринг на мобильных устройствах при скролле для улучшения производительности
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        if (window.innerWidth <= 768) {
            if (!renderingPaused) {
                splineApp.pause();
                renderingPaused = true;
            }
            
            clearTimeout(scrollTimeout);
            scrollTimeout = setTimeout(function() {
                if (isVisible && renderingPaused) {
                    splineApp.play();
                    renderingPaused = false;
                }
            }, 200);
        }
    }, { passive: true });
}

// Улучшенный запасной вариант с iframe для мобильных устройств
function fallbackToIframe() {
    const splineContainer = document.getElementById('spline-container');
    if (!splineContainer) return;
    
    // Определяем, мобильное ли устройство
    const isMobile = window.innerWidth <= 768 || 
                     ('ontouchstart' in window) || 
                     (navigator.maxTouchPoints > 0);
    
    // Создаем iframe как запасной вариант с адаптивными стилями
    const iframe = document.createElement('iframe');
    iframe.src = "https://my.spline.design/nexbotrobotcharacterconcept-B4SOFIJdzJ9yhXgdkApFKw2q/";
    iframe.frameBorder = "0";
    iframe.width = "100%";
    iframe.height = "100%";
    iframe.style.position = "absolute";
    iframe.style.top = "0";
    iframe.style.left = "0";
    iframe.style.width = "100%";
    iframe.style.height = isMobile ? "140%" : "160%";
    
    // Адаптивный масштаб в зависимости от устройства
    if (isMobile) {
        if (window.innerWidth <= 380) {
            iframe.style.transform = "translateY(0) scale(0.4)";
        } else if (window.innerWidth <= 480) {
            iframe.style.transform = "translateY(-5%) scale(0.5)";
        } else {
            iframe.style.transform = "translateY(-10%) scale(0.6)";
        }
    } else {
        iframe.style.transform = "translateY(-15%) scale(0.7)";
    }
    
    iframe.style.transformOrigin = "center";
    
    // Добавляем iframe в контейнер
    splineContainer.innerHTML = '';
    splineContainer.appendChild(iframe);
    
    // Добавляем слушатель изменения размера окна для адаптивности
    window.addEventListener('resize', function() {
        const isMobileNow = window.innerWidth <= 768;
        
        if (isMobileNow) {
            iframe.style.height = "140%";
            
            if (window.innerWidth <= 380) {
                iframe.style.transform = "translateY(0) scale(0.4)";
            } else if (window.innerWidth <= 480) {
                iframe.style.transform = "translateY(-5%) scale(0.5)";
            } else {
                iframe.style.transform = "translateY(-10%) scale(0.6)";
            }
        } else {
            iframe.style.height = "160%";
            iframe.style.transform = "translateY(-15%) scale(0.7)";
        }
    });
}

// Оптимизированная анимация для полос навыков
function initSkillBars() {
    const skillItems = document.querySelectorAll('.skill-item');
    if (skillItems.length === 0) return;
    
    // Используем IntersectionObserver для анимации при прокрутке
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const skillBar = entry.target.querySelector('.skill-level');
                skillBar.style.width = skillBar.style.width || '0%';
                
                // Используем requestAnimationFrame для плавной анимации
                requestAnimationFrame(() => {
                    skillBar.style.transition = 'width 1s ease-in-out';
                    requestAnimationFrame(() => {
                        skillBar.style.width = entry.target.querySelector('.skill-percent').textContent;
                    });
                });
                
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.3 });
    
    // Наблюдаем за каждым элементом навыка
    skillItems.forEach(item => {
        observer.observe(item);
    });
}

// Плавная прокрутка к якорям с учётом мобильного меню
function initSmoothScrolling() {
    document.addEventListener('click', function(e) {
        const link = e.target.closest('a[href^="#"]');
        if (!link) return;
        
        const targetId = link.getAttribute('href');
        if (!targetId || targetId === '#') return;
        
        const targetElement = document.querySelector(targetId);
        if (!targetElement) return;
        
        e.preventDefault();
        
        // Закрываем мобильное меню если оно открыто
        const navLinks = document.querySelector('.nav-links');
        const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
        
        if (navLinks.classList.contains('active')) {
            navLinks.classList.remove('active');
            mobileMenuBtn.classList.remove('active');
        }
        
        // Учитываем высоту навигационной панели
        const navHeight = document.querySelector('.main-nav').offsetHeight;
        const targetPosition = targetElement.getBoundingClientRect().top + window.pageYOffset;
        const offsetPosition = targetPosition - navHeight;
        
        // Плавная прокрутка с учётом мобильных устройств
        window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
        });
    });
}

// Функция для проверки поддержки WebP (для оптимизации изображений)
function checkWebpSupport() {
    const webpTest = new Image();
    webpTest.onload = function() {
        const result = (webpTest.width > 0) && (webpTest.height > 0);
        document.documentElement.classList.add(result ? 'webp' : 'no-webp');
    };
    webpTest.onerror = function() {
        document.documentElement.classList.add('no-webp');
    };
    webpTest.src = 'data:image/webp;base64,UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==';
}

// Функция для адаптации контента под высоту экрана на мобильных устройствах
function adaptContentToScreenHeight() {
    const hero = document.querySelector('.hero');
    const vh = window.innerHeight * 0.01;
    
    // Устанавливаем CSS переменную, которую можно использовать вместо vh
    document.documentElement.style.setProperty('--vh', `${vh}px`);
    
    // Устанавливаем высоту для первой секции
    hero.style.height = `calc(var(--vh, 1vh) * 100)`;
    
    // Обновляем высоту при изменении размера окна
    window.addEventListener('resize', () => {
        const vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
        hero.style.height = `calc(var(--vh, 1vh) * 100)`;
    });
}

// Оптимизация загрузки изображений
function lazyLoadImages() {
    if ('loading' in HTMLImageElement.prototype) {
        // Если браузер поддерживает нативную ленивую загрузку
        const images = document.querySelectorAll('img[loading="lazy"]');
        images.forEach(img => {
            img.src = img.dataset.src;
            if (img.dataset.srcset) {
                img.srcset = img.dataset.srcset;
            }
        });
    } else {
        // Fallback для браузеров без поддержки
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/lazysizes/5.3.2/lazysizes.min.js';
        document.body.appendChild(script);
    }
}

// Инициализация всех функций при загрузке страницы
document.addEventListener('DOMContentLoaded', function() {
    // Инициализация системы безопасности
    SecuritySystem.init();
    
    // Инициализация переключателя языков
    initLanguageSwitcher();
    
    // Инициализация мобильного меню
    initMobileMenu();
    
    // Инициализация 3D модели робота
    initRobot();
    
    // Инициализация анимации полос навыков
    initSkillBars();
    
    // Инициализация плавной прокрутки к якорям
    initSmoothScrolling();
    
    // Проверка поддержки WebP
    checkWebpSupport();
    
    // Адаптация контента под высоту экрана
    adaptContentToScreenHeight();
    
    // Ленивая загрузка изображений
    lazyLoadImages();
}); 
