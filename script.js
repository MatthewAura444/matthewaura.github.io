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

// Инициализация мобильного меню с улучшенной поддержкой для телефонов
function initMobileMenu() {
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const navLinks = document.querySelector('.nav-links');
    
    if (!mobileMenuBtn || !navLinks) return; // Выход если элементы не найдены
    
    // Удаляем все предыдущие обработчики событий
    const newMobileBtn = mobileMenuBtn.cloneNode(true);
    mobileMenuBtn.parentNode.replaceChild(newMobileBtn, mobileMenuBtn);
    
    // Добавляем новый обработчик для мобильного меню с поддержкой тач-событий
    newMobileBtn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.toggle('active');
        navLinks.classList.toggle('active');
        
        if (navLinks.classList.contains('active')) {
            document.body.style.overflow = 'hidden'; // Предотвращаем прокрутку страницы
        } else {
            document.body.style.overflow = ''; // Восстанавливаем прокрутку
        }
        
        return false;
    });
    
    // Добавляем обработчик для тач-событий
    newMobileBtn.addEventListener('touchend', function(e) {
        e.preventDefault();
        e.stopPropagation();
        this.classList.toggle('active');
        navLinks.classList.toggle('active');
        
        if (navLinks.classList.contains('active')) {
            document.body.style.overflow = 'hidden'; // Предотвращаем прокрутку страницы
        } else {
            document.body.style.overflow = ''; // Восстанавливаем прокрутку
        }
        
        return false;
    }, {passive: false});
    
    // Закрытие мобильного меню при клике по ссылке
    document.querySelectorAll('.nav-links .nav-link').forEach(link => {
        link.addEventListener('click', () => {
            newMobileBtn.classList.remove('active');
            navLinks.classList.remove('active');
            document.body.style.overflow = ''; // Восстанавливаем прокрутку
        });
    });
    
    // Закрытие меню при изменении ориентации экрана
    window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
            newMobileBtn.classList.remove('active');
            navLinks.classList.remove('active');
            document.body.style.overflow = ''; // Восстанавливаем прокрутку
        }
    });
}

// Загрузка и инициализация 3D модели робота
async function initRobot() {
    try {
        // Получаем контейнер для Spline
        const splineContainer = document.getElementById('spline-container');
        if (!splineContainer) return;

        // Создаем экземпляр Application из Spline Runtime
        const spline = new window.SplineLoader();
        
        // Загружаем модель из локального файла
        const app = await spline.loadFile('./scene.splinecode', {
            // Настройки для оптимальной производительности
            credentials: 'same-origin',
            background: { alpha: true }, // Прозрачный фон
            environmentPreset: 'neutral',
            rendererParams: {
                powerPreference: 'high-performance',
                antialias: true,
                alpha: true
            }
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

// Настройка управления видимостью и рендерингом
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
}

// Запасной вариант с iframe, если не удалось загрузить модель
function fallbackToIframe() {
    const splineContainer = document.getElementById('spline-container');
    if (!splineContainer) return;
    
    // Создаем iframe как запасной вариант
    const iframe = document.createElement('iframe');
    iframe.src = "https://my.spline.design/nexbotrobotcharacterconcept-B4SOFIJdzJ9yhXgdkApFKw2q/";
    iframe.frameBorder = "0";
    iframe.width = "100%";
    iframe.height = "100%";
    iframe.style.position = "absolute";
    iframe.style.top = "0";
    iframe.style.left = "0";
    iframe.style.width = "100%";
    iframe.style.height = "160%";
    iframe.style.transform = "translateY(-15%) scale(0.7)";
    iframe.style.transformOrigin = "center";
    
    // Добавляем iframe в контейнер
    splineContainer.innerHTML = '';
    splineContainer.appendChild(iframe);
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

// Плавная прокрутка к якорям
function initSmoothScrolling() {
    document.addEventListener('click', function(e) {
        const link = e.target.closest('a[href^="#"]');
        if (!link) return;
        
        const targetId = link.getAttribute('href');
        if (!targetId || targetId === '#') return;
        
        const targetElement = document.querySelector(targetId);
        if (!targetElement) return;
        
                    e.preventDefault();
        
        // Плавная прокрутка с учетом фиксированной навигации
        const navHeight = document.querySelector('.main-nav').offsetHeight;
        const targetPosition = targetElement.getBoundingClientRect().top + window.pageYOffset - navHeight;
        
                window.scrollTo({
            top: targetPosition,
                    behavior: 'smooth'
        });
    });
}

// Этот блок намеренно пропущен, чтобы избежать дублирования инициализации

// Добавляем оптимизации для производительности
window.addEventListener('load', function() {
    // Отложенная загрузка изображений
    const lazyImages = document.querySelectorAll('img[loading="lazy"]');
    if ('loading' in HTMLImageElement.prototype) {
        lazyImages.forEach(img => {
            if (img.dataset.src) {
                img.src = img.dataset.src;
                delete img.dataset.src;
            }
        });
    } else {
        // Фолбек для браузеров без поддержки lazy loading
        const lazyImageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    if (img.dataset.src) {
                        img.src = img.dataset.src;
                        delete img.dataset.src;
                    }
                    observer.unobserve(img);
                }
            });
        });
        
        lazyImages.forEach(img => {
            lazyImageObserver.observe(img);
        });
    }
}); 

// Оптимизация отображения 3D модели робота на мобильных устройствах
function optimizeRobotForMobile() {
    // Определяем, является ли устройство мобильным
    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) || window.innerWidth < 768;
    
    if (isMobile) {
        // Находим контейнер Spline
        const splineContainer = document.getElementById('spline-container');
        if (splineContainer) {
            // Если есть канвас внутри контейнера, применяем стили
            const canvas = splineContainer.querySelector('canvas');
            if (canvas) {
                // Базовые настройки позиционирования
                canvas.style.transformOrigin = 'center center';
                canvas.style.maxWidth = '100%';
                canvas.style.maxHeight = '100%';
                
                // Делаем контейнер робота видимым за границами
                const robotContainer = document.querySelector('.robot-container');
                if (robotContainer) {
                    // Настройка для оптимального отображения робота
                    robotContainer.style.overflow = 'visible';
                    robotContainer.style.width = '350%';
                    robotContainer.style.left = '-125%';
                    robotContainer.style.right = '-125%';
                    
                    // Оптимизация для производительности
                    robotContainer.style.willChange = 'transform';
                    robotContainer.style.backfaceVisibility = 'hidden';
                    robotContainer.style.webkitBackfaceVisibility = 'hidden';
                }
                
                // Предотвращаем дергание при скролле
                document.body.style.overscrollBehavior = 'none';
                document.documentElement.style.overscrollBehavior = 'none';
            }
        }
    }
}

// Улучшенная инициализация для мобильных устройств
document.addEventListener('DOMContentLoaded', function() {
    // Инициализация системы безопасности
    SecuritySystem.init();
    
    // Инициализация переключателя языков
    initLanguageSwitcher();
    
    // Инициализация 3D робота
    initRobot();
    
    // Оптимизация отображения робота на мобильных устройствах
    optimizeRobotForMobile();
    
    // Инициализация анимации шкал навыков
    initSkillBars();
    
    // Инициализация плавной прокрутки
    initSmoothScrolling();
    
    // Обработка ориентации экрана для мобильных устройств
    handleDeviceOrientation();
    
    // Инициализация мобильного меню с небольшой задержкой для надежности
    setTimeout(function() {
        initMobileMenu();
    }, 300);
    
    // Переинициализация при изменении размера окна
    window.addEventListener('resize', function() {
        optimizeRobotForMobile();
        handleDeviceOrientation();
    });
    
    // Обработка изменений ориентации устройства
    window.addEventListener('orientationchange', function() {
        setTimeout(() => {
            optimizeRobotForMobile();
            handleDeviceOrientation();
            // Переинициализация мобильного меню при изменении ориентации
            initMobileMenu();
        }, 300);
    });
});

// Функция для обработки изменений ориентации экрана
function handleDeviceOrientation() {
    const isLandscape = window.innerWidth > window.innerHeight;
    const isMobile = window.innerWidth < 768 || /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    
    if (isMobile && isLandscape && window.innerHeight < 500) {
        // Если мобильное устройство в ландшафтной ориентации с малой высотой
        document.documentElement.classList.add('landscape-mobile');
        
        // CSS управляет стилями трансформации для робота в разных ориентациях
    } else {
        document.documentElement.classList.remove('landscape-mobile');
    }
    
    // Всегда делаем контейнер робота видимым за границами
    const robotContainer = document.querySelector('.robot-container');
    if (robotContainer) {
        robotContainer.style.overflow = 'visible';
    }
} 
