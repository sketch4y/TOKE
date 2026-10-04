// ============================================================
//  ТокË — ЗАЩИЩЁННЫЙ СКРИПТ v5.4
//  Фото в корне (без папки images/)
// ============================================================

// ⚠️ ЗАМЕНИТЕ НА СВОЙ URL ИЗ APPS SCRIPT
const GOOGLE_SHEETS_URL = 'https://script.google.com/macros/s/AKfycbxjbn-PgiO9U__sHRKKgGl1Oq7_PeYtAlq5eOLm2EVvQv-s7g-O2s0rzW28UziAhnPIiA/exec';

// ============================================================
//  БЛОК 1: ЗАЩИТА ОТ XSS
// ============================================================

function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/\//g, '&#x2F;');
}

function isSafeURL(url) {
    if (!url) return false;
    try {
        const parsed = new URL(url, window.location.origin);
        return ['http:', 'https:', 'data:'].includes(parsed.protocol);
    } catch {
        return false;
    }
}

// ============================================================
//  БЛОК 2: ВАЛИДАЦИЯ
// ============================================================

function isValidName(name) {
    if (!name) return false;
    const trimmed = name.trim();
    return trimmed.length >= 2 && trimmed.length <= 50;
}

function isValidPhone(phone) {
    if (!phone) return false;
    const cleaned = phone.replace(/[\s\-\(\)]/g, '');
    return /^\+?[0-9]{10,15}$/.test(cleaned);
}

function isValidNumber(value, min = 0, max = 999999) {
    const num = parseFloat(value);
    return !isNaN(num) && num >= min && num <= max;
}

// ============================================================
//  БЛОК 3: КРИПТОГРАФИЯ
// ============================================================

const PASSWORD_SALT = 'tokyo_salt_2026_secure';
const PASSWORD_ITERATIONS = 100000;

async function hashPasswordSecure(password) {
    try {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw', encoder.encode(password),
            { name: 'PBKDF2' }, false, ['deriveBits']
        );
        const hashBuffer = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: encoder.encode(PASSWORD_SALT),
                iterations: PASSWORD_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial, 256
        );
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
        console.error('Ошибка хеширования:', e);
        return null;
    }
}

const ORDER_SIGNATURE_KEY = 'tokyo_order_signature_2026';

async function signOrder(order) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw', encoder.encode(ORDER_SIGNATURE_KEY),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const orderString = JSON.stringify(order, Object.keys(order).sort());
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(orderString));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// ============================================================
//  БЛОК 4: CSRF
// ============================================================

const CSRF_TOKEN_KEY = 'tokyoCSRFToken';
const CSRF_EXPIRY = 60 * 60 * 1000;

function generateCSRFToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const token = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
    sessionStorage.setItem(CSRF_TOKEN_KEY, JSON.stringify({ token, created: Date.now() }));
    return token;
}

function getCSRFToken() {
    const stored = sessionStorage.getItem(CSRF_TOKEN_KEY);
    if (!stored) return generateCSRFToken();
    try {
        const data = JSON.parse(stored);
        if (Date.now() - data.created > CSRF_EXPIRY) return generateCSRFToken();
        return data.token;
    } catch {
        return generateCSRFToken();
    }
}

function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

function verifyCSRFToken(token) {
    const stored = sessionStorage.getItem(CSRF_TOKEN_KEY);
    if (!stored) return false;
    try {
        const data = JSON.parse(stored);
        if (Date.now() - data.created > CSRF_EXPIRY) return false;
        return timingSafeEqual(token, data.token);
    } catch {
        return false;
    }
}

function checkOrigin() {
    const referrer = document.referrer;
    if (!referrer) return true;
    try {
        const referrerOrigin = new URL(referrer).origin;
        return referrerOrigin === window.location.origin;
    } catch {
        return false;
    }
}

// ============================================================
//  БЛОК 5: RATE LIMITING
// ============================================================

const RATE_LIMIT_KEY = 'tokyoRateLimit';
const MAX_ORDERS_PER_HOUR = 5;

function checkRateLimit() {
    const now = Date.now();
    const hourAgo = now - 60 * 60 * 1000;
    let requests = [];
    try {
        requests = JSON.parse(localStorage.getItem(RATE_LIMIT_KEY)) || [];
    } catch {
        requests = [];
    }
    requests = requests.filter(time => time > hourAgo);
    if (requests.length >= MAX_ORDERS_PER_HOUR) return false;
    requests.push(now);
    localStorage.setItem(RATE_LIMIT_KEY, JSON.stringify(requests));
    return true;
}

// ============================================================
//  БЛОК 6: БРУТФОРС
// ============================================================

const LOGIN_ATTEMPTS_KEY = 'tokyoLoginAttempts';
const MAX_LOGIN_ATTEMPTS = 5;
const BLOCK_TIME = 15 * 60 * 1000;

function checkLoginBlock() {
    try {
        const data = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY)) || { count: 0, blockedUntil: 0 };
        if (data.blockedUntil > Date.now()) {
            const remaining = Math.ceil((data.blockedUntil - Date.now()) / 60000);
            showToast(`🔒 Слишком много попыток. Подождите ${remaining} мин.`);
            return false;
        }
        return true;
    } catch {
        return true;
    }
}

function recordFailedAttempt() {
    try {
        const data = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY)) || { count: 0, blockedUntil: 0 };
        data.count++;
        if (data.count >= MAX_LOGIN_ATTEMPTS) {
            data.blockedUntil = Date.now() + BLOCK_TIME;
            data.count = 0;
            showToast('🔒 Аккаунт заблокирован на 15 минут');
        }
        localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(data));
    } catch (e) {}
}

function resetLoginAttempts() {
    localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify({ count: 0, blockedUntil: 0 }));
}

// ============================================================
//  БЛОК 7: КОНСТАНТЫ
// ============================================================

const ADMIN_PASSWORD_HASH_KEY = 'tokyoAdminPasswordHash';
const ADMIN_SESSION_KEY = 'tokyoAdminSession';
const SESSION_TIMEOUT = 30 * 60 * 1000;
const MAX_QTY = 99;

let isAdminLoggedIn = localStorage.getItem(ADMIN_SESSION_KEY) === 'true';
let sessionTimer = null;

// ============================================================
//  БЛОК 8: ДАННЫЕ (ФОТО БЕЗ ПАПКИ images/)
// ============================================================

function getDefaultData() {
    return {
        defaultProducts: [
            // ===== РОЛЛЫ =====
            { id: 1, name: 'Чили-вечиринка', desc: 'Лосось, сливочный сыр, огурец', weight: '250 г', price: 699, category: 'rolls', calories: 380, image: 'chili-party.jpg' },
            { id: 2, name: 'Манго-Креветка', desc: 'Креветка, манго, сливочный сыр', weight: '300 г', price: 649, category: 'rolls', calories: 340, image: 'mango-shrimp.jpg' },
            { id: 3, name: 'Филка с клубникой', desc: 'Рис, нори, сыр сливочный, клубника, лосось', weight: '280 г', price: 749, category: 'rolls', calories: 420, image: 'strawberry-filka.jpg' },
            { id: 4, name: 'Манго-кисс', desc: 'Манго, лосось, сыр', weight: '260 г', price: 699, category: 'rolls', calories: 380, image: 'mango-kiss.jpg' },
            { id: 5, name: 'Креветочный бриз', desc: 'Рис, рисовая бумага, сыр сливочный, креветки в темпура, салат', weight: '260 г', price: 649, category: 'rolls', calories: 340, image: 'shrimp-breeze.jpg' },
            { id: 6, name: 'Мангомания', desc: 'Рис, рисовая бумага, сыр сливочный, лосось, манго', weight: '250 г', price: 649, category: 'rolls', calories: 380, image: 'mangomania.jpg' },
            { id: 7, name: 'Карамельная филка', desc: 'Лосось, карамель, кунжут', weight: '280 г', price: 749, category: 'rolls', calories: 420, image: 'caramel-filka.jpg' },
            { id: 8, name: 'Ролл опаленный с гребешком', desc: 'Гребешок, соус, кунжут', weight: '260 г', price: 749, category: 'rolls', calories: 420, image: 'roll-scallop.jpg' },
            { id: 9, name: 'Ролл ройс', desc: 'Ассорти из 4 роллов', weight: '300 г', price: 899, category: 'rolls', calories: 500, image: 'roll-royce.jpg' },

            // ===== СУШИ =====
            { id: 10, name: 'Дымчатый жемчуг', desc: 'Рис, рисовая бумага, сыр сливочный, лосось, тобико, лук зеленый', weight: '250 г', price: 399, category: 'sushi', calories: 240, image: 'smoky-pearl.jpg' },
            { id: 11, name: 'Аками', desc: 'Тунец, рис, васаби', weight: '250 г', price: 450, category: 'sushi', calories: 260, image: 'akami.jpg' },

            // ===== ПИЦЦА (пока пусто) =====

            // ===== СЕТЫ =====
            { id: 12, name: 'Сет номер 1', desc: 'Ассорти роллов и суши', weight: '950 г', price: 1590, category: 'sets', calories: 1800, image: 'set-1.jpg' },
            { id: 13, name: 'Сет номер 2', desc: 'Большой сет для компании', weight: '1100 г', price: 1890, category: 'sets', calories: 2100, image: 'set-2.jpg' },
            { id: 14, name: 'Сет номер 3', desc: 'Премиум сет', weight: '1200 г', price: 2290, category: 'sets', calories: 2300, image: 'set-3.jpg' },
            { id: 15, name: 'Сет суши', desc: 'Ассорти суши', weight: '800 г', price: 1290, category: 'sets', calories: 1500, image: 'set-sushi.jpg' },
            { id: 16, name: 'Сет гунканов', desc: 'Ассорти гунканов', weight: '700 г', price: 1390, category: 'sets', calories: 1400, image: 'set-gunkan.jpg' },
            { id: 17, name: 'Сет Маки', desc: 'Ассорти маки-роллов', weight: '850 г', price: 1490, category: 'sets', calories: 1700, image: 'set-maki.jpg' },
            { id: 18, name: 'Сет фруктовый сад', desc: 'Фруктовые роллы', weight: '700 г', price: 1390, category: 'sets', calories: 1200, image: 'set-fruit.jpg' }
        ],
        defaultPromos: [
            // ===== АКЦИИ (СКИДКИ, БОНУСЫ — БЕЗ СЕТОВ) =====
            { title: '🔥 Скидка 20%', desc: 'На первый заказ от 2000 ₽' },
            { title: '🎁 Напиток в подарок', desc: 'При заказе от 1500 ₽' },
            { title: '🍱 Бесплатная доставка', desc: 'При заказе от 2500 ₽' },
            { title: '💝 Бонус 300 ₽', desc: 'На следующий заказ' }
        ],
        defaultReviews: [
            { name: 'Анна', rating: 5, text: 'Очень вкусно! Доставка быстрая.', date: '12.02.2025' },
            { name: 'Иван', rating: 5, text: 'Лучшие роллы в городе!', date: '10.02.2025' },
            { name: 'Мария', rating: 4, text: 'Пицца отличная!', date: '08.02.2025' }
        ],
        defaultSettings: {
            phone: '+7 910 835 42 29',
            address: 'г. Тверь, ул. Гусева 46',
            pickup: 'Самовывоз: ул. Гусева 46',
            minOrder: 1000,
            about: '<p>Мы готовим суши, роллы и пиццу из качественных продуктов.</p>',
            delivery: '<p><strong>📍 Доставка осуществляется по Твери в районах: Московский, Центральный, Пролетарский, Первомайский</strong></p>'
        }
    };
}

function loadData() {
    const { defaultProducts, defaultPromos, defaultReviews, defaultSettings } = getDefaultData();
    try {
        return {
            products: JSON.parse(localStorage.getItem('tokyoProducts')) || defaultProducts,
            promos: JSON.parse(localStorage.getItem('tokyoPromos')) || defaultPromos,
            reviews: JSON.parse(localStorage.getItem('tokyoReviews')) || defaultReviews,
            settings: JSON.parse(localStorage.getItem('tokyoSettings')) || defaultSettings,
            orders: JSON.parse(localStorage.getItem('tokyoOrders')) || []
        };
    } catch {
        return { products: defaultProducts, promos: defaultPromos, reviews: defaultReviews, settings: defaultSettings, orders: [] };
    }
}

let data = loadData();
let cart = [];
try { cart = JSON.parse(localStorage.getItem('tokyoCart')) || []; } catch { cart = []; }
let currentFilter = 'all';
let nextProductId = data.products.length ? Math.max(...data.products.map(p => p.id)) + 1 : 1;

// ============================================================
//  БЛОК 9: DOM
// ============================================================

const popularGrid = document.getElementById('popularGrid');
const menuGrid = document.getElementById('menuGrid');
const promoGrid = document.getElementById('promoGrid');
const reviewsGrid = document.getElementById('reviewsGrid');
const cartBadge = document.getElementById('cartBadge');
const cartItemsContainer = document.getElementById('cartItemsContainer');
const cartTotal = document.getElementById('cartTotal');
const cartMinWarning = document.getElementById('cartMinWarning');

// ============================================================
//  БЛОК 10: СОХРАНЕНИЕ
// ============================================================

async function saveAllData() {
    try {
        localStorage.setItem('tokyoProducts', JSON.stringify(data.products));
        localStorage.setItem('tokyoPromos', JSON.stringify(data.promos));
        localStorage.setItem('tokyoReviews', JSON.stringify(data.reviews));
        localStorage.setItem('tokyoSettings', JSON.stringify(data.settings));
        localStorage.setItem('tokyoOrders', JSON.stringify(data.orders));
        localStorage.setItem('tokyoCart', JSON.stringify(cart));
    } catch (e) {
        console.error('Ошибка сохранения:', e);
    }
}

// ============================================================
//  БЛОК 11: ВСПОМОГАТЕЛЬНЫЕ
// ============================================================

function showToast(msg) {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => toast.classList.remove('show'), 3000);
}

function getCartTotal() {
    return cart.reduce((s, i) => s + Number(i.price) * Number(i.qty), 0);
}

function getCartCount() {
    return cart.reduce((s, i) => s + Number(i.qty), 0);
}

function resetSessionTimer() {
    if (!isAdminLoggedIn) return;
    clearTimeout(sessionTimer);
    sessionTimer = setTimeout(() => {
        if (isAdminLoggedIn) {
            logoutAdmin();
            showToast('🔒 Сессия истекла');
        }
    }, SESSION_TIMEOUT);
}

// ============================================================
//  БЛОК 12: 📧 ОТПРАВКА В GOOGLE ТАБЛИЦУ
// ============================================================

async function sendOrderToGoogleSheets(orderData) {
    try {
        const itemsText = orderData.items
            .map(i => `${i.name} × ${i.qty} = ${i.price * i.qty} ₽`)
            .join('\n');

        const formData = new FormData();
        formData.append('date', orderData.date || '');
        formData.append('name', orderData.name || '');
        formData.append('phone', orderData.phone || '');
        formData.append('delivery', orderData.delivery || '');
        formData.append('street', orderData.street || '');
        formData.append('house', orderData.house || '');
        formData.append('apartment', orderData.apartment || '');
        formData.append('entrance', orderData.entrance || '');
        formData.append('floor', orderData.floor || '');
        formData.append('comment', orderData.comment || '');
        formData.append('payment', orderData.payment || '');
        formData.append('items', itemsText);
        formData.append('total', orderData.total || 0);

        console.log('📤 Отправка заказа:', {
            name: orderData.name,
            phone: orderData.phone,
            total: orderData.total
        });

        const response = await fetch(GOOGLE_SHEETS_URL, {
            method: 'POST',
            body: formData
        });

        console.log('✅ Заказ отправлен в Google Sheets');
        return true;

    } catch (error) {
        console.error('❌ Ошибка отправки:', error);
        return false;
    }
}

// ============================================================
//  БЛОК 13: КОРЗИНА
// ============================================================

function updateCartUI() {
    if (cartBadge) cartBadge.textContent = getCartCount();
    renderCartItems();
    const total = getCartTotal();
    if (cartTotal) cartTotal.textContent = total + ' ₽';
    if (cartMinWarning) {
        cartMinWarning.style.display = (total < data.settings.minOrder && cart.length > 0) ? 'block' : 'none';
    }
}

function renderCartItems() {
    if (!cartItemsContainer) return;
    if (!cart.length) {
        cartItemsContainer.innerHTML = '<p style="text-align:center; padding:2rem; color:#888;">🛒 Корзина пуста</p>';
        return;
    }
    let html = '';
    cart.forEach((item) => {
        html += `
            <div class="cart-item">
                <div class="item-info">
                    <strong>${escapeHTML(item.name)}</strong>
                    <span style="color:#888; font-size:0.9rem;">${Number(item.price)} ₽ × ${Number(item.qty)}</span>
                </div>
                <div class="item-controls">
                    <button class="cart-qty-minus" data-id="${Number(item.id)}">−</button>
                    <span style="font-weight:600; min-width:24px; text-align:center;">${Number(item.qty)}</span>
                    <button class="cart-qty-plus" data-id="${Number(item.id)}">+</button>
                    <button class="cart-remove" data-id="${Number(item.id)}"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `;
    });
    cartItemsContainer.innerHTML = html;
    cartItemsContainer.querySelectorAll('.cart-qty-minus').forEach(btn =>
        btn.addEventListener('click', () => changeQty(Number(btn.dataset.id), -1)));
    cartItemsContainer.querySelectorAll('.cart-qty-plus').forEach(btn =>
        btn.addEventListener('click', () => changeQty(Number(btn.dataset.id), 1)));
    cartItemsContainer.querySelectorAll('.cart-remove').forEach(btn =>
        btn.addEventListener('click', () => removeFromCart(Number(btn.dataset.id))));
}

function changeQty(id, delta) {
    const item = cart.find(i => i.id === id);
    if (!item) return;
    const newQty = Number(item.qty) + delta;
    if (newQty <= 0) cart = cart.filter(i => i.id !== id);
    else item.qty = Math.min(newQty, MAX_QTY);
    saveAllData();
    updateCartUI();
}

function removeFromCart(id) {
    cart = cart.filter(i => i.id !== id);
    saveAllData();
    updateCartUI();
    showToast('Товар удалён');
}

function addToCart(id) {
    const product = data.products.find(p => p.id === id);
    if (!product || product.price === 0) {
        showToast('Это акция без стоимости');
        return;
    }
    const existing = cart.find(i => i.id === id);
    if (existing) existing.qty = Math.min(Number(existing.qty) + 1, MAX_QTY);
    else cart.push({ id: product.id, name: product.name, price: product.price, calories: product.calories, qty: 1 });
    saveAllData();
    updateCartUI();
    showToast(`✅ ${escapeHTML(product.name)} добавлен`);
}

// ============================================================
//  БЛОК 14: ОТРИСОВКА ТОВАРОВ
// ============================================================

function renderProducts(gridId, list, filter = 'all') {
    const grid = document.getElementById(gridId);
    if (!grid) return;
    const filtered = filter === 'all' ? list : list.filter(p => p.category === filter);
    if (!filtered.length) {
        grid.innerHTML = '<p style="grid-column:1/-1; text-align:center; padding:3rem; color:#888;">Товары не найдены</p>';
        return;
    }
    const isAdmin = isAdminLoggedIn && document.getElementById('adminPanel')?.classList.contains('open');
    grid.innerHTML = filtered.map(p => {
        const safeImage = isSafeURL(p.image) ? escapeHTML(p.image) : '';
        return `
            <div class="product-card">
                ${isAdmin ? `
                    <div class="admin-actions show">
                        <button onclick="editProduct(${Number(p.id)})"><i class="fas fa-pen"></i></button>
                        <button onclick="deleteProduct(${Number(p.id)})"><i class="fas fa-trash"></i></button>
                    </div>
                ` : ''}
                <img src="${safeImage}" alt="${escapeHTML(p.name)}" loading="lazy" />
                <h4>${escapeHTML(p.name)}</h4>
                <div class="desc">${escapeHTML(p.desc)}</div>
                <div class="weight">${escapeHTML(p.weight)}</div>
                <div class="calories"><i class="fas fa-fire" style="color:#ff6b35;"></i> ${Number(p.calories) || 0} ккал</div>
                <div class="price">${Number(p.price) > 0 ? Number(p.price) + ' ₽' : 'По акции'}</div>
                ${Number(p.price) > 0
                    ? `<button class="add-to-cart" data-id="${Number(p.id)}">Добавить в корзину</button>`
                    : `<button class="add-to-cart" disabled>Недоступно</button>`}
            </div>
        `;
    }).join('');
    grid.querySelectorAll('.add-to-cart:not([disabled])').forEach(btn => {
        btn.addEventListener('click', () => addToCart(Number(btn.dataset.id)));
    });
}

// ============================================================
//  БЛОК 15: АКЦИИ И ОТЗЫВЫ
// ============================================================

function renderPromos() {
    if (!promoGrid) return;
    const isAdmin = isAdminLoggedIn && document.getElementById('adminPanel')?.classList.contains('open');
    promoGrid.innerHTML = data.promos.map((item, i) => `
        <div class="promo-card">
            ${isAdmin ? `<div class="admin-actions show"><button onclick="deletePromo(${i})"><i class="fas fa-trash"></i></button></div>` : ''}
            <h3>${escapeHTML(item.title)}</h3>
            <p>${escapeHTML(item.desc)}</p>
        </div>
    `).join('');
}

function renderReviews() {
    if (!reviewsGrid) return;
    const isAdmin = isAdminLoggedIn && document.getElementById('adminPanel')?.classList.contains('open');
    reviewsGrid.innerHTML = data.reviews.map((r, i) => `
        <div class="review-card">
            ${isAdmin ? `<div class="admin-actions show"><button onclick="deleteReview(${i})"><i class="fas fa-trash"></i></button></div>` : ''}
            <div><span class="name">${escapeHTML(r.name)}</span> <span class="date">${escapeHTML(r.date)}</span></div>
            <div class="rating">${'⭐'.repeat(Math.min(Math.max(Number(r.rating) || 0, 0), 5))}</div>
            <p>${escapeHTML(r.text)}</p>
        </div>
    `).join('');
}

// ============================================================
//  БЛОК 16: ОФОРМЛЕНИЕ ЗАКАЗА
// ============================================================

document.getElementById('orderForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();

    if (!checkOrigin()) {
        showToast('❌ Неверный источник запроса');
        return;
    }

    const csrfInput = document.querySelector('input[name="csrf_token"]');
    if (!csrfInput) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = getCSRFToken();
        e.target.appendChild(input);
    } else if (!verifyCSRFToken(csrfInput.value)) {
        showToast('❌ Ошибка безопасности. Обновите страницу.');
        return;
    }

    const name = document.getElementById('orderName')?.value.trim() || '';
    const phone = document.getElementById('orderPhone')?.value.trim() || '';
    const delivery = document.getElementById('orderDeliveryType')?.value || 'delivery';
    const street = document.getElementById('orderStreet')?.value.trim() || '';
    const house = document.getElementById('orderHouse')?.value.trim() || '';
    const apartment = document.getElementById('orderApartment')?.value.trim() || '';
    const entrance = document.getElementById('orderEntrance')?.value.trim() || '';
    const floor = document.getElementById('orderFloor')?.value.trim() || '';

    if (!isValidName(name)) {
        showToast('⚠️ Имя: 2-50 символов');
        document.getElementById('orderName').focus();
        return;
    }
    if (!isValidPhone(phone)) {
        showToast('⚠️ Неверный телефон');
        document.getElementById('orderPhone').focus();
        return;
    }

    if (delivery === 'delivery') {
        if (!street || street.length < 3) {
            showToast('⚠️ Введите улицу');
            document.getElementById('orderStreet').focus();
            return;
        }
        if (!house) {
            showToast('⚠️ Введите номер дома');
            document.getElementById('orderHouse').focus();
            return;
        }
        if (!apartment) {
            showToast('⚠️ Введите квартиру');
            document.getElementById('orderApartment').focus();
            return;
        }
        if (!entrance) {
            showToast('⚠️ Введите подъезд');
            document.getElementById('orderEntrance').focus();
            return;
        }
        if (!floor) {
            showToast('⚠️ Введите этаж');
            document.getElementById('orderFloor').focus();
            return;
        }
    }

    const consent = document.getElementById('privacyConsent');
    if (!consent?.checked) {
        showToast('⚠️ Нужно согласие на обработку данных');
        return;
    }

    if (!checkRateLimit()) {
        showToast('⚠️ Слишком много заказов');
        return;
    }

    const orderData = {
        id: Date.now(),
        date: new Date().toLocaleString('ru-RU'),
        name: escapeHTML(name),
        phone: escapeHTML(phone),
        delivery: delivery,
        street: escapeHTML(street),
        house: escapeHTML(house),
        apartment: escapeHTML(apartment),
        entrance: escapeHTML(entrance),
        floor: escapeHTML(floor),
        comment: escapeHTML(document.getElementById('orderComment')?.value.trim() || ''),
        payment: document.getElementById('orderPayment')?.value || 'cash',
        items: cart.map(i => ({
            name: escapeHTML(i.name),
            qty: Number(i.qty),
            price: Number(i.price)
        })),
        total: getCartTotal(),
        calories: cart.reduce((s, i) => s + (Number(i.calories) || 0) * Number(i.qty), 0)
    };

    const submitBtn = document.getElementById('submitOrderBtn');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = '⏳ Отправка...';
    }

    showToast('⏳ Отправляем заказ...');

    const success = await sendOrderToGoogleSheets(orderData);

    if (success) {
        const signature = await signOrder(orderData);
        orderData.signature = signature;

        data.orders.unshift(orderData);
        await saveAllData();

        showToast('🎉 Спасибо за заказ! Мы скоро свяжемся.');

        cart = [];
        await saveAllData();
        updateCartUI();

        document.getElementById('orderModal')?.classList.remove('open');
        e.target.reset();

        const deliveryFields = document.getElementById('deliveryFields');
        if (deliveryFields) deliveryFields.style.display = 'grid';

        renderOrders();
    } else {
        showToast('❌ Ошибка отправки. Попробуйте ещё раз.');
    }

    if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Оформить заказ';
    }
});

// ============================================================
//  БЛОК 17: ИСТОРИЯ ЗАКАЗОВ
// ============================================================

function renderOrders() {
    const container = document.getElementById('ordersList');
    if (!container) return;
    if (!data.orders.length) {
        container.innerHTML = '<p style="text-align:center;color:#888;padding:40px;">Заказов пока нет</p>';
        return;
    }
    container.innerHTML = data.orders.map(order => `
        <div class="order-history-item">
            <div class="order-header">
                <span>📦 Заказ #${escapeHTML(order.id)}</span>
                <span>${escapeHTML(order.date)}</span>
            </div>
            <div class="order-details">
                ${escapeHTML(order.name)} | ${escapeHTML(order.phone)}
                ${order.delivery === 'delivery'
                    ? ` | ${escapeHTML(order.street)} ${escapeHTML(order.house)}`
                    : ' | Самовывоз'}
                | ${order.payment === 'online' ? '💳 Онлайн' : order.payment === 'terminal' ? '💳 Терминал' : '💰 Наличные'}
            </div>
            <div class="order-items">
                ${order.items.map(i => `${escapeHTML(i.name)} × ${Number(i.qty)}`).join(', ')}
                | <strong>${Number(order.total)} ₽</strong>
            </div>
        </div>
    `).join('');
    const navLink = document.getElementById('ordersNavLink');
    if (navLink) navLink.style.display = data.orders.length ? 'block' : 'none';
}

// ============================================================
//  БЛОК 18: АДМИН
// ============================================================

async function initAdminPassword() {
    if (!localStorage.getItem(ADMIN_PASSWORD_HASH_KEY)) {
        const defaultHash = await hashPasswordSecure('tokyo2026');
        if (defaultHash) localStorage.setItem(ADMIN_PASSWORD_HASH_KEY, defaultHash);
    }
    getCSRFToken();
}

function showAdminLogin() {
    if (!checkLoginBlock()) return;
    document.getElementById('adminLoginOverlay')?.classList.add('open');
    const input = document.getElementById('adminPasswordInput');
    if (input) { input.value = ''; setTimeout(() => input.focus(), 100); }
    const error = document.getElementById('adminLoginError');
    if (error) error.style.display = 'none';
}

function hideAdminLogin() {
    document.getElementById('adminLoginOverlay')?.classList.remove('open');
}

async function checkAdminPassword(password) {
    if (!checkLoginBlock()) return false;
    const inputHash = await hashPasswordSecure(password);
    const storedHash = localStorage.getItem(ADMIN_PASSWORD_HASH_KEY);
    if (inputHash && inputHash === storedHash) {
        isAdminLoggedIn = true;
        localStorage.setItem(ADMIN_SESSION_KEY, 'true');
        resetLoginAttempts();
        hideAdminLogin();
        openAdminPanel();
        document.getElementById('adminIndicator')?.classList.add('show');
        resetSessionTimer();
        showToast('✅ Вход выполнен');
        return true;
    } else {
        recordFailedAttempt();
        const error = document.getElementById('adminLoginError');
        if (error) error.style.display = 'block';
        return false;
    }
}

function logoutAdmin() {
    isAdminLoggedIn = false;
    localStorage.setItem(ADMIN_SESSION_KEY, 'false');
    document.getElementById('adminPanel')?.classList.remove('open');
    document.getElementById('adminIndicator')?.classList.remove('show');
    document.querySelectorAll('.admin-actions').forEach(el => el.classList.remove('show'));
    clearTimeout(sessionTimer);
    showToast('🔒 Выход');
    renderAll();
}

function openAdminPanel() {
    if (!isAdminLoggedIn) { showAdminLogin(); return; }
    const panel = document.getElementById('adminPanel');
    if (!panel) return;
    panel.classList.toggle('open');
    if (panel.classList.contains('open')) {
        renderAll();
        updateAdminLists();
        document.querySelectorAll('.admin-actions').forEach(el => el.classList.add('show'));
    } else {
        document.querySelectorAll('.admin-actions').forEach(el => el.classList.remove('show'));
        renderAll();
    }
}

// ============================================================
//  БЛОК 19: СЕКРЕТНЫЕ 12 КЛИКОВ
// ============================================================

let clickCount = 0;
let clickTimer = null;

function initSecretLogo() {
    const logo = document.getElementById('secretLogo');
    if (!logo) return;
    logo.addEventListener('click', (e) => {
        e.stopPropagation();
        if (isAdminLoggedIn) return;
        clickCount++;
        if (clickCount >= 12) {
            clickCount = 0;
            clearTimeout(clickTimer);
            showAdminLogin();
            showToast('🔐 Введите пароль');
        }
        clearTimeout(clickTimer);
        clickTimer = setTimeout(() => { clickCount = 0; }, 3000);
    });
}

// ============================================================
//  БЛОК 20: ПОКАЗ/СКРЫТИЕ ПОЛЕЙ АДРЕСА
// ============================================================

function initOrderForm() {
    const deliveryType = document.getElementById('orderDeliveryType');
    const fields = document.getElementById('deliveryFields');
    if (!deliveryType || !fields) return;

    if (deliveryType.value === 'delivery') {
        fields.style.display = 'grid';
    } else {
        fields.style.display = 'none';
    }

    deliveryType.addEventListener('change', (e) => {
        if (e.target.value === 'delivery') {
            fields.style.display = 'grid';
            ['orderStreet', 'orderHouse', 'orderApartment', 'orderEntrance', 'orderFloor'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.required = true;
            });
        } else {
            fields.style.display = 'none';
            ['orderStreet', 'orderHouse', 'orderApartment', 'orderEntrance', 'orderFloor'].forEach(id => {
                const el = document.getElementById(id);
                if (el) { el.required = false; el.value = ''; }
            });
        }
    });
}

// ============================================================
//  БЛОК 21: ВСЕ ОСТАЛЬНЫЕ ОБРАБОТЧИКИ
// ============================================================

document.getElementById('cartBtn')?.addEventListener('click', () => {
    document.getElementById('cartModal')?.classList.add('open');
    updateCartUI();
});
document.getElementById('cartModalClose')?.addEventListener('click', () => {
    document.getElementById('cartModal')?.classList.remove('open');
});
document.getElementById('cartModal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
});

document.getElementById('caloriesBtn')?.addEventListener('click', () => {
    document.getElementById('caloriesModal')?.classList.add('open');
    updateCalories();
});
document.getElementById('caloriesModalClose')?.addEventListener('click', () => {
    document.getElementById('caloriesModal')?.classList.remove('open');
});

document.getElementById('profileBtn')?.addEventListener('click', () => {
    document.getElementById('profileModal')?.classList.add('open');
    const nameEl = document.getElementById('profileName');
    const phoneEl = document.getElementById('profilePhone');
    if (nameEl) nameEl.value = localStorage.getItem('profileName') || '';
    if (phoneEl) phoneEl.value = localStorage.getItem('profilePhone') || '';
});
document.getElementById('profileModalClose')?.addEventListener('click', () => {
    document.getElementById('profileModal')?.classList.remove('open');
});
document.getElementById('profileSaveBtn')?.addEventListener('click', () => {
    const name = document.getElementById('profileName')?.value.trim() || '';
    const phone = document.getElementById('profilePhone')?.value.trim() || '';
    if (name && !isValidName(name)) { showToast('⚠️ Неверное имя'); return; }
    if (phone && !isValidPhone(phone)) { showToast('⚠️ Неверный телефон'); return; }
    if (name) localStorage.setItem('profileName', escapeHTML(name));
    if (phone) localStorage.setItem('profilePhone', escapeHTML(phone));
    showToast('✅ Сохранено');
    document.getElementById('profileModal')?.classList.remove('open');
});

document.getElementById('clearCartBtn')?.addEventListener('click', async () => {
    cart = [];
    await saveAllData();
    updateCartUI();
    showToast('Корзина очищена');
});

document.getElementById('checkoutBtn')?.addEventListener('click', () => {
    const total = getCartTotal();
    if (total < data.settings.minOrder) {
        showToast(`⚠️ Минимум ${data.settings.minOrder} ₽`);
        return;
    }
    if (!cart.length) { showToast('⚠️ Корзина пуста'); return; }
    document.getElementById('cartModal')?.classList.remove('open');
    document.getElementById('orderModal')?.classList.add('open');
    const nameEl = document.getElementById('orderName');
    const phoneEl = document.getElementById('orderPhone');
    if (nameEl) nameEl.value = localStorage.getItem('profileName') || '';
    if (phoneEl) phoneEl.value = localStorage.getItem('profilePhone') || '';
});

document.getElementById('orderModalClose')?.addEventListener('click', () => {
    document.getElementById('orderModal')?.classList.remove('open');
});
document.getElementById('orderModal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
});

document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        renderProducts('menuGrid', data.products, btn.dataset.filter);
    });
});

document.getElementById('menuToggle')?.addEventListener('click', () => {
    document.getElementById('mainNav')?.classList.toggle('open');
});

document.querySelectorAll('nav a').forEach(a => {
    a.addEventListener('click', () => document.getElementById('mainNav')?.classList.remove('open'));
});

document.getElementById('adminLoginBtn')?.addEventListener('click', () => {
    const password = document.getElementById('adminPasswordInput')?.value || '';
    checkAdminPassword(password);
});

document.getElementById('adminPasswordInput')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('adminLoginBtn')?.click();
});

document.getElementById('adminLogoutBtn')?.addEventListener('click', logoutAdmin);

document.getElementById('closeAdminPanel')?.addEventListener('click', () => {
    document.getElementById('adminPanel')?.classList.remove('open');
    document.querySelectorAll('.admin-actions').forEach(el => el.classList.remove('show'));
    renderAll();
});

document.querySelectorAll('.admin-tabs button').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.admin-tabs button').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.admin-section').forEach(s => s.classList.remove('active'));
        document.getElementById('tab-' + btn.dataset.tab)?.classList.add('active');
    });
});

// ============================================================
//  БЛОК 22: АДМИН ДЕЙСТВИЯ
// ============================================================

document.getElementById('adminAddProductBtn')?.addEventListener('click', async () => {
    if (!isAdminLoggedIn) return;
    const name = document.getElementById('adminProductName')?.value.trim() || '';
    const desc = document.getElementById('adminProductDesc')?.value.trim() || '';
    const price = parseInt(document.getElementById('adminProductPrice')?.value);
    const weight = document.getElementById('adminProductWeight')?.value.trim() || '';
    const calories = parseInt(document.getElementById('adminProductCalories')?.value) || 0;
    const category = document.getElementById('adminProductCategory')?.value || 'rolls';
    const image = document.getElementById('adminProductImage')?.value.trim() || 'https://images.unsplash.com/photo-1579871494447-9811cf80d66c?w=300&h=200&fit=crop';

    if (!isValidName(name)) { showToast('⚠️ Название 2-50 символов'); return; }
    if (!desc || desc.length < 3) { showToast('⚠️ Описание минимум 3 символа'); return; }
    if (!isValidNumber(price, 1, 999999)) { showToast('⚠️ Цена от 1 ₽'); return; }

    data.products.push({
        id: nextProductId++,
        name: escapeHTML(name),
        desc: escapeHTML(desc),
        price: price,
        weight: escapeHTML(weight),
        calories: calories,
        category: category,
        image: escapeHTML(image)
    });

    await saveAllData();
    updateAdminLists();
    renderAll();
    showToast('✅ Товар добавлен');

    ['adminProductName', 'adminProductDesc', 'adminProductPrice', 'adminProductWeight', 'adminProductCalories', 'adminProductImage'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
});

window.deleteProduct = async function(id) {
    if (!isAdminLoggedIn) return;
    if (!confirm('Удалить товар?')) return;
    data.products = data.products.filter(p => p.id !== id);
    cart = cart.filter(i => i.id !== id);
    await saveAllData();
    updateAdminLists();
    renderAll();
    showToast('🗑️ Удалено');
};

window.editProduct = async function(id) {
    if (!isAdminLoggedIn) return;
    const p = data.products.find(x => x.id === id);
    if (!p) return;
    const name = prompt('Название:', p.name);
    if (name && isValidName(name)) p.name = escapeHTML(name);
    const price = prompt('Цена:', p.price);
    if (price && isValidNumber(price, 1)) p.price = parseInt(price);
    await saveAllData();
    renderAll();
    showToast('✅ Обновлено');
};

document.getElementById('adminAddPromoBtn')?.addEventListener('click', async () => {
    if (!isAdminLoggedIn) return;
    const title = document.getElementById('adminPromoTitle')?.value.trim() || '';
    const desc = document.getElementById('adminPromoDesc')?.value.trim() || '';
    if (!title || !desc) { showToast('⚠️ Заполните поля'); return; }
    data.promos.push({ title: escapeHTML(title), desc: escapeHTML(desc) });
    await saveAllData();
    updateAdminLists();
    renderPromos();
    showToast('✅ Акция добавлена');
    document.getElementById('adminPromoTitle').value = '';
    document.getElementById('adminPromoDesc').value = '';
});

window.deletePromo = async function(index) {
    if (!isAdminLoggedIn) return;
    if (!confirm('Удалить?')) return;
    data.promos.splice(index, 1);
    await saveAllData();
    updateAdminLists();
    renderPromos();
    showToast('🗑️ Удалено');
};

document.getElementById('adminAddReviewBtn')?.addEventListener('click', async () => {
    if (!isAdminLoggedIn) return;
    const name = document.getElementById('adminReviewName')?.value.trim() || '';
    const text = document.getElementById('adminReviewText')?.value.trim() || '';
    const rating = parseInt(document.getElementById('adminReviewRating')?.value) || 5;
    const date = document.getElementById('adminReviewDate')?.value.trim() || new Date().toLocaleDateString('ru-RU');
    if (!isValidName(name) || !text) { showToast('⚠️ Заполните поля'); return; }
    data.reviews.push({ name: escapeHTML(name), text: escapeHTML(text), rating: rating, date: escapeHTML(date) });
    await saveAllData();
    updateAdminLists();
    renderReviews();
    showToast('✅ Отзыв добавлен');
    ['adminReviewName', 'adminReviewText', 'adminReviewRating', 'adminReviewDate'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
});

window.deleteReview = async function(index) {
    if (!isAdminLoggedIn) return;
    if (!confirm('Удалить?')) return;
    data.reviews.splice(index, 1);
    await saveAllData();
    updateAdminLists();
    renderReviews();
    showToast('🗑️ Удалено');
};

document.getElementById('adminSaveSettingsBtn')?.addEventListener('click', async () => {
    if (!isAdminLoggedIn) return;
    const phone = document.getElementById('adminPhone')?.value.trim();
    const address = document.getElementById('adminAddress')?.value.trim();
    const pickup = document.getElementById('adminPickup')?.value.trim();
    const minOrder = parseInt(document.getElementById('adminMinOrder')?.value);
    if (phone) data.settings.phone = escapeHTML(phone);
    if (address) data.settings.address = escapeHTML(address);
    if (pickup) data.settings.pickup = escapeHTML(pickup);
    if (minOrder) data.settings.minOrder = minOrder;
    await saveAllData();
    updateSettingsUI();
    showToast('✅ Сохранено');
});

document.getElementById('adminChangePasswordBtn')?.addEventListener('click', async () => {
    if (!isAdminLoggedIn) return;
    const p1 = document.getElementById('adminNewPassword')?.value || '';
    const p2 = document.getElementById('adminNewPasswordConfirm')?.value || '';
    if (p1.length < 8) { showToast('⚠️ Минимум 8 символов'); return; }
    if (p1 !== p2) { showToast('⚠️ Пароли не совпадают'); return; }
    const hash = await hashPasswordSecure(p1);
    if (hash) {
        localStorage.setItem(ADMIN_PASSWORD_HASH_KEY, hash);
        showToast('🔑 Пароль изменён');
        document.getElementById('adminNewPassword').value = '';
        document.getElementById('adminNewPasswordConfirm').value = '';
    }
});

document.getElementById('adminResetBtn')?.addEventListener('click', () => {
    if (!isAdminLoggedIn) return;
    if (!confirm('⚠️ ВСЕ ДАННЫЕ БУДУТ УДАЛЕНЫ!')) return;
    localStorage.clear();
    sessionStorage.clear();
    location.reload();
});

function updateAdminLists() {
    if (!isAdminLoggedIn) return;
    const productList = document.getElementById('adminProductList');
    if (productList) {
        productList.innerHTML = data.products.map(p =>
            `<div class="list-item"><span>${escapeHTML(p.name)} — ${Number(p.price)}₽</span><button onclick="deleteProduct(${Number(p.id)})">✕</button></div>`
        ).join('');
    }
    const promoList = document.getElementById('adminPromoList');
    if (promoList) {
        promoList.innerHTML = data.promos.map((p, i) =>
            `<div class="list-item"><span>${escapeHTML(p.title)}</span><button onclick="deletePromo(${i})">✕</button></div>`
        ).join('');
    }
    const reviewList = document.getElementById('adminReviewList');
    if (reviewList) {
        reviewList.innerHTML = data.reviews.map((r, i) =>
            `<div class="list-item"><span>${escapeHTML(r.name)}</span><button onclick="deleteReview(${i})">✕</button></div>`
        ).join('');
    }
    const phoneEl = document.getElementById('adminPhone');
    const addressEl = document.getElementById('adminAddress');
    const pickupEl = document.getElementById('adminPickup');
    const minOrderEl = document.getElementById('adminMinOrder');
    if (phoneEl) phoneEl.value = data.settings.phone;
    if (addressEl) addressEl.value = data.settings.address;
    if (pickupEl) pickupEl.value = data.settings.pickup;
    if (minOrderEl) minOrderEl.value = data.settings.minOrder;
}

function updateSettingsUI() {
    const phoneEl = document.getElementById('contactPhone');
    const addressEl = document.getElementById('contactAddress');
    const pickupEl = document.getElementById('contactPickup');
    if (phoneEl) phoneEl.textContent = data.settings.phone;
    if (addressEl) addressEl.textContent = data.settings.address;
    if (pickupEl) pickupEl.textContent = data.settings.pickup;
}

function updateCalories() {
    const total = cart.reduce((s, i) => s + (Number(i.calories) || 0) * Number(i.qty), 0);
    const totalEl = document.getElementById('totalCalories');
    if (totalEl) totalEl.textContent = total;
    const bar = document.getElementById('caloriesBar');
    if (bar) bar.style.width = Math.min((total / 2000) * 100, 100) + '%';
}

function renderAll() {
    renderProducts('popularGrid', data.products.slice(0, 6));
    renderProducts('menuGrid', data.products, currentFilter);
    renderPromos();
    renderReviews();
    updateSettingsUI();
    updateCartUI();
    updateCalories();
    updateAdminLists();
    renderOrders();
}

// ============================================================
//  БЛОК 23: ИНИЦИАЛИЗАЦИЯ
// ============================================================

async function init() {
    await initAdminPassword();
    initSecretLogo();
    initOrderForm();
    renderAll();

    if (isAdminLoggedIn) {
        document.getElementById('adminIndicator')?.classList.add('show');
        resetSessionTimer();
    }

    console.log('%c🛡️ ТокË — Защищённая версия 5.4', 'color:#d32f2f; font-size:16px; font-weight:bold;');
    console.log('✅ Фото без папки images/');
    console.log('✅ Все защиты активны');
}

window.filterMenu = function(filter) {
    currentFilter = filter;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`.filter-btn[data-filter="${filter}"]`)?.classList.add('active');
    renderProducts('menuGrid', data.products, filter);
    document.getElementById('menu')?.scrollIntoView({ behavior: 'smooth' });
};

window.addToCart = addToCart;
window.escapeHTML = escapeHTML;

init();
