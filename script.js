const API_URL = "https://api.mcptool.net/mcptool/dbs/search";
const API_USER = "Thund3rHun";
const API_PASS = "Bertalan285628";
const SYSTEM_CODE = "Windows 10.0-#-8d6c7662d0fe4f58498e74c814b0cf8d5fda8a03e0ce5f632c9df1b39393ca01";
const XOR_KEY = "L3/kK{Z8K@D[732{;50u~/\\YETz@Uwv?xl~9i#iUzZ.gH!c3b?";

// DOM Elements
const appContainer = document.getElementById('appContainer');
const searchSection = document.querySelector('.search-section');
const searchInput = document.getElementById('searchInput');
const searchBtn = document.getElementById('searchBtn');
const resultsArea = document.getElementById('results');
const loader = document.getElementById('loader');
const profileHeader = document.getElementById('profileHeader');
const userAvatar = document.getElementById('userAvatar');
const profileName = document.getElementById('profileName');
const resultStatus = document.getElementById('resultStatus');
const creditsDisplay = document.createElement('div'); // Credit Display

// Inject Credit Display
creditsDisplay.className = 'credits-display hidden';
document.body.appendChild(creditsDisplay);

searchBtn.addEventListener('click', performSearch);
searchInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') performSearch();
});

async function performSearch() {
    const displayQuery = searchInput.value.trim(); // Preserve case for display
    const query = displayQuery.toLowerCase();      // Lowercase for API
    if (!query) return;

    // --- ANIMATION START ---
    // 1. Transition to split layout
    appContainer.classList.add('has-results');

    // 2. Add loading effects
    searchSection.classList.add('searching');
    loader.classList.remove('hidden');
    resultsArea.classList.remove('results-loaded');
    resultsArea.classList.remove('results-loaded');
    resultsArea.innerHTML = ''; // Clear previous
    searchBtn.disabled = true;

    // Clear Session Cache on new search
    unlockedCache.clear();
    unlockedUUIDs.clear();

    // 3. Setup Profile Placeholder
    profileHeader.classList.remove('hidden');
    profileName.textContent = displayQuery; // Use original casing
    resultStatus.textContent = "Buscando...";
    resultStatus.style.color = "var(--text-muted)";
    resultStatus.style.borderColor = "rgba(255,255,255,0.1)";

    // 4. Load Avatar (Minotar)
    userAvatar.src = `https://minotar.net/helm/${query}/300.png`;
    userAvatar.onerror = () => { userAvatar.src = 'https://minotar.net/helm/steve/300.png'; };

    // Wait for basic layout transition to finish visually (nice effect)
    await new Promise(r => setTimeout(r, 800));

    try {
        const params = new URLSearchParams({
            username: API_USER,
            password: API_PASS,
            system_code: SYSTEM_CODE,
            username_to_search: query
        });

        const response = await fetch(`${API_URL}?${params.toString()}`);

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const json = await response.json();

        if (json.data) {
            const decryptedData = decryptData(json.data);
            let parsedResults = [];

            try {
                parsedResults = JSON.parse(decryptedData);
            } catch (e) {
                try {
                    const jsonFriendly = decryptedData
                        .replace(/'/g, '"')
                        .replace(/None/g, 'null')
                        .replace(/False/g, 'false')
                        .replace(/True/g, 'true');
                    parsedResults = JSON.parse(jsonFriendly);
                } catch (e2) {
                    throw new Error("Parse: " + e2.message);
                }
            }

            // Success
            if (parsedResults.length > 0 && parsedResults[0].username) {
                profileName.textContent = parsedResults[0].username; // Update with canonical name from DB
            }
            updateProfileStatus(parsedResults.length);
            renderResults(parsedResults);

        } else {
            updateProfileStatus(0, true);
            showError("Sin datos en la respuesta.");
        }

    } catch (error) {
        console.error(error);
        updateProfileStatus(0, true);
        showError("Error: " + error.message);
    } finally {
        searchSection.classList.remove('searching');
        loader.classList.add('hidden');
        searchBtn.disabled = false;
        // Trigger generic fade in for results container
        resultsArea.classList.add('results-loaded');
    }
}

function updateProfileStatus(count, isError = false) {
    if (isError) {
        resultStatus.textContent = "Error";
        resultStatus.style.color = "#ef4444";
        resultStatus.style.borderColor = "#ef4444";
    } else if (count === 0) {
        resultStatus.textContent = "0 Resultados";
        resultStatus.style.color = "#eab308";
        resultStatus.style.borderColor = "#eab308";
    } else {
        resultStatus.textContent = `${count} Resultados`;
        resultStatus.style.color = "#22c55e"; // Green
        resultStatus.style.borderColor = "#22c55e";
    }
}

function decryptData(encodedStr) {
    const base64 = encodedStr.replace(/-/g, '+').replace(/_/g, '/');
    const binaryStr = atob(base64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
    }
    const xorText = new TextDecoder('utf-8').decode(bytes);
    let result = '';
    for (let i = 0; i < xorText.length; i++) {
        const charCode = xorText.charCodeAt(i);
        const keyChar = XOR_KEY.charCodeAt(i % XOR_KEY.length);
        result += String.fromCharCode(charCode ^ keyChar);
    }
    return result;
}

function renderResults(results) {
    if (!results || results.length === 0) {
        resultsArea.innerHTML = '<div class="no-results">No se encontraron registros.</div>';
        return;
    }

    results.forEach((item, index) => {
        const card = document.createElement('div');
        card.className = 'result-card';
        card.style.animationDelay = `${index * 0.05}s`;

        const pwd = item.password || '******';
        let pwdDisplay;

        if (isHash(pwd)) {
            pwdDisplay = `<span class="hash-badge" onclick="crackHash(this, '${escapeHtml(pwd)}')">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                            DESCIFRAR HASH
                          </span>`;
        } else {
            pwdDisplay = `<span class="value clickable-pass" onclick="handlePasswordAction('${escapeHtml(pwd)}')">${escapeHtml(pwd)}</span>`;
        }

        const ip = item.ip || '---';
        const cardId = `card-${index}`;
        card.id = cardId;

        card.innerHTML = `
            <div class="card-header">
                <span class="username">${escapeHtml(item.username)}</span>
                <span class="server-info">${escapeHtml(item.servername || 'N/A')}</span>
            </div>
            <div class="card-body">
                <div class="info-row">
                    <span class="label">IP</span>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <div id="geo-icon-${index}" class="geo-placeholder" style="margin-right:8px;"></div>
                        <span class="value">${escapeHtml(ip)}</span>
                        <div id="leak-icon-${index}" class="leak-placeholder"></div>
                    </div>
                </div>
                <div class="info-row">
                    <span class="label">Pass</span>
                    ${pwdDisplay}
                </div>
            </div>
        `;
        resultsArea.appendChild(card);

        // Auto Check IP
        if (ip && ip !== '---') {
            checkIPLeak(ip, index);
            queueGeoFetch(ip, index); // Add to Geo Queue
        }
    });
}

async function checkIPLeak(ip, index) {
    try {
        const res = await fetch('/api/check-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const data = await res.json();

        const leakContainer = document.getElementById(`leak-icon-${index}`);
        if (data.results && Object.keys(data.results).length > 0) {
            const leakCount = data.size || Object.keys(data.results).length;

            // Encode data to pass it safe
            const safeData = encodeURIComponent(JSON.stringify(data));

            leakContainer.innerHTML = `
                <div class="leak-warning" onclick='openLeakModal("${ip}", "${safeData}")' title="${leakCount} Filtraciones detectadas">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                </div>
            `;
        }
    } catch (err) {
        console.warn("Leak check failed for", ip);
    }
}

// Global Leak Modal
let currentLeakIp = null;
let currentLeakData = null; // Store preview data
let isLeakUnlocked = false; // Track unlock state
let unlockedUUIDs = new Set(); // Track purchased UUIDs to prevent button re-rendering
const unlockedCache = new Map(); // Cache for unlocked terms: term -> data

const leakModal = document.createElement('div');
leakModal.id = 'leakModal';
leakModal.className = 'admin-panel hidden';
leakModal.innerHTML = `
    <div class="admin-box" style="max-width: 700px;">
        <div class="admin-header">
            <h3>Filtraciones IP</h3>
            <button class="close-btn" onclick="closeLeakModal()">&times;</button>
        </div>
        <div class="leak-ui-container" style="display:flex; height:400px; gap:1rem; margin-top:1rem;">
            <!-- Left: List -->
            <div id="leakSources" style="width:200px; background:rgba(0,0,0,0.2); border-radius:12px; overflow-y:auto; padding:0.5rem; border:1px solid rgba(255,255,255,0.05);"></div>
            <!-- Right: Preview -->
            <div style="flex:1; display:flex; flex-direction:column; background:rgba(0,0,0,0.2); border-radius:12px; padding:1rem; border:1px solid rgba(255,255,255,0.05);">
                <div id="leakPreviewHeader" style="font-weight:bold; color:var(--primary-purple); margin-bottom:1rem; border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:0.5rem;">Resumen</div>
                <div id="leakPreviewContent" style="flex:1; overflow-y:auto; color:var(--text-muted); font-size:0.9rem; white-space:pre-wrap;">Selecciona una fuente para ver la vista previa.</div>
                <div style="margin-top:1rem; text-align:center; padding-top:1rem; border-top:1px solid rgba(255,255,255,0.1);">
                     <button id="unlockBtn" class="action-btn" onclick="unlockLeak()">
                        Desbloquear Todo (1 Crédito)
                     </button>
                </div>
            </div>
        </div>
    </div>
`;
document.body.appendChild(leakModal);

window.openLeakModal = function (term, encodedData, type = 'IP') {
    currentLeakIp = term;
    leakModal.dataset.type = type;

    // Check Cache
    if (unlockedCache.has(term)) {
        currentLeakData = unlockedCache.get(term);
        isLeakUnlocked = true;
    } else {
        isLeakUnlocked = false; // Reset unlock state
        if (encodedData) {
            try {
                currentLeakData = JSON.parse(decodeURIComponent(encodedData));
            } catch (e) { currentLeakData = null; }
        }
    }

    leakModal.classList.remove('hidden');

    // Update Header based on type
    const headerTitle = leakModal.querySelector('h3');
    headerTitle.textContent = type === 'PASSWORD' ? 'Rastros de Contraseña' : 'Filtraciones IP';

    renderPreviewUI();
};

function renderPreviewUI() {
    const list = document.getElementById('leakSources');
    const preview = document.getElementById('leakPreviewContent');
    const header = document.getElementById('leakPreviewHeader');
    const results = currentLeakData?.results || {};

    list.innerHTML = '';
    preview.innerHTML = 'Selecciona una base de datos de la izquierda.';
    preview.innerHTML = 'Selecciona una base de datos de la izquierda.';
    header.textContent = `${leakModal.dataset.type === 'PASSWORD' ? 'Pass' : 'IP'}: ${currentLeakIp}`;

    const sources = Object.keys(results);

    if (sources.length === 0) {
        list.innerHTML = '<div style="padding:0.5rem; color:#666">Sin datos</div>';
        return;
    }

    sources.forEach((source, idx) => {
        const item = document.createElement('div');
        item.className = 'source-item';
        item.textContent = source;
        item.onclick = () => {
            // Highlight
            document.querySelectorAll('.source-item').forEach(el => el.classList.remove('active'));
            item.classList.add('active');

            // Show Preview (Pretty Print)
            header.textContent = source;
            const entries = results[source];
            preview.innerHTML = formatLeakData(entries);
        };
        // Auto select first
        if (idx === 0) setTimeout(() => item.click(), 0);
        list.appendChild(item);
    });
}

function formatLeakData(entries) {
    if (!Array.isArray(entries) || entries.length === 0) return '<div class="no-data">Sin entradas</div>';

    let html = '<div class="leak-table-container"><table class="leak-table"><thead><tr><th>Campo</th><th>Valor</th></tr></thead><tbody>';

    entries.forEach((entry, index) => {
        // Add a separator row if multiple entries, though usually it's one per generic block
        if (index > 0) html += '<tr class="separator-row"><td colspan="2"></td></tr>';

        for (const [key, value] of Object.entries(entry)) {
            if (key.toLowerCase() === 'uuid') {
                if (isLeakUnlocked && !unlockedUUIDs.has(value)) {
                    html += `<tr>
                                <td class="leak-key">UUID</td>
                                <td class="leak-val">
                                    <button class="uuid-btn" onclick="searchByUUID('${escapeHtml(String(value))}')">
                                        Mostrar todas las filtraciones de esta máquina (-1 crédito)
                                    </button>
                                </td>
                             </tr>`;
                } else if (unlockedUUIDs.has(value)) {
                    // Show a green "View Again" button
                    html += `<tr>
                                <td class="leak-key">UUID</td>
                                <td class="leak-val">
                                    <button class="uuid-btn unlocked" onclick="searchByUUID('${escapeHtml(String(value))}')">
                                        Ver Resultados (Desbloqueado)
                                    </button>
                                </td>
                             </tr>`;
                } else {
                    html += `<tr>
                                <td class="leak-key">UUID</td>
                                <td class="leak-val">${escapeHtml(String(value))}</td>
                             </tr>`;
                }
            } else {
                html += `<tr>
                            <td class="leak-key">${key}</td>
                            <td class="leak-val">${escapeHtml(String(value))}</td>
                         </tr>`;
            }
        }
    });

    html += '</tbody></table></div>';
    return html;
}

window.searchByUUID = async function (uuid) {
    // Check Cache First
    if (unlockedCache.has(uuid)) {
        currentLeakData = unlockedCache.get(uuid);
        currentLeakIp = uuid;
        leakModal.dataset.type = 'UUID';

        unlockedUUIDs.add(uuid); // Ensure tracked
        isLeakUnlocked = true;

        renderPreviewUI();
        showToast("Cargado desde caché", "success");
        return;
    }

    if (!confirm("¿Buscar por UUID? Esto costará 1 crédito y reemplazará los resultados actuales de la vista previa.")) return;

    const currentUser = localStorage.getItem(CURRENT_USER_KEY);
    if (!currentUser) return;

    // Show loading in modal button
    const btn = document.querySelector('.uuid-btn'); // The one clicked
    const originalText = btn ? btn.innerText : '';
    if (btn) {
        btn.innerText = "Buscando...";
        btn.disabled = true;
    }

    try {
        const res = await fetch('/api/unlock-uuid', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ uuid: uuid, username: currentUser })
        });
        const data = await res.json();

        if (data.success) {
            updateCredits(data.newCredits);

            // Handle structure:
            let rawResults = {};
            if (data.data.results && data.data.results.results) {
                rawResults = data.data.results.results; // Deep nesting case
            } else if (data.data.results) {
                rawResults = data.data.results;
            }

            // GROUP BY SERVICE/DOMAIN
            // The user wants to see "Services" in the list, effectively flattening the DBs
            let groupedResults = {};

            // Iterate over each Source DB
            Object.keys(rawResults).forEach(sourceKey => {
                const entries = rawResults[sourceKey];
                if (Array.isArray(entries)) {
                    entries.forEach(entry => {
                        // Determine Domain/Service
                        let serviceName = "Desconocido";
                        if (entry.url_domain) serviceName = entry.url_domain;
                        else if (entry.login_domain) serviceName = entry.login_domain;
                        else if (entry.url_full_domain) serviceName = entry.url_full_domain;
                        else if (entry.source_db) serviceName = entry.source_db; // Fallback

                        if (!groupedResults[serviceName]) {
                            groupedResults[serviceName] = [];
                        }
                        groupedResults[serviceName].push(entry);
                    });
                }
            });

            // Update Global State with GROUPED results
            currentLeakData = { results: groupedResults };
            currentLeakIp = uuid; // Display UUID in header
            leakModal.dataset.type = 'UUID'; // Update type

            // Mark this UUID as unlocked so we don't show the button AGAIN inside its own results
            unlockedUUIDs.add(uuid);
            isLeakUnlocked = true; // Ensure new view is treated as unlocked content (preview enabled)

            // Cache the UUID result too
            unlockedCache.set(uuid, currentLeakData);

            // Re-render
            renderPreviewUI();

            showToast("Búsqueda por UUID completada", "success");
        } else {
            showToast(data.message || "Error al buscar por UUID", "error");
            if (btn) {
                btn.innerText = originalText;
                btn.disabled = false;
            }
        }
    } catch (e) {
        console.error(e);
        showToast("Error de conexión", "error");
        if (btn) {
            btn.innerText = originalText;
            btn.disabled = false;
        }
    }
};

window.closeLeakModal = function () {
    leakModal.classList.add('hidden');
    currentLeakIp = null;
    currentLeakData = null;
};

window.unlockLeak = async function (passedIp) {
    // If passedIp exists (from old calls), use it, otherwise use current global
    const term = passedIp || currentLeakIp;
    if (!term) return;

    const type = leakModal.dataset.type || 'IP';
    const endpoint = type === 'PASSWORD' ? '/api/unlock-pass' : '/api/unlock-ip';
    const payloadKey = type === 'PASSWORD' ? 'password' : 'ip';

    const btn = document.getElementById('unlockBtn');
    const currentUser = localStorage.getItem(CURRENT_USER_KEY);

    if (!currentUser) return;

    btn.textContent = "Desbloqueando...";
    btn.disabled = true;

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ [payloadKey]: term, username: currentUser })
        });

        const data = await res.json();

        if (data.success) {
            updateCredits(data.newCredits);
            isLeakUnlocked = true; // Mark as unlocked
            // Replace preview data with FULL data
            currentLeakData.results = data.data.results.results; // Ensure structure matches

            // Cache It
            unlockedCache.set(term, currentLeakData);

            renderPreviewUI(); // Re-render with full data
            btn.textContent = "¡Desbloqueado!";
            btn.style.background = "#22c55e";
        } else {
            btn.textContent = data.message || "Error";
            btn.style.background = "#ef4444";
        }
    } catch (err) {
        btn.textContent = "Error de conexión";
    }
};

function updateCredits(count) {
    creditsDisplay.textContent = `Créditos: ${count}`;
    creditsDisplay.classList.remove('hidden');
}

function isHash(text) {
    // Basic detection: MD5 (32), SHA-1 (40), SHA-256 (64), Bcrypt (60), AuthMe
    if (!text) return false;
    // Length >= 32 to catch MD5.
    // Regex must include ALL letters (a-z, A-Z) for base64/bcrypt, not just hex (a-f).
    // Also include common hash punctuation like $ . : + / =
    if (text.length >= 32 && /^[a-zA-Z0-9$+/=.:]+$/.test(text)) return true;
    return false;
}

window.crackHash = async function (el, hash) {
    if (el.classList.contains('decrypting') || el.classList.contains('found')) return;

    const originalText = el.innerHTML;
    el.classList.add('decrypting');
    el.innerHTML = `<span class="loader-spinner"></span> DESCIFRANDO...`;

    try {
        const res = await fetch('http://localhost:3000/api/crack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash: hash })
        });

        const json = await res.json();

        // Check for success in HashMob format
        if (json.data && json.data.found && json.data.found.length > 0) {
            const plain = json.data.found[0].plain;
            el.classList.remove('decrypting');
            el.classList.add('found');
            el.style.background = 'rgba(34, 197, 94, 0.1)';
            el.style.borderColor = '#22c55e';
            el.style.color = '#22c55e';
            el.style.cursor = 'default';
            el.innerHTML = escapeHtml(plain);
        } else {
            throw new Error('Not found');
        }

    } catch (err) {
        console.warn("Crack failed:", err);
        el.classList.remove('decrypting');
        el.classList.add('failed');
        el.innerHTML = "NO ENCONTRADO";
        el.style.color = "#ef4444";
        el.style.borderColor = "#ef4444";

        setTimeout(() => {
            el.classList.remove('failed');
            el.innerHTML = originalText;
            el.style.color = "";
            el.style.borderColor = "";
        }, 2000);
    }
};

function showError(msg) {
    resultsArea.innerHTML = `<div class="no-results" style="color:#ef4444">${msg}</div>`;
}

function escapeHtml(text) {
    if (!text) return text;
    return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/* AUTHENTICATION SYSTEM */
const CURRENT_USER_KEY = 'neptune_current_user';
const TOKEN_KEY = 'neptune_token';

// Init
function initAuth() {
    // Check session locally
    const currentUser = localStorage.getItem(CURRENT_USER_KEY);
    if (currentUser) {
        showApp(currentUser);
        fetchUserProfile(currentUser);
    } else {
        document.getElementById('loginOverlay').classList.remove('hidden');
    }
}

// Auth Elements
const loginBtn = document.getElementById('loginBtn');
const loginUser = document.getElementById('loginUser');
const loginPass = document.getElementById('loginPass');
const loginError = document.getElementById('loginError');
const logoutBtn = document.getElementById('logoutBtn');
const adminTriggerBtn = document.getElementById('adminTriggerBtn');
const adminPanel = document.getElementById('adminPanel');
const closeAdminBtn = document.getElementById('closeAdminBtn');
const createUserBtn = document.getElementById('createUserBtn');
const newUserInput = document.getElementById('newUser');
const newPassInput = document.getElementById('newPass');
const adminMsg = document.getElementById('adminMsg');

// Event Listeners
loginBtn.addEventListener('click', login);
loginPass.addEventListener('keypress', (e) => { if (e.key === 'Enter') login(); });
logoutBtn.addEventListener('click', logout);

adminTriggerBtn.addEventListener('click', () => {
    adminPanel.classList.remove('hidden');
    adminMsg.textContent = '';
});

closeAdminBtn.addEventListener('click', () => {
    adminPanel.classList.add('hidden');
});

createUserBtn.addEventListener('click', createUser);

async function login() {
    const user = loginUser.value.trim();
    const pass = loginPass.value.trim();

    if (!user || !pass) return;

    loginBtn.textContent = 'Verificando...';

    try {
        const res = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });

        const data = await res.json();

        if (data.success) {
            localStorage.setItem(CURRENT_USER_KEY, data.username);
            if (data.token) {
                localStorage.setItem(TOKEN_KEY, data.token); // Store secure token
            }
            // Set credits from login response
            if (data.credits !== undefined) {
                updateCredits(data.credits);
            }

            loginError.classList.add('hidden');
            showApp(data.username);
            loginUser.value = '';
            loginPass.value = '';
        } else {
            loginError.textContent = data.message || 'Error de acceso';
            loginError.classList.remove('hidden');
            loginPass.value = '';
        }
    } catch (err) {
        console.error(err);
        loginError.textContent = 'Error de conexión';
        loginError.classList.remove('hidden');
    } finally {
        loginBtn.textContent = 'Ingresar';
    }
}

function logout() {
    localStorage.removeItem(CURRENT_USER_KEY);
    localStorage.removeItem(TOKEN_KEY);
    location.reload();
}

function showApp(username) {
    document.getElementById('loginOverlay').classList.add('hidden');
    document.getElementById('appContainer').classList.remove('hidden');
    logoutBtn.classList.remove('hidden');
    creditsDisplay.classList.remove('hidden'); // Show credits immediately

    if (username === 'Weinsther') {
        adminTriggerBtn.classList.remove('hidden');
    }
}

async function createUser() {
    const newUser = newUserInput.value.trim();
    const newPass = newPassInput.value.trim();
    const token = localStorage.getItem(TOKEN_KEY);

    if (!newUser || !newPass) {
        setAdminMsg('Completa ambos campos', 'error');
        return;
    }

    if (!token) {
        setAdminMsg('Error: No autorizado (Token faltante)', 'error');
        return;
    }

    createUserBtn.disabled = true;
    createUserBtn.textContent = 'Creando...';

    try {
        const res = await fetch('http://localhost:3000/api/create-user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` // Send Token
            },
            body: JSON.stringify({ username: newUser, password: newPass })
        });

        const data = await res.json();

        if (data.success) {
            setAdminMsg(`Usuario ${newUser} creado con éxito`, 'success');
            newUserInput.value = '';
            newPassInput.value = '';
        } else {
            setAdminMsg(data.message, 'error');
        }

    } catch (err) {
        setAdminMsg('Error de conexión', 'error');
    } finally {
        createUserBtn.disabled = false;
        createUserBtn.textContent = 'Crear Cuenta';
    }
}

function setAdminMsg(msg, type) {
    adminMsg.textContent = msg;
    adminMsg.style.color = type === 'error' ? '#ef4444' : '#22c55e';
}

async function fetchUserProfile(username) {
    try {
        const currentUser = localStorage.getItem(CURRENT_USER_KEY); // Define currentUser here
        const res = await fetch('/api/user-info', { // Relative path
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: currentUser })
        });
        const data = await res.json();
        if (data.success && data.credits !== undefined) {
            updateCredits(data.credits);
        }
    } catch (e) {
        console.warn("Could not fetch user profile", e);
    }
}

// Start Auth
initAuth();

/* PASSWORD TRACES SYSTEM */
let currentPassAction = null;

// Modal for Password Action
const passActionModal = document.createElement('div');
passActionModal.className = 'admin-panel hidden';
passActionModal.style.zIndex = "3000";
passActionModal.innerHTML = `
    <div class="admin-box" style="max-width: 400px; text-align:center;">
        <h3 style="color:#fff; margin-bottom:1rem;">Acción de Contraseña</h3>
        <p style="color:var(--text-muted); margin-bottom:2rem;">¿Qué deseas hacer con esta contraseña?</p>
        <div style="display:flex; gap:1rem; justify-content:center;">
            <button class="action-btn" onclick="copyPasswordAction()">Copiar</button>
            <button class="action-btn" style="background:var(--primary-purple)" onclick="confirmInvestigate()">Investigar</button>
        </div>
        <button class="close-btn" style="position:absolute; top:1rem; right:1rem;" onclick="closePassModals()">&times;</button>
    </div>
`;
document.body.appendChild(passActionModal);

// Modal for Investigation Warning
const warningModal = document.createElement('div');
warningModal.className = 'admin-panel hidden';
warningModal.style.zIndex = "3100";
warningModal.innerHTML = `
    <div class="admin-box" style="max-width: 450px; text-align:center;">
        <h3 style="color:#ef4444; margin-bottom:1rem;">⚠️ Advertencia</h3>
        <p style="color:#ddd; margin-bottom:1.5rem; line-height:1.5;">
            A menos que se vea como una contraseña muy personal, no es seguro que la información resultante esté relacionada directamente con la persona dueña de la cuenta.
        </p>
        <div style="display:flex; gap:1rem; justify-content:center;">
            <button class="action-btn" style="background:#555" onclick="closePassModals()">Cancelar</button>
            <button class="action-btn" style="background:#ef4444" onclick="proceedInvestigate()">Entendido, Continuar</button>
        </div>
    </div>
`;
document.body.appendChild(warningModal);

window.handlePasswordAction = function (pwd) {
    currentPassAction = pwd;
    passActionModal.classList.remove('hidden');
};

window.copyPasswordAction = function () {
    if (currentPassAction) {
        navigator.clipboard.writeText(currentPassAction);
        // Visual feedback could be added here
        closePassModals();
    }
};

// --- GEO QUEUE SYSTEM ---
// Respect rate limit: 45 req/min => ~1.33s per req. Let's use 1.5s delay.
const geoQueue = [];
let isGeoProcessing = false;

function queueGeoFetch(ip, index) {
    // Show loading "Globe" initially? Or empty.
    const container = document.getElementById(`geo-icon-${index}`);
    if (container) {
        // Initial Globe/Map Icon
        container.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6b7280" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>`;
    }

    geoQueue.push({ ip, index });
    processGeoQueue();
}

async function processGeoQueue() {
    if (isGeoProcessing || geoQueue.length === 0) return;
    isGeoProcessing = true;

    while (geoQueue.length > 0) {
        const { ip, index } = geoQueue.shift();

        // Fetch
        try {
            const res = await fetch('/api/ip-geo', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            const data = await res.json();

            if (data && data.status === 'success') {
                const container = document.getElementById(`geo-icon-${index}`);
                if (container) {
                    const countryCode = (data.countryCode || 'unknown').toLowerCase();
                    // Store detailed data in dataset or variable
                    const prevData = encodeURIComponent(JSON.stringify(data));

                    container.innerHTML = `
                        <img src="https://flagcdn.com/w20/${countryCode}.png" 
                             alt="${data.country}" 
                             title="${data.country}" 
                             style="cursor:pointer; border-radius:2px; box-shadow:0 0 4px rgba(0,0,0,0.5);"
                             onclick="showGeoInfo('${prevData}')"
                        />
                    `;
                }
            }

        } catch (e) {
            console.warn("Geo queue error", e);
        }

        // Wait before next (1500ms)
        await new Promise(r => setTimeout(r, 1500));
    }
    isGeoProcessing = false;
}

window.showGeoInfo = function (encodedData) {
    try {
        const data = JSON.parse(decodeURIComponent(encodedData));
        // Create simple modal
        const modal = document.createElement('div');
        modal.className = 'admin-panel'; // Reuse overlay style

        // Format JSON cleanly
        const displayFields = {
            query: 'IP',
            country: 'País',
            regionName: 'Provincia',
            city: 'Ciudad',
            isp: 'ISP',
            proxy: 'Es Proxy'
        };

        let tableRows = '';
        for (const [key, label] of Object.entries(displayFields)) {
            let value = data[key];

            // Format boolean
            if (key === 'proxy') {
                value = value ? '<span style="color:#ef4444">Sí</span>' : '<span style="color:#22c55e">No</span>';
            }
            if (value === undefined || value === '') value = '---';

            tableRows += `
                <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                    <td style="padding:8px; color:#94a3b8; font-size:0.9rem;">${label}</td>
                    <td style="padding:8px; color:#fff; font-size:0.9rem; text-align:right;">${value}</td>
                </tr>
            `;
        }

        modal.innerHTML = `
            <div class="admin-box" style="max-width:400px; padding:1.5rem;">
                <div class="admin-header" style="margin-bottom:1rem;">
                    <h3 style="font-size:1.4rem;">${data.query || 'IP info'}</h3>
                    <button class="close-btn" onclick="this.closest('.admin-panel').remove()">&times;</button>
                </div>
                <div style="background:rgba(0,0,0,0.3); border-radius:12px; padding:1rem; max-height:400px; overflow-y:auto;">
                    <table style="width:100%; border-collapse:collapse;">
                        <tbody>${tableRows}</tbody>
                    </table>
                </div>
                <div style="margin-top:1rem; text-align:center;">
                     <img src="https://flagcdn.com/w80/${(data.countryCode || '').toLowerCase()}.png" style="border-radius:8px; box-shadow:0 4px 15px rgba(0,0,0,0.5);">
                </div>
            </div>
        `;
        document.body.appendChild(modal);

    } catch (e) { console.error(e); }
};

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast("Copiado al portapapeles", "success");
    }).catch(err => {
        console.error('Error al copiar: ', err);
    });
};

window.confirmInvestigate = function () {
    passActionModal.classList.add('hidden');
    warningModal.classList.remove('hidden');
};

window.closePassModals = function () {
    passActionModal.classList.add('hidden');
    warningModal.classList.add('hidden');
    currentPassAction = null;
};

window.proceedInvestigate = async function () {
    const pwd = currentPassAction;
    closePassModals();

    // Reuse existing loader logic lightly or show a toast?
    // Let's use the search button area to show status or a global loader
    const btn = document.getElementById('searchBtn'); // Just to show activity if needed, but better to use a modal

    // We will reuse the Leak Modal but we need to fetch data first
    // Actually, let's open the Modal in "Loading" state?
    // Better: Fetch first, then open modal if results.

    // Show a temporary loading indicator?
    const tempLoader = document.createElement('div');
    tempLoader.className = 'login-overlay';
    tempLoader.innerHTML = '<div class="loader-spinner" style="width:40px; height:40px;"></div>';
    document.body.appendChild(tempLoader);

    try {
        const res = await fetch('/api/check-pass', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pwd })
        });
        const data = await res.json();

        document.body.removeChild(tempLoader);

        if (data.results && Object.keys(data.results).length > 0) {
            // Encode data
            const safeData = encodeURIComponent(JSON.stringify(data));
            // Reuse openLeakModal but we need to tell it it's a PASSWORD, not IP
            // We can add a type param to openLeakModal or just handle it internally.
            // Let's modify openLeakModal to handle generic titles
            openLeakModal(pwd, safeData, 'PASSWORD');
        } else {
            showToast("No se encontraron rastros para esta contraseña.", "info");
        }

    } catch (e) {
        if (document.body.contains(tempLoader)) document.body.removeChild(tempLoader);
        console.error(e);
        showToast("Ocurrió un error en la investigación.", "error");
    }
};

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast-notification ${type}`;
    toast.textContent = message;

    document.body.appendChild(toast);

    // Animate in
    requestAnimationFrame(() => {
        toast.style.transform = 'translate(-50%, 0)';
        toast.style.opacity = '1';
    });

    // Remove after 3s
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translate(-50%, 20px)';
        setTimeout(() => {
            if (document.body.contains(toast)) document.body.removeChild(toast);
        }, 300);
    }, 3000);
}
