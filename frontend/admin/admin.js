document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();

    // ========== DOM REFERENCES ==========
    const body = document.body;
    const authView = document.getElementById('auth-view');
    const dashboardWrapper = document.getElementById('dashboard-wrapper');
    const loginForm = document.getElementById('login-form');
    const authError = document.getElementById('auth-error');

    const sidebar = document.getElementById('sidebar');
    const toggleSidebarBtn = document.getElementById('toggle-sidebar-btn');
    const sidebarToggleIcon = document.getElementById('sidebar-toggle-icon');
    const navItems = document.querySelectorAll('.nav-item[data-target]');
    const contentViews = document.querySelectorAll('.content-view');
    const logoutBtn = document.getElementById('logout-btn');

    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');
    const omnibar = document.getElementById('omnibar');

    const mappingsTbody = document.getElementById('mappings-tbody');
    const addModal = document.getElementById('add-modal');
    const openAddModalBtn = document.getElementById('open-add-modal-btn');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const addRecordForm = document.getElementById('add-record-form');
    const openPortsList = document.getElementById('open-ports-list');

    const configView = document.getElementById('config-view');
    const backToMappingsBtn = document.getElementById('back-to-mappings');
    const configForm = document.getElementById('config-form');

    const confirmDialog = document.getElementById('confirm-dialog');
    const confirmTitle = document.getElementById('confirm-title');
    const confirmMessage = document.getElementById('confirm-message');
    const confirmCancel = document.getElementById('confirm-cancel');
    const confirmOk = document.getElementById('confirm-ok');

    // ========== STATE ==========
    let recordsCache = {};
    let metricsInterval;
    let globalChartInstance = null;
    let domainChartInstance = null;
    let currentDomainContext = null;
    let confirmCallback = null;

    // ========== HELPERS ==========
    function getAuthHeaders() {
        const token = sessionStorage.getItem('trels_auth');
        return { 'Content-Type': 'application/json', 'Authorization': `Basic ${token}` };
    }

    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str || '';
        return d.innerHTML;
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // ========== TOAST SYSTEM ==========
    function showToast(type, title, message) {
        const container = document.getElementById('toast-container');
        const iconMap = {
            success: 'check-circle-2',
            error: 'x-circle',
            warning: 'alert-triangle',
            info: 'info'
        };

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <i data-lucide="${iconMap[type] || 'info'}" class="toast-icon ${type}"></i>
            <div class="toast-content">
                <div class="toast-title">${escapeHtml(title)}</div>
                ${message ? `<div class="toast-message">${escapeHtml(message)}</div>` : ''}
            </div>
            <button class="toast-close"><i data-lucide="x"></i></button>
        `;

        container.appendChild(toast);
        lucide.createIcons({ nodes: [toast] });

        const close = () => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        };

        toast.querySelector('.toast-close').addEventListener('click', close);
        setTimeout(close, 4000);
    }

    // ========== CONFIRM DIALOG ==========
    function showConfirm(title, message) {
        return new Promise((resolve) => {
            confirmTitle.textContent = title;
            confirmMessage.textContent = message;
            confirmDialog.classList.add('active');
            confirmCallback = resolve;
        });
    }

    confirmCancel.addEventListener('click', () => {
        confirmDialog.classList.remove('active');
        if (confirmCallback) confirmCallback(false);
        confirmCallback = null;
    });

    confirmOk.addEventListener('click', () => {
        confirmDialog.classList.remove('active');
        if (confirmCallback) confirmCallback(true);
        confirmCallback = null;
    });

    // ========== AUTHENTICATION ==========
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        authError.textContent = '';
        const loginBtn = document.getElementById('login-btn');
        loginBtn.disabled = true;
        loginBtn.textContent = 'Signing in…';

        const user = document.getElementById('username').value;
        const pass = document.getElementById('password').value;
        sessionStorage.setItem('trels_auth', btoa(`${user}:${pass}`));

        try {
            const res = await fetch('/api/records', { headers: getAuthHeaders() });
            if (!res.ok) throw new Error('Invalid username or password.');
            authView.style.display = 'none';
            dashboardWrapper.style.display = 'flex';
            initDashboard();
        } catch (err) {
            authError.textContent = err.message;
            sessionStorage.removeItem('trels_auth');
        } finally {
            loginBtn.disabled = false;
            loginBtn.textContent = 'Sign In';
        }
    });

    logoutBtn.addEventListener('click', () => {
        sessionStorage.removeItem('trels_auth');
        clearInterval(metricsInterval);
        dashboardWrapper.style.display = 'none';
        authView.style.display = 'flex';
        loginForm.reset();
        authError.textContent = '';
    });

    // ========== SIDEBAR & NAVIGATION ==========
    toggleSidebarBtn.addEventListener('click', () => {
        sidebar.classList.toggle('minimized');
        const isMin = sidebar.classList.contains('minimized');
        sidebarToggleIcon.setAttribute('data-lucide', isMin ? 'panel-left-open' : 'panel-left-close');
        lucide.createIcons({ nodes: [sidebarToggleIcon.parentElement] });
    });

    function navigateTo(targetId) {
        contentViews.forEach(v => v.classList.remove('active'));
        const target = document.getElementById(targetId);
        if (target) target.classList.add('active');

        navItems.forEach(n => {
            n.classList.toggle('active', n.getAttribute('data-target') === targetId);
        });

        currentDomainContext = null;
        omnibar.value = '';
    }

    navItems.forEach(item => {
        item.addEventListener('click', () => navigateTo(item.getAttribute('data-target')));
    });

    // ========== THEME ==========
    const savedTheme = localStorage.getItem('trels_theme');
    if (savedTheme) {
        body.setAttribute('data-theme', savedTheme);
        themeIcon.setAttribute('data-lucide', savedTheme === 'dark' ? 'sun' : 'moon');
        lucide.createIcons({ nodes: [themeIcon.parentElement] });
    }

    themeToggle.addEventListener('click', () => {
        const isDark = body.getAttribute('data-theme') === 'dark';
        const newTheme = isDark ? 'light' : 'dark';
        body.setAttribute('data-theme', newTheme);
        localStorage.setItem('trels_theme', newTheme);
        themeIcon.setAttribute('data-lucide', isDark ? 'moon' : 'sun');
        lucide.createIcons({ nodes: [themeIcon.parentElement] });
        updateChartColors();
    });

    // ========== OMNIBAR ==========
    omnibar.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase().trim();
        if (q === '') {
            renderMappingsTable(Object.values(recordsCache));
            return;
        }

        if (!document.getElementById('mappings-view').classList.contains('active') &&
            !document.getElementById('config-view').classList.contains('active')) {
            navigateTo('mappings-view');
        }

        const filtered = Object.values(recordsCache).filter(r =>
            r.domain.toLowerCase().includes(q) || r.port.toString().includes(q)
        );
        renderMappingsTable(filtered);
    });

    // ========== INIT ==========
    function initDashboard() {
        fetchRecords();
        fetchPorts();
        setupCharts();
        fetchMetrics();
        metricsInterval = setInterval(fetchMetrics, 2500);
    }

    // ========== RECORDS ==========
    async function fetchRecords() {
        try {
            const res = await fetch('/api/records', { headers: getAuthHeaders() });
            if (!res.ok) return;
            const arr = (await res.json()) || [];
            recordsCache = {};
            arr.forEach(r => recordsCache[r.domain] = r);
            renderMappingsTable(arr);
        } catch (e) { /* silent */ }
    }

    async function fetchPorts() {
        try {
            const res = await fetch('/api/ports', { headers: getAuthHeaders() });
            if (!res.ok) return;
            const ports = (await res.json()) || [];
            openPortsList.innerHTML = '';
            ports.forEach(p => {
                const opt = document.createElement('option');
                opt.value = p.port;
                opt.label = `${p.port} — ${p.process}`;
                openPortsList.appendChild(opt);
            });
        } catch (e) { /* silent */ }
    }

    // ========== ADD MODAL ==========
    openAddModalBtn.addEventListener('click', () => { addModal.classList.add('active'); fetchPorts(); });
    closeModalBtn.addEventListener('click', () => { addModal.classList.remove('active'); addRecordForm.reset(); });
    addModal.addEventListener('click', (e) => { if (e.target === addModal) { addModal.classList.remove('active'); addRecordForm.reset(); } });

    addRecordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('record-domain').value.trim();
        const port = parseInt(document.getElementById('record-port').value, 10);

        try {
            const res = await fetch('/api/records', {
                method: 'POST', headers: getAuthHeaders(),
                body: JSON.stringify({ domain, port, enabled: true, https: false, rateLimit: 0 })
            });
            if (!res.ok) throw new Error(await res.text());
            addModal.classList.remove('active');
            addRecordForm.reset();
            await fetchRecords();
            showToast('success', 'Mapping created', `${domain} → port ${port}`);
        } catch (err) {
            showToast('error', 'Failed to create mapping', err.message);
        }
    });

    // ========== EXPORT / IMPORT ==========
    const exportBtn = document.getElementById('export-mappings-btn');
    const importBtn = document.getElementById('import-mappings-btn');
    const importFileInput = document.getElementById('import-file-input');

    if (exportBtn) {
        exportBtn.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/records/export', { headers: getAuthHeaders() });
                if (!res.ok) throw new Error('Export API failed');
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `trels-export-${new Date().toISOString().slice(0,10)}.json`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
                showToast('success', 'Export successful', 'Mappings exported to JSON file');
            } catch (err) {
                showToast('error', 'Export failed', err.message);
            }
        });
    }

    if (importBtn && importFileInput) {
        importBtn.addEventListener('click', () => {
            importFileInput.click();
        });
        importFileInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            
            const reader = new FileReader();
            reader.onload = async (evt) => {
                try {
                    const data = JSON.parse(evt.target.result);
                    if (!Array.isArray(data)) throw new Error('Import data must be a JSON array');
                    
                    for (const item of data) {
                        if (typeof item.domain !== 'string' || typeof item.port !== 'number') {
                            throw new Error('Invalid record structure inside JSON');
                        }
                    }

                    const res = await fetch('/api/records/import', {
                        method: 'POST',
                        headers: getAuthHeaders(),
                        body: JSON.stringify(data)
                    });
                    if (!res.ok) throw new Error(await res.text());
                    const resData = await res.json();
                    await fetchRecords();
                    showToast('success', 'Import successful', `Imported ${resData.count} mappings`);
                } catch (err) {
                    showToast('error', 'Import failed', err.message);
                }
                importFileInput.value = '';
            };
            reader.readAsText(file);
        });
    }

    // ========== RENDER MAPPINGS TABLE ==========
    function renderMappingsTable(records) {
        mappingsTbody.innerHTML = '';
        if (!records || records.length === 0) {
            mappingsTbody.innerHTML = `
                <tr><td colspan="6">
                    <div class="empty-state">
                        <i data-lucide="inbox"></i>
                        <h3>No mappings yet</h3>
                        <p>Create your first mapping to get started.</p>
                    </div>
                </td></tr>`;
            lucide.createIcons({ nodes: [mappingsTbody] });
            return;
        }

        records.forEach(r => {
            const tr = document.createElement('tr');
            tr.className = 'clickable-row';
            tr.innerHTML = `
                <td>
                    <div class="domain-cell">
                        <span class="domain-dot ${r.enabled ? 'active' : 'inactive'}"></span>
                        ${escapeHtml(r.domain)}
                    </div>
                </td>
                <td class="port-cell">${r.port}</td>
                <td>${r.https
                    ? '<i data-lucide="shield-check" style="width:16px;height:16px;color:hsl(var(--success))"></i>'
                    : '<i data-lucide="shield-off" style="width:16px;height:16px;color:hsl(var(--muted-foreground));opacity:0.4"></i>'
                }</td>
                <td>${r.rateLimit > 0 ? `<span style="font-family:monospace;font-size:0.75rem;">${r.rateLimit} req/s</span>` : '<span style="color:hsl(var(--muted-foreground));font-size:0.75rem;">—</span>'}</td>
                <td><span class="badge ${r.enabled ? 'badge-active' : 'badge-inactive'}">${r.enabled ? 'Active' : 'Disabled'}</span></td>
                <td>
                    <button class="icon-btn delete-btn" data-domain="${escapeHtml(r.domain)}" title="Delete mapping" style="color:hsl(var(--destructive))">
                        <i data-lucide="trash-2" style="width:15px;height:15px;"></i>
                    </button>
                </td>
            `;

            tr.addEventListener('click', (e) => {
                if (e.target.closest('.delete-btn')) return;
                openConfigView(r.domain);
            });

            tr.querySelector('.delete-btn').addEventListener('click', async (e) => {
                e.stopPropagation();
                const confirmed = await showConfirm(
                    'Delete mapping?',
                    `This will remove the mapping for "${r.domain}" and update your hosts file.`
                );
                if (!confirmed) return;

                try {
                    await fetch('/api/records', {
                        method: 'DELETE', headers: getAuthHeaders(),
                        body: JSON.stringify({ domain: r.domain })
                    });
                    await fetchRecords();
                    showToast('success', 'Mapping deleted', `${r.domain} has been removed.`);
                } catch (err) {
                    showToast('error', 'Failed to delete', err.message);
                }
            });

            mappingsTbody.appendChild(tr);
        });

        lucide.createIcons({ nodes: [mappingsTbody] });
    }

    // ========== CONFIG VIEW ==========
    const configAuthEnabled = document.getElementById('config-authenabled');
    const configAuthFields = document.getElementById('config-auth-fields');

    if (configAuthEnabled) {
        configAuthEnabled.addEventListener('change', (e) => {
            configAuthFields.style.display = e.target.checked ? 'block' : 'none';
        });
    }

    function openConfigView(domain) {
        const rec = recordsCache[domain];
        if (!rec) return;

        currentDomainContext = domain;
        document.getElementById('config-domain-title').textContent = domain;
        document.getElementById('config-domain').value = domain;
        document.getElementById('config-port').value = rec.port;
        document.getElementById('config-ratelimit').value = rec.rateLimit || 0;
        document.getElementById('config-https').checked = rec.https;
        document.getElementById('config-authenabled').checked = rec.authEnabled || false;
        document.getElementById('config-authuser').value = rec.authUser || '';
        document.getElementById('config-authpass').value = rec.authPass || '';
        document.getElementById('config-enabled').checked = rec.enabled;

        configAuthFields.style.display = rec.authEnabled ? 'block' : 'none';

        if (domainChartInstance) {
            domainChartInstance.data.labels = [];
            domainChartInstance.data.datasets[0].data = [];
            domainChartInstance.update();
        }

        contentViews.forEach(v => v.classList.remove('active'));
        configView.classList.add('active');
        navItems.forEach(n => n.classList.remove('active'));
    }

    backToMappingsBtn.addEventListener('click', () => navigateTo('mappings-view'));

    configForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('config-domain').value;
        const port = parseInt(document.getElementById('config-port').value, 10);
        const rateLimit = parseInt(document.getElementById('config-ratelimit').value, 10) || 0;
        const https = document.getElementById('config-https').checked;
        const authEnabled = document.getElementById('config-authenabled').checked;
        const authUser = document.getElementById('config-authuser').value.trim();
        const authPass = document.getElementById('config-authpass').value;
        const enabled = document.getElementById('config-enabled').checked;

        if (authEnabled && (!authUser || !authPass)) {
            showToast('error', 'Authentication setup error', 'Username and password are required when HTTP Basic Auth is enabled.');
            return;
        }

        try {
            const res = await fetch('/api/records', {
                method: 'POST', headers: getAuthHeaders(),
                body: JSON.stringify({ domain, port, enabled, https, rateLimit, authEnabled, authUser, authPass })
            });
            if (!res.ok) throw new Error(await res.text());
            await fetchRecords();
            showToast('success', 'Configuration saved', `Settings for ${domain} have been updated.`);
        } catch (err) {
            showToast('error', 'Failed to save', err.message);
        }
    });

    // ========== CHARTS ==========
    function getChartColors() {
        const isDark = body.getAttribute('data-theme') === 'dark';
        return {
            text: isDark ? '#a1a1aa' : '#71717a',
            grid: isDark ? 'rgba(63, 63, 70, 0.3)' : 'rgba(228, 228, 231, 0.5)',
            line: isDark ? '#d4d4d8' : '#18181b',
            fill: isDark ? 'rgba(212, 212, 216, 0.06)' : 'rgba(24, 24, 27, 0.05)',
            accent: isDark ? '#60a5fa' : '#2563eb',
            accentFill: isDark ? 'rgba(96, 165, 250, 0.1)' : 'rgba(37, 99, 235, 0.08)',
        };
    }

    function getChartOptions(colors) {
        return {
            responsive: true,
            maintainAspectRatio: true,
            animation: { duration: 200 },
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: colors.line,
                    titleFont: { family: 'Inter', size: 11 },
                    bodyFont: { family: 'Inter', size: 11 },
                    padding: 8,
                    cornerRadius: 6,
                    displayColors: false,
                }
            },
            scales: {
                x: {
                    display: true,
                    grid: { display: false },
                    ticks: { color: colors.text, font: { size: 10 }, maxTicksLimit: 6, maxRotation: 0 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: colors.grid },
                    ticks: { color: colors.text, font: { size: 10 }, maxTicksLimit: 5 }
                }
            },
            elements: {
                point: { radius: 0, hoverRadius: 3, hitRadius: 8 },
                line: { borderWidth: 2 }
            }
        };
    }

    function setupCharts() {
        const c = getChartColors();

        const gCtx = document.getElementById('global-traffic-chart').getContext('2d');
        globalChartInstance = new Chart(gCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{ label: 'Req/s', data: [], borderColor: c.line, tension: 0.35, fill: true, backgroundColor: c.fill }]
            },
            options: getChartOptions(c)
        });

        const dCtx = document.getElementById('domain-traffic-chart').getContext('2d');
        domainChartInstance = new Chart(dCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{ label: 'Req/s', data: [], borderColor: c.accent, tension: 0.35, fill: true, backgroundColor: c.accentFill }]
            },
            options: getChartOptions(c)
        });
    }

    function updateChartColors() {
        const c = getChartColors();
        if (globalChartInstance) {
            globalChartInstance.data.datasets[0].borderColor = c.line;
            globalChartInstance.data.datasets[0].backgroundColor = c.fill;
            globalChartInstance.options = getChartOptions(c);
            globalChartInstance.update();
        }
        if (domainChartInstance) {
            domainChartInstance.data.datasets[0].borderColor = c.accent;
            domainChartInstance.data.datasets[0].backgroundColor = c.accentFill;
            domainChartInstance.options = getChartOptions(c);
            domainChartInstance.update();
        }
    }

    // ========== METRICS ==========
    let lastGlobalReqs = 0;
    let lastDomainReqs = {};

    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics', { headers: getAuthHeaders() });
            if (!res.ok) return;
            const metrics = await res.json();
            if (!metrics) return;

            let totalReqs = 0, totalIn = 0, totalOut = 0, activeDomains = 0;
            const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

            const dashMetrics = document.getElementById('dashboard-metrics-tbody');
            dashMetrics.innerHTML = '';

            for (const [domain, stats] of Object.entries(metrics)) {
                totalReqs += stats.requests;
                totalIn += stats.bytesIn;
                totalOut += stats.bytesOut;

                const rec = recordsCache[domain];
                if (rec && rec.enabled) activeDomains++;

                // Dashboard per-domain table
                const dtr = document.createElement('tr');
                dtr.innerHTML = `
                    <td style="font-weight:500;">${escapeHtml(domain)}</td>
                    <td class="port-cell">${stats.requests}</td>
                    <td class="port-cell">${formatBytes(stats.bytesIn)}</td>
                    <td class="port-cell">${formatBytes(stats.bytesOut)}</td>
                `;
                dashMetrics.appendChild(dtr);

                // Domain-specific chart
                if (currentDomainContext === domain) {
                    document.getElementById('domain-bytes-in').textContent = formatBytes(stats.bytesIn);
                    document.getElementById('domain-bytes-out').textContent = formatBytes(stats.bytesOut);

                    const reqDiff = stats.requests - (lastDomainReqs[domain] ?? stats.requests);
                    lastDomainReqs[domain] = stats.requests;

                    if (domainChartInstance.data.labels.length > 25) {
                        domainChartInstance.data.labels.shift();
                        domainChartInstance.data.datasets[0].data.shift();
                    }
                    domainChartInstance.data.labels.push(now);
                    domainChartInstance.data.datasets[0].data.push(reqDiff);
                    domainChartInstance.update();
                } else {
                    lastDomainReqs[domain] = stats.requests;
                }
            }

            // Global stats
            document.getElementById('stat-active-domains').textContent = activeDomains;
            document.getElementById('stat-total-reqs').textContent = totalReqs.toLocaleString();
            document.getElementById('stat-data-in').textContent = formatBytes(totalIn);
            document.getElementById('stat-data-out').textContent = formatBytes(totalOut);

            // Global chart
            const globalDiff = totalReqs - (lastGlobalReqs === 0 ? totalReqs : lastGlobalReqs);
            lastGlobalReqs = totalReqs;

            if (globalChartInstance.data.labels.length > 25) {
                globalChartInstance.data.labels.shift();
                globalChartInstance.data.datasets[0].data.shift();
            }
            globalChartInstance.data.labels.push(now);
            globalChartInstance.data.datasets[0].data.push(globalDiff);
            globalChartInstance.update();

        } catch (e) { /* silent */ }
    }
});
