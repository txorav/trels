document.addEventListener('DOMContentLoaded', () => {
    // --- Initialize Lucide Icons ---
    lucide.createIcons();

    // --- DOM Elements ---
    const body = document.body;
    const authView = document.getElementById('auth-view');
    const dashboardWrapper = document.getElementById('dashboard-wrapper');
    const loginForm = document.getElementById('login-form');
    
    // Sidebar & Navigation
    const sidebar = document.getElementById('sidebar');
    const toggleSidebarBtn = document.getElementById('toggle-sidebar-btn');
    const sidebarIcon = document.getElementById('sidebar-icon');
    const navItems = document.querySelectorAll('.nav-item[data-target]');
    const contentViews = document.querySelectorAll('.content-view');
    const logoutBtn = document.getElementById('logout-btn');
    
    // Theme & Omnibar
    const themeToggle = document.getElementById('theme-toggle');
    const themeIcon = document.getElementById('theme-icon');
    const omnibar = document.getElementById('omnibar');

    // Mappings & Modal
    const mappingsTbody = document.getElementById('mappings-tbody');
    const addModal = document.getElementById('add-modal');
    const openAddModalBtn = document.getElementById('open-add-modal-btn');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const addRecordForm = document.getElementById('add-record-form');
    const openPortsList = document.getElementById('open-ports-list');

    // Config View
    const configView = document.getElementById('config-view');
    const mappingsView = document.getElementById('mappings-view');
    const backToMappingsBtn = document.getElementById('back-to-mappings');
    const configForm = document.getElementById('config-form');
    
    // State
    let recordsCache = {};
    let metricsInterval;
    let globalChartInstance = null;
    let domainChartInstance = null;
    let currentDomainContext = null;

    // --- Helpers ---
    function getAuthHeaders() {
        const token = sessionStorage.getItem('trels_auth');
        return { 'Content-Type': 'application/json', 'Authorization': `Basic ${token}` };
    }
    function escapeHtml(unsafe) {
        return (unsafe || "").toString()
             .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }
    function formatBytes(bytes) {
        if(bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // --- Authentication ---
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const user = document.getElementById('username').value;
        const pass = document.getElementById('password').value;
        sessionStorage.setItem('trels_auth', btoa(`${user}:${pass}`));
        try {
            const res = await fetch('/api/records', { headers: getAuthHeaders() });
            if (!res.ok) throw new Error("Invalid credentials");
            authView.style.display = 'none';
            dashboardWrapper.style.display = 'flex';
            initDashboard();
        } catch (err) {
            alert(err.message);
            sessionStorage.removeItem('trels_auth');
        }
    });

    logoutBtn.addEventListener('click', () => {
        sessionStorage.removeItem('trels_auth');
        window.location.reload();
    });

    // --- Layout & Navigation ---
    toggleSidebarBtn.addEventListener('click', () => {
        sidebar.classList.toggle('minimized');
        const isMin = sidebar.classList.contains('minimized');
        sidebarIcon.setAttribute('data-lucide', isMin ? 'panel-left-open' : 'panel-left-close');
        lucide.createIcons();
    });

    themeToggle.addEventListener('click', () => {
        const isDark = body.getAttribute('data-theme') === 'dark';
        body.setAttribute('data-theme', isDark ? 'light' : 'dark');
        themeIcon.setAttribute('data-lucide', isDark ? 'moon' : 'sun');
        lucide.createIcons();
        if(globalChartInstance) globalChartInstance.update();
        if(domainChartInstance) domainChartInstance.update();
    });

    function navigateTo(targetId) {
        contentViews.forEach(v => v.classList.remove('active'));
        document.getElementById(targetId).classList.add('active');
        
        navItems.forEach(n => {
            if(n.getAttribute('data-target') === targetId) n.classList.add('active');
            else n.classList.remove('active');
        });

        currentDomainContext = null;
    }

    navItems.forEach(item => {
        item.addEventListener('click', () => navigateTo(item.getAttribute('data-target')));
    });

    // --- Search / Omnibar ---
    omnibar.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase();
        if(q === '') {
            fetchRecords(); // Reset table
            return;
        }
        
        // Auto-switch to mappings view if searching
        if(!document.getElementById('mappings-view').classList.contains('active')) {
            navigateTo('mappings-view');
        }

        const filtered = Object.values(recordsCache).filter(r => 
            r.domain.toLowerCase().includes(q) || r.port.toString().includes(q)
        );
        renderMappingsTable(filtered);
    });

    // --- Initialization ---
    function initDashboard() {
        fetchRecords();
        fetchPorts();
        setupCharts();
        metricsInterval = setInterval(fetchMetrics, 2000);
    }

    // --- Records & Modals ---
    async function fetchRecords() {
        try {
            const res = await fetch('/api/records', { headers: getAuthHeaders() });
            if(res.ok) {
                const arr = await res.json();
                recordsCache = {};
                arr.forEach(r => recordsCache[r.domain] = r);
                renderMappingsTable(arr);
            }
        } catch(e) {}
    }

    async function fetchPorts() {
        try {
            const res = await fetch('/api/ports', { headers: getAuthHeaders() });
            if(res.ok) {
                const ports = await res.json();
                openPortsList.innerHTML = '';
                if(ports) ports.forEach(p => {
                    const opt = document.createElement('option');
                    opt.value = p.port;
                    opt.text = `${p.port} (${p.process})`;
                    openPortsList.appendChild(opt);
                });
            }
        } catch(e) {}
    }

    openAddModalBtn.addEventListener('click', () => { addModal.classList.add('active'); fetchPorts(); });
    closeModalBtn.addEventListener('click', () => { addModal.classList.remove('active'); addRecordForm.reset(); });

    addRecordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = document.getElementById('record-domain').value.trim();
        const port = parseInt(document.getElementById('record-port').value, 10);
        try {
            await fetch('/api/records', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({ domain, port, enabled: true, https: false, rateLimit: 0 })
            });
            addModal.classList.remove('active');
            addRecordForm.reset();
            fetchRecords();
        } catch(err) { alert(err.message); }
    });

    function renderMappingsTable(records) {
        mappingsTbody.innerHTML = '';
        if(!records || records.length === 0) {
            mappingsTbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:hsl(var(--muted-foreground))">No mappings found.</td></tr>`;
            return;
        }

        records.forEach(r => {
            const tr = document.createElement('tr');
            tr.style.cursor = 'pointer';
            tr.innerHTML = `
                <td style="font-weight: 500;">${escapeHtml(r.domain)}</td>
                <td>${r.port}</td>
                <td>${r.https ? '<i data-lucide="lock" style="width:16px; color:hsl(var(--primary))"></i>' : '<i data-lucide="unlock" style="width:16px; color:hsl(var(--muted-foreground))"></i>'}</td>
                <td><span class="badge ${r.enabled ? 'badge-active' : 'badge-inactive'}">${r.enabled ? 'Active' : 'Disabled'}</span></td>
                <td>
                    <button class="icon-btn delete-btn" data-domain="${escapeHtml(r.domain)}" title="Delete" style="color:hsl(var(--destructive))">
                        <i data-lucide="trash-2" style="width:16px;"></i>
                    </button>
                </td>
            `;
            
            // Row click -> Config View
            tr.addEventListener('click', (e) => {
                if(e.target.closest('.delete-btn')) return; // Ignore delete click
                openConfigView(r.domain);
            });

            tr.querySelector('.delete-btn').addEventListener('click', async (e) => {
                e.stopPropagation();
                if(confirm(`Delete mapping for ${r.domain}?`)) {
                    await fetch('/api/records', {
                        method: 'DELETE',
                        headers: getAuthHeaders(),
                        body: JSON.stringify({ domain: r.domain })
                    });
                    fetchRecords();
                }
            });

            mappingsTbody.appendChild(tr);
        });
        lucide.createIcons();
    }

    // --- Config Detailed View ---
    function openConfigView(domain) {
        const rec = recordsCache[domain];
        if(!rec) return;

        currentDomainContext = domain;
        document.getElementById('config-domain-title').textContent = domain;
        document.getElementById('config-domain').value = domain;
        document.getElementById('config-port').value = rec.port;
        document.getElementById('config-ratelimit').value = rec.rateLimit || '';
        document.getElementById('config-https').checked = rec.https;
        document.getElementById('config-enabled').checked = rec.enabled;

        // Reset chart data
        if(domainChartInstance) {
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
        const enabled = document.getElementById('config-enabled').checked;

        try {
            await fetch('/api/records', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({ domain, port, enabled, https, rateLimit })
            });
            fetchRecords(); // Update cache
            alert("Configuration saved!");
        } catch(err) { alert(err.message); }
    });

    // --- Metrics & Charts ---
    Chart.defaults.color = () => body.getAttribute('data-theme') === 'dark' ? '#a1a1aa' : '#71717a';
    Chart.defaults.borderColor = () => body.getAttribute('data-theme') === 'dark' ? '#27272a' : '#e4e4e7';

    function setupCharts() {
        const gCtx = document.getElementById('global-traffic-chart').getContext('2d');
        globalChartInstance = new Chart(gCtx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Requests/sec', data: [], borderColor: '#18181b', tension: 0.3, fill: true, backgroundColor: 'rgba(24, 24, 27, 0.1)' }] },
            options: { responsive: true, animation: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
        });

        const dCtx = document.getElementById('domain-traffic-chart').getContext('2d');
        domainChartInstance = new Chart(dCtx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Requests/sec', data: [], borderColor: '#2563eb', tension: 0.3, fill: true, backgroundColor: 'rgba(37, 99, 235, 0.1)' }] },
            options: { responsive: true, animation: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
        });
    }

    let lastGlobalReqs = 0;
    let lastDomainReqs = {};

    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics', { headers: getAuthHeaders() });
            if(!res.ok) return;
            const metrics = await res.json();
            
            let totalReqs = 0, totalIn = 0, totalOut = 0;
            const now = new Date().toLocaleTimeString();

            for(const [domain, stats] of Object.entries(metrics)) {
                totalReqs += stats.requests;
                totalIn += stats.bytesIn;
                totalOut += stats.bytesOut;

                // Domain specific processing
                if(currentDomainContext === domain) {
                    document.getElementById('domain-bytes-in').textContent = formatBytes(stats.bytesIn);
                    document.getElementById('domain-bytes-out').textContent = formatBytes(stats.bytesOut);
                    
                    const reqDiff = stats.requests - (lastDomainReqs[domain] || stats.requests);
                    lastDomainReqs[domain] = stats.requests;

                    if(domainChartInstance.data.labels.length > 20) {
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

            // Global dashboard updates
            document.getElementById('stat-total-reqs').textContent = totalReqs;
            document.getElementById('stat-data-in').textContent = formatBytes(totalIn);
            document.getElementById('stat-data-out').textContent = formatBytes(totalOut);

            const globalDiff = totalReqs - (lastGlobalReqs === 0 ? totalReqs : lastGlobalReqs);
            lastGlobalReqs = totalReqs;

            if(globalChartInstance.data.labels.length > 20) {
                globalChartInstance.data.labels.shift();
                globalChartInstance.data.datasets[0].data.shift();
            }
            globalChartInstance.data.labels.push(now);
            globalChartInstance.data.datasets[0].data.push(globalDiff);
            globalChartInstance.update();

        } catch(e) {}
    }
});
