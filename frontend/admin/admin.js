document.addEventListener('DOMContentLoaded', () => {
    const authView = document.getElementById('auth-view');
    const dashboardWrapper = document.getElementById('dashboard-wrapper');
    const dashboardView = document.getElementById('dashboard-view');
    const monitoringView = document.getElementById('monitoring-view');
    const loginForm = document.getElementById('login-form');
    const logoutBtn = document.getElementById('logout-btn');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    
    const addModal = document.getElementById('add-modal');
    const addRecordBtn = document.getElementById('add-record-btn');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const addRecordForm = document.getElementById('add-record-form');
    const dnsTbody = document.getElementById('dns-tbody');
    const portInput = document.getElementById('record-port');
    const datalist = document.getElementById('open-ports-list');
    const portWarning = document.getElementById('port-warning');

    let openPortsCache = [];
    let metricsInterval;

    // Helper to get auth headers
    function getAuthHeaders() {
        const token = sessionStorage.getItem('trels_auth');
        return {
            'Content-Type': 'application/json',
            'Authorization': `Basic ${token}`
        };
    }

    // Helper for XSS protection
    function escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    // Navigation
    document.querySelectorAll('.nav-item[data-target]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            
            dashboardView.style.display = 'none';
            monitoringView.style.display = 'none';
            
            const targetId = item.getAttribute('data-target');
            document.getElementById(targetId).style.display = 'block';

            if (targetId === 'monitoring-view') {
                fetchMetrics();
                metricsInterval = setInterval(fetchMetrics, 3000);
            } else {
                clearInterval(metricsInterval);
            }
        });
    });

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const token = btoa(`${usernameInput.value}:${passwordInput.value}`);
        sessionStorage.setItem('trels_auth', token);

        try {
            // Test auth by hitting records
            const response = await fetch('/api/records', { headers: getAuthHeaders() });
            if (!response.ok) {
                if (response.status === 401) throw new Error("Invalid username or password");
                throw new Error("Failed to connect");
            }
            
            authView.classList.remove('active');
            dashboardWrapper.style.display = 'flex';
            fetchRecords(); 
            fetchOpenPorts();
        } catch (err) {
            alert(err.message);
            sessionStorage.removeItem('trels_auth');
        }
    });

    logoutBtn.addEventListener('click', () => {
        sessionStorage.removeItem('trels_auth');
        dashboardWrapper.style.display = 'none';
        authView.classList.add('active');
        loginForm.reset();
        clearInterval(metricsInterval);
    });

    addRecordBtn.addEventListener('click', () => {
        addModal.classList.add('active');
        fetchOpenPorts(); // refresh list
    });

    closeModalBtn.addEventListener('click', () => {
        addModal.classList.remove('active');
        addRecordForm.reset();
        portWarning.style.display = 'none';
    });

    // --- Port Scanner Logic ---
    async function fetchOpenPorts() {
        try {
            const res = await fetch('/api/ports', { headers: getAuthHeaders() });
            if(res.ok) {
                openPortsCache = await res.json();
                datalist.innerHTML = '';
                if(openPortsCache) {
                    openPortsCache.forEach(p => {
                        const opt = document.createElement('option');
                        opt.value = p.port;
                        opt.text = `${p.port} (${p.process})`;
                        datalist.appendChild(opt);
                    });
                }
            }
        } catch(e) {}
    }

    portInput.addEventListener('input', () => {
        const val = parseInt(portInput.value, 10);
        if(!val) {
            portWarning.style.display = 'none';
            return;
        }
        const isActive = openPortsCache && openPortsCache.some(p => p.port === val);
        if(!isActive && openPortsCache.length > 0) {
            portWarning.style.display = 'block';
        } else {
            portWarning.style.display = 'none';
        }
    });

    // --- Mappings Logic ---
    async function fetchRecords() {
        try {
            const response = await fetch('/api/records', { headers: getAuthHeaders() });
            if (!response.ok) throw new Error('Failed to fetch records');
            const records = await response.json();
            
            dnsTbody.innerHTML = ''; 
            
            if (records && records.length > 0) {
                records.forEach(record => {
                    appendRecordToTable(escapeHtml(record.domain), record.port, record.enabled);
                });
            } else {
                dnsTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--muted-foreground);">No mappings found.</td></tr>';
            }
        } catch (err) {
            console.error(err);
        }
    }

    function appendRecordToTable(domain, port, enabled) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${domain}</td>
            <td>${port}</td>
            <td>
                <span class="badge ${enabled ? 'badge-active' : ''}" style="${!enabled ? 'background: var(--muted); color: var(--muted-foreground);' : ''}">
                    ${enabled ? 'Active' : 'Disabled'}
                </span>
            </td>
            <td>
                <button class="btn btn-sm btn-outline toggle-btn" data-domain="${domain}" data-enabled="${enabled}">
                    ${enabled ? 'Disable' : 'Enable'}
                </button>
                <button class="btn btn-sm btn-outline delete-btn" data-domain="${domain}" style="color: #dc3545; border-color: #f8d7da; margin-left: 0.25rem;">Delete</button>
            </td>
        `;

        if (dnsTbody.querySelector('td[colspan]')) {
            dnsTbody.innerHTML = '';
        }
        dnsTbody.appendChild(tr);

        tr.querySelector('.toggle-btn').addEventListener('click', async (e) => {
            const btn = e.target;
            const currentEnabled = btn.getAttribute('data-enabled') === 'true';
            try {
                await fetch('/api/records/toggle', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ domain: domain, enabled: !currentEnabled })
                });
                fetchRecords(); 
            } catch (err) {}
        });

        tr.querySelector('.delete-btn').addEventListener('click', async (e) => {
            if(!confirm(`Delete mapping for ${domain}?`)) return;
            try {
                await fetch('/api/records', {
                    method: 'DELETE',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ domain: domain })
                });
                fetchRecords();
            } catch (err) {}
        });
    }

    addRecordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const domain = document.getElementById('record-domain').value.trim();
        const port = parseInt(document.getElementById('record-port').value, 10);
        const enabled = document.getElementById('record-enabled').checked;

        try {
            const response = await fetch('/api/records', {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify({ domain, port, enabled })
            });

            if (!response.ok) throw new Error(await response.text());

            addModal.classList.remove('active');
            addRecordForm.reset();
            portWarning.style.display = 'none';
            fetchRecords();
            
        } catch (err) {
            alert('Failed to save mapping: ' + err.message);
        }
    });

    // --- Monitoring Logic ---
    function formatBytes(bytes) {
        if(bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function fetchMetrics() {
        try {
            const res = await fetch('/api/metrics', { headers: getAuthHeaders() });
            if(!res.ok) return;
            const metrics = await res.json();
            
            const metricsBody = document.getElementById('metrics-tbody');
            metricsBody.innerHTML = '';

            let totalReqs = 0, totalIn = 0, totalOut = 0, domains = 0;

            for(const [domain, stats] of Object.entries(metrics)) {
                domains++;
                totalReqs += stats.requests;
                totalIn += stats.bytesIn;
                totalOut += stats.bytesOut;

                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${escapeHtml(domain)}</td>
                    <td>${stats.requests}</td>
                    <td>${formatBytes(stats.bytesIn)}</td>
                    <td>${formatBytes(stats.bytesOut)}</td>
                `;
                metricsBody.appendChild(tr);
            }

            document.getElementById('stat-total-domains').textContent = domains;
            document.getElementById('stat-total-requests').textContent = totalReqs;
            document.getElementById('stat-bandwidth').textContent = `${formatBytes(totalIn)} / ${formatBytes(totalOut)}`;

        } catch(e) {}
    }
});
