document.addEventListener('DOMContentLoaded', () => {
    const authView = document.getElementById('auth-view');
    const dashboardView = document.getElementById('dashboard-view');
    const loginForm = document.getElementById('login-form');
    const logoutBtn = document.getElementById('logout-btn');
    
    const addModal = document.getElementById('add-modal');
    const addRecordBtn = document.getElementById('add-record-btn');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const addRecordForm = document.getElementById('add-record-form');
    const dnsTbody = document.getElementById('dns-tbody');

    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        authView.classList.remove('active');
        dashboardView.classList.add('active');
        fetchRecords(); 
    });

    logoutBtn.addEventListener('click', () => {
        dashboardView.classList.remove('active');
        authView.classList.add('active');
        loginForm.reset();
    });

    addRecordBtn.addEventListener('click', () => {
        addModal.classList.add('active');
    });

    closeModalBtn.addEventListener('click', () => {
        addModal.classList.remove('active');
        addRecordForm.reset();
    });

    async function fetchRecords() {
        try {
            const response = await fetch('/api/records');
            if (!response.ok) throw new Error('Failed to fetch records');
            const records = await response.json();
            
            dnsTbody.innerHTML = ''; 
            
            if (records && records.length > 0) {
                records.forEach(record => {
                    appendRecordToTable(record.domain, record.port, record.enabled);
                });
            } else {
                dnsTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--muted-foreground);">No mappings found.</td></tr>';
            }
        } catch (err) {
            console.error(err);
            dnsTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--muted-foreground);">Failed to load mappings. Check backend connection.</td></tr>';
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

        // Toggle Event
        tr.querySelector('.toggle-btn').addEventListener('click', async (e) => {
            const btn = e.target;
            const currentEnabled = btn.getAttribute('data-enabled') === 'true';
            
            try {
                const res = await fetch('/api/records/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain, enabled: !currentEnabled })
                });
                if (!res.ok) throw new Error(await res.text());
                fetchRecords(); // refresh
            } catch (err) {
                alert('Failed to toggle: ' + err.message);
            }
        });

        // Delete Event
        tr.querySelector('.delete-btn').addEventListener('click', async (e) => {
            if(!confirm(`Delete mapping for ${domain}?`)) return;
            try {
                const res = await fetch('/api/records', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain })
                });
                if (!res.ok) throw new Error(await res.text());
                fetchRecords();
            } catch (err) {
                alert('Failed to delete: ' + err.message);
            }
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
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ domain, port, enabled })
            });

            if (!response.ok) {
                const errMsg = await response.text();
                throw new Error(errMsg);
            }

            addModal.classList.remove('active');
            addRecordForm.reset();
            fetchRecords();
            
        } catch (err) {
            alert('Failed to save mapping: ' + err.message + '\nNote: Run Trels as Administrator to edit the hosts file.');
            console.error(err);
        }
    });
});
