document.addEventListener('DOMContentLoaded', () => {
    const statusIndicator = document.getElementById('status-indicator');

    // Simulate an API call to the Go backend
    fetch('http://localhost:8080/api/status')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'running') {
                statusIndicator.textContent = 'Online - ' + data.message;
                statusIndicator.className = 'online';
            } else {
                statusIndicator.textContent = 'Unknown Status';
                statusIndicator.className = 'offline';
            }
        })
        .catch(error => {
            statusIndicator.textContent = 'Offline (Backend not reachable)';
            statusIndicator.className = 'offline';
        });
});
