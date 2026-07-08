/* ==================== SECURITY MONITORING DASHBOARD - JavaScript ==================== */

// Configuration
const CONFIG = {
    refreshInterval: 5000, // 5 seconds
    alertSound: true,
    maxAlerts: 50,
    maxProcesses: 200,
    maxConnections: 100
};

// State Management
const state = {
    currentTab: 'overview',
    processFilter: '',
    riskFilter: '',
    connSuspiciousOnly: true,
    connEstablishedOnly: true,
    lastRefresh: null,
    baselineSet: false
};

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', () => {
    console.log('Initializing Security Monitoring Dashboard...');
    
    // Setup event listeners
    setupNavigation();
    setupSearch();
    setupFilters();
    
    // Initial data load
    refreshAllData();
    
    // Auto-refresh
    setInterval(refreshAllData, CONFIG.refreshInterval);
    
    // Update time
    updateTime();
    setInterval(updateTime, 1000);
    
    console.log('Dashboard initialized successfully');
});

// ==================== NAVIGATION ====================

function setupNavigation() {
    const navTabs = document.querySelectorAll('.nav-tab');
    navTabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
            const tabName = e.target.dataset.tab;
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    // Update active tab button
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update active tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    state.currentTab = tabName;
}

// ==================== SEARCH & FILTER ====================

function setupSearch() {
    const processFilter = document.getElementById('process-filter');
    if (processFilter) {
        processFilter.addEventListener('input', (e) => {
            state.processFilter = e.target.value.toLowerCase();
            filterProcessTable();
        });
    }
}

function setupFilters() {
    const riskFilter = document.getElementById('risk-filter');
    if (riskFilter) {
        riskFilter.addEventListener('change', (e) => {
            state.riskFilter = e.target.value;
            filterProcessTable();
        });
    }
    
    const suspiciousCheckbox = document.getElementById('conn-filter-suspicious');
    if (suspiciousCheckbox) {
        suspiciousCheckbox.addEventListener('change', (e) => {
            state.connSuspiciousOnly = e.target.checked;
            filterNetworkTable();
        });
    }
    
    const establishedCheckbox = document.getElementById('conn-filter-established');
    if (establishedCheckbox) {
        establishedCheckbox.addEventListener('change', (e) => {
            state.connEstablishedOnly = e.target.checked;
            filterNetworkTable();
        });
    }
}

function filterProcessTable() {
    const rows = document.querySelectorAll('#processes-list tr');
    rows.forEach(row => {
        const processName = row.cells[1]?.textContent.toLowerCase() || '';
        const riskLevel = row.cells[5]?.textContent || '';
        
        const matchesFilter = processName.includes(state.processFilter);
        const matchesRisk = !state.riskFilter || riskLevel.includes(state.riskFilter);
        
        row.style.display = (matchesFilter && matchesRisk) ? '' : 'none';
    });
}

function filterNetworkTable() {
    const rows = document.querySelectorAll('#network-list tr');
    rows.forEach(row => {
        const riskLevel = row.cells[4]?.textContent || '';
        const status = row.cells[3]?.textContent || '';
        
        const isSuspicious = riskLevel.includes('HIGH') || riskLevel.includes('MEDIUM');
        const isEstablished = status.includes('ESTABLISHED');
        
        const shouldShow = 
            (!state.connSuspiciousOnly || isSuspicious) &&
            (!state.connEstablishedOnly || isEstablished);
        
        row.style.display = shouldShow ? '' : 'none';
    });
}

// ==================== DATA FETCHING ====================

async function refreshAllData() {
    try {
        // Fetch all data in parallel
        const [systemData, processesData, networkData, alertsData, startupData] = await Promise.all([
            fetch('/api/system').then(r => r.json()),
            fetch('/api/processes').then(r => r.json()),
            fetch('/api/network').then(r => r.json()),
            fetch('/api/alerts').then(r => r.json()),
            fetch('/api/startup').then(r => r.json())
        ]);
        
        // Update UI
        updateSystemStatus(systemData);
        updateProcesses(processesData);
        updateNetwork(networkData);
        updateAlerts(alertsData);
        updateStartup(startupData);
        updateLastRefreshTime();
        
    } catch (error) {
        console.error('Error refreshing data:', error);
        showNotification('Error refreshing data', 'error');
    }
}

async function fetch_api(endpoint) {
    try {
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API error: ${endpoint}`, error);
        throw error;
    }
}

// ==================== SYSTEM STATUS ====================

function updateSystemStatus(data) {
    if (!data) return;
    
    // Update CPU
    const cpuPercent = Math.min(data.cpu_percent, 100);
    document.getElementById('cpu-bar').style.width = cpuPercent + '%';
    document.getElementById('cpu-percent').textContent = cpuPercent.toFixed(1) + '%';
    
    // Update Memory
    const memPercent = Math.min(data.memory.percent, 100);
    document.getElementById('memory-bar').style.width = memPercent + '%';
    document.getElementById('memory-percent').textContent = memPercent.toFixed(1) + '%';
    
    // Update Disk
    const diskPercent = Math.min(data.disk.percent, 100);
    document.getElementById('disk-bar').style.width = diskPercent + '%';
    document.getElementById('disk-percent').textContent = diskPercent.toFixed(1) + '%';
    
    // Update anomalies alert
    if (data.anomalies && data.anomalies.length > 0) {
        console.warn('System anomalies detected:', data.anomalies);
    }
}

// ==================== PROCESSES ====================

function updateProcesses(data) {
    if (!data) return;
    
    document.getElementById('threats-count').textContent = data.critical;
    document.getElementById('process-count').textContent = data.count;
    
    // Update processes list
    const tbody = document.getElementById('processes-list');
    tbody.innerHTML = '';
    
    if (data.processes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No processes found</td></tr>';
        return;
    }
    
    // Top 5 processes for overview
    const topProcesses = data.processes.slice(0, 5);
    const topTbody = document.getElementById('top-processes');
    if (topTbody) {
        topTbody.innerHTML = '';
        topProcesses.forEach(proc => {
            const row = document.createElement('tr');
            row.className = `risk-${proc.risk_level.toLowerCase()}`;
            row.innerHTML = `
                <td>${proc.pid}</td>
                <td>${proc.name}</td>
                <td>${proc.cpu_percent.toFixed(1)}%</td>
                <td>${proc.memory_mb.toFixed(0)}MB</td>
                <td><span class="risk-badge risk-${proc.risk_level.toLowerCase()}">${proc.risk_level}</span></td>
            `;
            topTbody.appendChild(row);
        });
    }
    
    // Full processes table
    data.processes.forEach(proc => {
        const row = document.createElement('tr');
        const factorsHtml = proc.factors ? proc.factors.map(f => `<span class="risk-badge">${f}</span>`).join(' ') : 'N/A';
        
        row.innerHTML = `
            <td>${proc.pid}</td>
            <td>${escapeHtml(proc.name)}</td>
            <td title="${escapeHtml(proc.path)}">${truncate(proc.path, 40)}</td>
            <td>${proc.cpu_percent.toFixed(1)}%</td>
            <td>${proc.memory_mb.toFixed(0)}MB</td>
            <td><span class="risk-badge risk-${proc.risk_level.toLowerCase()}">${proc.risk_level}</span></td>
            <td>${factorsHtml}</td>
            <td>
                ${proc.risk_level !== 'LOW' ? `<button class="btn btn-danger btn-small" onclick="killProcess(${proc.pid}, '${escapeHtml(proc.name)}')">Kill</button>` : ''}
            </td>
        `;
        
        tbody.appendChild(row);
    });
    
    filterProcessTable();
}

async function killProcess(pid, name) {
    if (!confirm(`Are you sure you want to terminate ${name} (PID ${pid})?`)) {
        return;
    }
    
    try {
        const response = await fetch(`/api/process/${pid}/kill`, { method: 'POST' });
        const result = await response.json();
        
        if (result.success) {
            showNotification(`Process ${name} terminated`, 'success');
            setTimeout(() => refreshAllData(), 1000);
        } else {
            showNotification(`Error: ${result.error}`, 'error');
        }
    } catch (error) {
        showNotification('Error terminating process', 'error');
        console.error(error);
    }
}

// ==================== NETWORK ====================

function updateNetwork(data) {
    if (!data) return;
    
    // Update stats
    document.getElementById('net-total').textContent = data.stats.total;
    document.getElementById('net-established').textContent = data.stats.established;
    document.getElementById('net-listening').textContent = data.stats.listening;
    document.getElementById('net-suspicious').textContent = data.stats.suspicious;
    document.getElementById('connections-count').textContent = data.stats.total;
    
    // Update connections table
    const tbody = document.getElementById('network-list');
    tbody.innerHTML = '';
    
    if (data.connections.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center">No connections found</td></tr>';
        return;
    }
    
    data.connections.forEach(conn => {
        const row = document.createElement('tr');
        const factorsHtml = conn.factors ? conn.factors.map(f => `<span class="risk-badge">${f}</span>`).join(' ') : 'N/A';
        
        row.innerHTML = `
            <td>${escapeHtml(conn.process)}</td>
            <td>${conn.local_ip}:${conn.local_port}</td>
            <td>${conn.remote_ip}:${conn.remote_port}</td>
            <td>${conn.status}</td>
            <td><span class="risk-badge risk-${conn.risk_level.toLowerCase()}">${conn.risk_level}</span></td>
            <td>${factorsHtml}</td>
        `;
        
        tbody.appendChild(row);
    });
    
    filterNetworkTable();
}

// ==================== STARTUP PROGRAMS ====================

function updateStartup(data) {
    if (!data) return;
    
    const tbody = document.getElementById('startup-list');
    tbody.innerHTML = '';
    
    if (data.items.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center">No startup programs found</td></tr>';
        return;
    }
    
    data.items.forEach(item => {
        const row = document.createElement('tr');
        row.className = item.risk === 'HIGH' ? 'risk-high' : '';
        
        row.innerHTML = `
            <td>${escapeHtml(item.name)}</td>
            <td title="${escapeHtml(item.path)}">${truncate(item.path, 50)}</td>
            <td><code>${escapeHtml(item.registry_path)}</code></td>
            <td><span class="risk-badge risk-${item.risk.toLowerCase()}">${item.risk}</span></td>
        `;
        
        tbody.appendChild(row);
    });
}

// ==================== ALERTS ====================

function updateAlerts(data) {
    if (!data) return;
    
    document.getElementById('alert-critical-stat').textContent = `${data.critical} Critical`;
    document.getElementById('alert-high-stat').textContent = `${data.high} High`;
    document.getElementById('alerts-count').textContent = data.count;
    
    const container = document.getElementById('alerts-container');
    container.innerHTML = '';
    
    if (data.alerts.length === 0) {
        container.innerHTML = '<div class="placeholder">No alerts at this time</div>';
        return;
    }
    
    data.alerts.forEach(alert => {
        const alertElement = document.createElement('div');
        alertElement.className = `alert-item ${alert.severity.toLowerCase()}`;
        
        const timeAgo = getTimeAgo(new Date(alert.timestamp));
        
        alertElement.innerHTML = `
            <span class="alert-time">${timeAgo}</span>
            <div class="alert-title">
                <span class="risk-badge risk-${alert.severity.toLowerCase()}">${alert.severity}</span>
                ${escapeHtml(alert.title)}
            </div>
            <div class="alert-description">${escapeHtml(alert.description)}</div>
            <div class="alert-recommendation">💡 ${escapeHtml(alert.recommendation)}</div>
        `;
        
        container.appendChild(alertElement);
        
        // Play sound for critical alerts
        if (alert.severity === 'CRITICAL' && CONFIG.alertSound) {
            playAlertSound();
        }
    });
}

// ==================== UTILITY FUNCTIONS ====================

function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { 
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    document.getElementById('time').textContent = timeString;
}

function updateLastRefreshTime() {
    state.lastRefresh = new Date();
    document.getElementById('last-update').textContent = state.lastRefresh.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function truncate(text, length) {
    if (!text) return 'N/A';
    return text.length > length ? text.substring(0, length) + '...' : text;
}

function getTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    return Math.floor(seconds / 86400) + 'd ago';
}

function showNotification(message, type = 'info') {
    // You can implement a toast notification here
    console.log(`[${type.toUpperCase()}] ${message}`);
    
    // Simple alert for now
    if (type === 'error') {
        alert('❌ ' + message);
    } else if (type === 'success') {
        alert('✓ ' + message);
    }
}

function playAlertSound() {
    // Create a beep sound using Web Audio API
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.value = 800;
        oscillator.type = 'sine';
        
        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.5);
    } catch (e) {
        console.warn('Could not play alert sound:', e);
    }
}

// ==================== ACTION BUTTONS ====================

function setBaseline() {
    if (confirm('Set current system metrics as baseline for anomaly detection?')) {
        fetch('/api/baseline', { method: 'POST' })
            .then(r => r.json())
            .then(result => {
                if (result.success) {
                    state.baselineSet = true;
                    showNotification('Baseline metrics set successfully', 'success');
                } else {
                    showNotification('Error setting baseline', 'error');
                }
            })
            .catch(err => {
                console.error(err);
                showNotification('Error setting baseline', 'error');
            });
    }
}

function refreshAllData_Manual() {
    refreshAllData();
}

function exportAlerts() {
    fetch('/api/export/alerts')
        .then(r => r.json())
        .then(data => {
            const json = JSON.stringify(data, null, 2);
            const blob = new Blob([json], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security_alerts_${new Date().getTime()}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showNotification('Alerts exported successfully', 'success');
        })
        .catch(err => {
            console.error(err);
            showNotification('Error exporting alerts', 'error');
        });
}

// ==================== KEYBOARD SHORTCUTS ====================

document.addEventListener('keydown', (e) => {
    // Ctrl+R: Full refresh
    if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        refreshAllData();
    }
    
    // Ctrl+B: Set baseline
    if (e.ctrlKey && e.key === 'b') {
        e.preventDefault();
        setBaseline();
    }
    
    // Ctrl+E: Export alerts
    if (e.ctrlKey && e.key === 'e') {
        e.preventDefault();
        exportAlerts();
    }
});

// ==================== PERFORMANCE MONITORING ====================

let lastUpdateTime = 0;

function recordUpdate() {
    const now = performance.now();
    if (lastUpdateTime > 0) {
        const deltaTime = now - lastUpdateTime;
        if (deltaTime > 100) {
            console.warn(`Slow update detected: ${deltaTime.toFixed(0)}ms`);
        }
    }
    lastUpdateTime = now;
}

// ==================== CONSOLE LOGGING ====================

console.log('%c🛡️ SECURITY MONITORING DASHBOARD', 'color: #00ff41; font-size: 16px; font-weight: bold;');
console.log('%cKeyboard Shortcuts:', 'color: #00ff41; font-weight: bold;');
console.log('%cCtrl+R: Refresh all data', 'color: #ffa500;');
console.log('%cCtrl+B: Set baseline metrics', 'color: #ffa500;');
console.log('%cCtrl+E: Export alerts', 'color: #ffa500;');
console.log('%cAPI Endpoints available:', 'color: #00ff41; font-weight: bold;');
console.log('%c/api/system - System status', 'color: #3b82f6;');
console.log('%c/api/processes - Process information', 'color: #3b82f6;');
console.log('%c/api/network - Network connections', 'color: #3b82f6;');
console.log('%c/api/alerts - Security alerts', 'color: #3b82f6;');
console.log('%c/api/startup - Startup programs', 'color: #3b82f6;');
