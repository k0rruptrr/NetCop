const API_BASE = '/api';
let agentsState = {};
let selectedHostname = null;
let trafficChart = null;

let apiKey = sessionStorage.getItem('netcop_api_key');
while (!apiKey) {
    apiKey = prompt("Enter NetCop API Key (required to continue):");
    if (apiKey) {
        sessionStorage.setItem('netcop_api_key', apiKey);
    } else {
        alert("API Key is required. Please provide it.");
    }
}

function escapeHTML(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag] || tag)
    );
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

async function fetchWithAuth(url, options = {}) {
    if (!options.headers) options.headers = {};
    options.headers['X-NetCop-Key'] = apiKey || '';
    const res = await fetch(url, options);
    if (res.status === 403) {
        sessionStorage.removeItem('netcop_api_key');
        throw new Error("Invalid API Key");
    }
    return res;
}

function initChart() {
    const ctx = document.getElementById('traffic-chart').getContext('2d');
    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Inbound',
                    borderColor: '#38bdf8',
                    backgroundColor: 'rgba(56, 189, 248, 0.1)',
                    data: [],
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Outbound',
                    borderColor: '#fb923c',
                    backgroundColor: 'rgba(251, 146, 60, 0.1)',
                    data: [],
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false, // Turn off animation for frequent updates
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#a0a5b8' }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: {
                        color: '#a0a5b8',
                        callback: function(value) { return formatBytes(value) + '/s'; }
                    }
                }
            },
            plugins: {
                legend: { labels: { color: '#f8f9fa' } }
            }
        }
    });
}

async function fetchStatus() {
    try {
        const response = await fetchWithAuth(`${API_BASE}/status`);
        const data = await response.json();
        agentsState = data.agents;
        renderAgents();
        if (currentModalHostname && agentsState[currentModalHostname]) {
            renderProcesses(currentModalHostname);
        }
    } catch (error) {
        console.error('Error fetching status:', error);
    }
}

function renderAgents() {
    const tbody = document.getElementById('agents-tbody');
    tbody.innerHTML = '';
    
    let activeCount = 0;
    const alertThresholdMbps = parseInt(document.getElementById('alert-threshold').value) || 50;
    const thresholdBytes = alertThresholdMbps * 125000;
    
    for (const [hostname, agent] of Object.entries(agentsState)) {
        if (agent.status === 'online') activeCount++;
        
        const isAlert = agent.traffic_in_bps > thresholdBytes;
        
        const tr = document.createElement('tr');
        if (isAlert) {
            tr.classList.add('alert-pulse');
        }
        
        const statusHtml = `
            <div class="status-indicator ${agent.status}">
                <div class="status-dot"></div>
                ${agent.status.charAt(0).toUpperCase() + agent.status.slice(1)}
            </div>
        `;
        
        const safeHostname = escapeHTML(hostname);
        const safeIp = escapeHTML(agent.ip);
        const safeMac = escapeHTML(agent.mac);

        const hostnameHtml = `
            <div class="hostname" onclick="selectAgent('${safeHostname}')">${safeHostname}</div>
            <div class="meta-text" title="Last seen">
                ${new Date(agent.last_seen * 1000).toLocaleTimeString()}
            </div>
            <button class="btn btn-sm" style="margin-top:0.5rem" onclick="showProcesses('${safeHostname}')">Processes & QoS</button>
        `;
        
        const ipMacHtml = `
            <div>${safeIp}</div>
            <div class="meta-text">${safeMac}</div>
        `;
        
        const trafficHtml = `
            <div title="Inbound Traffic">
                <span class="traffic-badge">↓ ${formatBytes(agent.traffic_in_bps)}/s</span>
            </div>
            <div style="margin-top:0.25rem" title="Outbound Traffic">
                <span class="traffic-badge out">↑ ${formatBytes(agent.traffic_out_bps)}/s</span>
            </div>
        `;
        
        const limitDisplay = agent.limit_mbps ? `${agent.limit_mbps} Mbit/s` : 'None';
        const limitHtml = `
            <div style="margin-bottom:0.5rem">Global: <strong>${limitDisplay}</strong></div>
            <div class="actions-cell">
                <input type="number" id="limit-${hostname}" class="limit-input" placeholder="Mbit/s" min="1">
                <button class="btn btn-primary btn-sm" onclick="setLimit('${safeHostname}')">Apply</button>
            </div>
        `;
        
        const actionsHtml = `
            <div class="actions-cell">
                <button class="btn btn-sm" onclick="unlimit('${safeHostname}')">RM Limit</button>
                <button class="btn btn-danger btn-sm" onclick="killNetwork('${safeHostname}')">Kill Net</button>
            </div>
        `;
        
        tr.innerHTML = `
            <td>${statusHtml}</td>
            <td>${hostnameHtml}</td>
            <td>${ipMacHtml}</td>
            <td>${trafficHtml}</td>
            <td>${limitHtml}</td>
            <td>${actionsHtml}</td>
        `;
        tbody.appendChild(tr);
    }
    
    document.getElementById('active-agents-count').textContent = activeCount;
}

function selectAgent(hostname) {
    selectedHostname = hostname;
    document.getElementById('chart-hostname-label').textContent = `- ${hostname}`;
    document.getElementById('chart-overlay').classList.add('hidden');
    fetchHistory();
}

async function fetchHistory() {
    if (!selectedHostname) return;
    try {
        const response = await fetchWithAuth(`${API_BASE}/history/${selectedHostname}`);
        const data = await response.json();
        const history = data.history;
        
        trafficChart.data.labels = history.map(d => new Date(d.t * 1000).toLocaleTimeString());
        trafficChart.data.datasets[0].data = history.map(d => d.in);
        trafficChart.data.datasets[1].data = history.map(d => d.out);
        trafficChart.update('none'); // silent update
    } catch(e) { console.error(e); }
}

let currentModalHostname = null;

function showProcesses(hostname) {
    currentModalHostname = hostname;
    renderProcesses(hostname);
    document.getElementById('processes-modal').classList.add('active');
}

function renderProcesses(hostname) {
    if (currentModalHostname !== hostname) return;
    
    const agent = agentsState[hostname];
    if (!agent) return;
    
    const tbody = document.getElementById('processes-tbody');
    tbody.innerHTML = '';
    
    const processLimits = agent.process_limits || {};
    const categoriesPresent = new Set();

    agent.top_processes.forEach(p => {
        const safeName = escapeHTML(p.name);
        const safeExe = p.exe ? escapeHTML(p.exe.split('\\').pop()) : safeName;
        const category = p.category || 'other';
        categoriesPresent.add(category);
        
        const isThrottled = processLimits.hasOwnProperty(safeExe);
        const currentLimit = processLimits[safeExe];
        
        const tr = document.createElement('tr');
        if (isThrottled) tr.classList.add('process-throttled');
        
        let catBadge = category !== 'other' ? `<span class="cat-badge cat-${category}">${category}</span>` : '';
        
        let actionBtn = isThrottled 
            ? `<button class="btn btn-sm" onclick="unlimitProcess('${hostname}', '${safeExe}')">✕ Unthrottle IN+OUT (${currentLimit}M)</button>`
            : `<button class="btn btn-sm btn-primary" onclick="limitProcess('${hostname}', '${safeExe}')">✂ Throttle IN+OUT</button>`;
            
        tr.innerHTML = `
            <td>${safeName}</td>
            <td>${catBadge}</td>
            <td>${p.pid}</td>
            <td>${p.connections}</td>
            <td>${(p.cpu_percent || 0).toFixed(1)}%</td>
            <td>${(p.memory_mb || 0).toFixed(1)}</td>
            <td>${actionBtn}</td>
        `;
        tbody.appendChild(tr);
    });
    
    const massContainer = document.getElementById('mass-actions-container');
    massContainer.innerHTML = '';
    if (categoriesPresent.has('torrent')) {
        massContainer.innerHTML += `<button class="btn btn-sm btn-danger" onclick="massLimit('${hostname}', 'torrent')">Throttle all torrents</button>`;
    }
    if (categoriesPresent.has('streaming')) {
        massContainer.innerHTML += `<button class="btn btn-sm btn-danger" onclick="massLimit('${hostname}', 'streaming')">Throttle all streaming</button>`;
    }
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
    if (id === 'processes-modal') currentModalHostname = null;
}

function getDefaultThrottle() {
    return parseInt(document.getElementById('default-throttle').value) || 2;
}

async function setLimit(hostname) {
    const input = document.getElementById(`limit-${hostname}`);
    const val = parseInt(input.value);
    if (!val) return alert('Enter a valid limit in Mbit/s');
    
    try {
        await fetchWithAuth(`${API_BASE}/limit/${hostname}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({speed_mbps: val})
        });
        input.value = '';
        fetchStatus();
    } catch (e) { console.error(e); }
}

async function unlimit(hostname) {
    try {
        await fetchWithAuth(`${API_BASE}/unlimit/${hostname}`, { method: 'POST' });
        fetchStatus();
    } catch (e) { console.error(e); }
}

async function killNetwork(hostname) {
    if(!confirm(`Are you sure you want to disable the network interface on ${hostname}? This requires manual intervention on the host to fix!`)) return;
    try {
        await fetchWithAuth(`${API_BASE}/kill/${hostname}`, { method: 'POST' });
        fetchStatus();
    } catch (e) { console.error(e); }
}

async function limitProcess(hostname, exeName) {
    const limit = getDefaultThrottle();
    try {
        await fetchWithAuth(`${API_BASE}/full_throttle/${hostname}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({exe_name: exeName, speed_mbps: limit})
        });
        fetchStatus();
    } catch(e) { console.error(e); }
}

async function unlimitProcess(hostname, exeName) {
    try {
        await fetchWithAuth(`${API_BASE}/full_unthrottle/${hostname}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({exe_name: exeName})
        });
        fetchStatus();
    } catch(e) { console.error(e); }
}

async function massLimit(hostname, category) {
    const agent = agentsState[hostname];
    if (!agent) return;
    
    const limit = getDefaultThrottle();
    const exesToLimit = new Set();
    
    agent.top_processes.forEach(p => {
        if (p.category === category) {
            const exe = p.exe ? p.exe.split('\\').pop() : p.name;
            exesToLimit.add(exe);
        }
    });
    
    for (const exe of exesToLimit) {
        try {
            await fetchWithAuth(`${API_BASE}/full_throttle/${hostname}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({exe_name: exe, speed_mbps: limit})
            });
        } catch(e) { console.error(e); }
    }
    fetchStatus();
}

// Init
initChart();
fetchStatus();
setInterval(fetchStatus, 3000);
setInterval(fetchHistory, 5000);
