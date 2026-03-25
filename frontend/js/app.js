// Constants and State
const API_BASE = 'http://localhost:8000/api';
const WS_URL = 'ws://localhost:8000/ws/live';

let threatChart;
let chartData = {
    labels: Array(20).fill(''), // X axis time points
    datasets: [
        {
            label: 'Normal Requests',
            data: Array(20).fill(0),
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            borderWidth: 2,
            tension: 0.4,
            fill: true
        },
        {
            label: 'Total Blocks',
            data: Array(20).fill(0),
            borderColor: '#ef4444',
            backgroundColor: 'transparent',
            borderWidth: 2,
            tension: 0.4,
            borderDash: [5, 5]
        }
    ]
};

let totalPackets = 0;
let mlDetections = 0;
let currentBlocksCount = 0;

// Initialize when DOM loads
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    fetchInitialData();
    connectWebSocket();
});

// Chart.js Setup
function initChart() {
    Chart.defaults.color = '#8b92a5';
    Chart.defaults.font.family = "'Inter', sans-serif";
    
    const ctx = document.getElementById('threatChart').getContext('2d');
    threatChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: {
                duration: 0 // Disable animation for live updates
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: { boxWidth: 12, usePointStyle: true }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });

    // Update chart interval for sweeping time
    setInterval(tickChart, 2000);
}

function tickChart() {
    chartData.labels.push('');
    chartData.labels.shift();
    
    // Default zero logic if no packets arrive
    chartData.datasets[0].data.push(0); 
    chartData.datasets[0].data.shift();
    
    chartData.datasets[1].data.push(currentBlocksCount);
    chartData.datasets[1].data.shift();
    
    threatChart.update();
}

// Data Fetching
async function fetchInitialData() {
    try {
        const [blockedRes, statsRes] = await Promise.all([
            fetch(`${API_BASE}/blocked`).then(res => res.json()),
            fetch(`${API_BASE}/stats`).then(res => res.json())
        ]);

        if (blockedRes.status === 'success') {
            updateBlockedTable(blockedRes.blocked_ips);
            currentBlocksCount = blockedRes.blocked_ips.length;
            document.getElementById('stat-blocks').innerText = currentBlocksCount;
        }

    } catch (err) {
        console.error("Failed to fetch initial data:", err);
    }
}

// SPA Navigation
window.switchView = function(viewId, element) {
    // Hide all views
    document.querySelectorAll('.app-view').forEach(view => {
        view.style.display = 'none';
        view.classList.remove('active');
    });
    
    // Show target view
    const target = document.getElementById(`view-${viewId}`);
    if (target) {
        target.style.display = 'block';
        setTimeout(() => target.classList.add('active'), 10);
    }
    
    // Update active nav link
    if (element) {
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        element.classList.add('active');
    } else {
        // If profile clicked, remove all active sidebar highlight
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    }
}

// WebSocket Connection
function connectWebSocket() {
    const ws = new WebSocket(WS_URL);
    const connStatus = document.getElementById('conn-status');
    const pingDot = document.querySelector('.ping-dot');

    ws.onopen = () => {
        connStatus.innerText = 'Engine Online';
        pingDot.classList.add('active');
        document.getElementById('live-feed').innerHTML = ''; // Clear skeletons
    };

    ws.onclose = () => {
        connStatus.innerText = 'Engine Offline - Retrying...';
        pingDot.classList.remove('active');
        setTimeout(connectWebSocket, 5000);
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleLiveEvent(data);
    };
}

function handleLiveEvent(data) {
    // 1. Update Metrics
    totalPackets += data.req_count || 1;
    document.getElementById('stat-packets').innerText = formatNumber(totalPackets);

    if (data.blocked) {
        mlDetections++;
        document.getElementById('stat-ml').innerText = mlDetections;
        
        // Prevent hitting the API constantly. Just update UI if it's a new blocked IP.
        const encodedIp = data.ip.replace(/\./g, '-');
        if (!document.getElementById(`row-${encodedIp}`)) {
            currentBlocksCount++;
            document.getElementById('stat-blocks').innerText = currentBlocksCount;
            addSingleBlockedIp(data.ip);
        }
    }

    // 2. Add to Chart current tick (we just bump the last value)
    const lastIndex = chartData.datasets[0].data.length - 1;
    chartData.datasets[0].data[lastIndex] += data.req_count || 1;

    // 3. Add to live UI feed
    addFeedItem(data);
}

// UI Updaters
function addFeedItem(data) {
    const feed = document.getElementById('live-feed');
    const isMalicious = data.blocked;
    
    const timeString = new Date((data.timestamp || Date.now() / 1000) * 1000).toLocaleTimeString();
    
    const el = document.createElement('div');
    el.className = `feed-item ${isMalicious ? 'malicious' : ''}`;
    el.innerHTML = `
        <div class="feed-header">
            <span>${timeString}</span>
            <span><i class="fa-solid ${isMalicious ? 'fa-shield-virus' : 'fa-arrow-right-arrow-left'}"></i> ${data.req_count} reqs</span>
        </div>
        <div class="feed-ip">${data.ip}</div>
    `;

    feed.prepend(el);

    // Keep feed bounded
    if (feed.children.length > 30) {
        feed.removeChild(feed.lastChild);
    }
}

function updateBlockedTable(ips) {
    const tbody = document.getElementById('blocked-table-body');
    tbody.innerHTML = '';

    if (ips.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color: var(--text-secondary);">No active blocks.</td></tr>`;
        return;
    }

    // Due to mock simplified API, we just list IPs. In real app, we fetch full objects
    ips.forEach(ip => addSingleBlockedIp(ip));
}

function addSingleBlockedIp(ip) {
    const tbody = document.getElementById('blocked-table-body');
    const fullTbody = document.getElementById('full-blocked-table-body');
    
    // Remove "No active blocks" message if present
    if (tbody && tbody.innerHTML.includes('No active blocks')) tbody.innerHTML = '';
    if (fullTbody && fullTbody.innerHTML.includes('No active blocks')) fullTbody.innerHTML = '';
    
    const encodedIp = ip.replace(/\./g, '-');
    
    // Quick Dash Table
    if (tbody && !document.getElementById(`row-${encodedIp}`)) {
        const tr = document.createElement('tr');
        tr.id = `row-${encodedIp}`;
        tr.innerHTML = `
            <td>${ip}</td>
            <td><span class="badge badge-outline" style="border-color:var(--danger);color:var(--danger)">Threat Detected</span></td>
            <td>High</td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="unblockIp('${ip}')">Unblock</button>
            </td>
        `;
        tbody.appendChild(tr);
    }
    
    // Full DB Table (adds extra columns)
    if (fullTbody && !document.getElementById(`fullrow-${encodedIp}`)) {
        const trFull = document.createElement('tr');
        trFull.id = `fullrow-${encodedIp}`;
        trFull.innerHTML = `
            <td>${ip}</td>
            <td>Malicious Packet Signature / DDoS Attempt</td>
            <td><span class="text-red glow-text">98.5%</span></td>
            <td>${new Date().toLocaleTimeString()}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="unblockIp('${ip}')">Remove Rule</button>
            </td>
        `;
        fullTbody.appendChild(trFull);
    }
}

// Modal & Actions
function toggleManualBlockModal() {
    const modal = document.getElementById('blockModal');
    if (modal.classList.contains('active')) {
        modal.classList.remove('active');
    } else {
        modal.classList.add('active');
        document.getElementById('manualIpInput').focus();
    }
}

async function submitManualBlock() {
    const ip = document.getElementById('manualIpInput').value.trim();
    const reason = document.getElementById('manualReasonInput').value.trim() || 'Manual Block';

    if (!ip) return alert('IP Address is required');

    try {
        const res = await fetch(`${API_BASE}/block`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason })
        });
        const data = await res.json();
        
        if (data.status === 'success') {
            toggleManualBlockModal();
            document.getElementById('manualIpInput').value = '';
            document.getElementById('manualReasonInput').value = '';
            // Table updates via websocket or auto-refresh
        } else {
            alert('Error: ' + data.detail);
        }
    } catch (err) {
        alert('Failed to connect to server.');
    }
}

async function unblockIp(ip) {
    try {
        const res = await fetch(`${API_BASE}/unblock/${ip}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.status === 'success') {
            // Re-fetch list
            fetchInitialData();
        } else {
            alert('Error: ' + data.detail);
        }
    } catch (err) {
        alert('Failed to unblock IP.');
    }
}

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num;
}
