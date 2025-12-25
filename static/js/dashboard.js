document.addEventListener('DOMContentLoaded', function() {
    console.log("🚀 Dashboard Script Started");

    // --- STATE VARIABLES (Defined at top to avoid ReferenceErrors) ---
    let clientLogs = [];
    let isMuted = false;
    let audioCtx = null;
    let attackChart = null;
    let distributionChart = null;

    // --- DOM ELEMENTS ---
    const threatLevelEl = document.getElementById('threat-level');
    const totalScansEl = document.getElementById('total-scans');
    const attacksBlockedEl = document.getElementById('attacks-blocked');
    const consoleWindow = document.getElementById('console-window');
    const cpuEl = document.getElementById('cpu-val');
    const ramEl = document.getElementById('ram-val');
    const netEl = document.getElementById('net-val');
    const mapCanvas = document.getElementById('worldMap');
    const mapCtx = mapCanvas.getContext('2d');

    // --- MAP INITIALIZATION ---
    const mapImg = new Image();
    mapImg.onload = () => {
        console.log("✅ World Map Image Loaded Successfully", mapImg.width, "x", mapImg.height);
        drawMap(false);
    };
    mapImg.onerror = (e) => console.error("❌ World Map Image Failed to Load", e);
    mapImg.src = "/static/img/world_map.png?t=" + new Date().getTime();

    function resizeMap() {
        if (!mapCanvas.parentElement) return;
        mapCanvas.width = mapCanvas.parentElement.clientWidth;
        mapCanvas.height = mapCanvas.parentElement.clientHeight;
        drawMap(false);
    }
    window.addEventListener('resize', resizeMap);
    resizeMap();

    // --- CHART INITIALIZATION ---
    try {
        const ctx = document.getElementById('attackChart').getContext('2d');
        const MAX_POINTS = 50;
        attackChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(MAX_POINTS).fill(''),
                datasets: [{
                    label: 'Attack Probability',
                    data: Array(MAX_POINTS).fill(0),
                    borderColor: '#00f3ff',
                    backgroundColor: 'rgba(0, 243, 255, 0.1)',
                    borderWidth: 2,
                    tension: 0.5,
                    fill: true,
                    pointRadius: 0,
                    pointHoverRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, max: 1, grid: { color: 'rgba(0, 243, 255, 0.05)' }, ticks: { color: '#88aaff', font: {family: 'Rajdhani'} } },
                    x: { display: false }
                },
                plugins: { legend: { display: false } },
                animation: { duration: 0 }
            }
        });

        const distCtx = document.getElementById('distributionChart').getContext('2d');
        distributionChart = new Chart(distCtx, {
            type: 'doughnut',
            data: {
                labels: ['DDoS', 'Brute Force', 'Malware', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#ff0055', '#ffcc00', '#00f3ff', '#888'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { color: '#fff', font: {size: 10} } }
                }
            }
        });
    } catch(e) {
        console.error("📊 Chart Initialization Failed:", e);
    }

    // --- CORE API FUNCTIONS ---
    window.setScenario = function(scenario) {
        document.querySelectorAll('.btn').forEach(btn => btn.classList.remove('active'));
        const btnMap = { 'NORMAL':0, 'DDOS':1, 'BRUTE_FORCE':2 };
        const buttons = document.querySelectorAll('.btn-group .btn');
        if (buttons[btnMap[scenario]]) buttons[btnMap[scenario]].classList.add('active');

        fetch('/api/control/scenario', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({scenario: scenario})
        }).then(r => r.json()).then(d => console.log("Scenario Update:", d));
    }

    window.setThreshold = function(val) {
        document.getElementById('thresh-val').innerText = val + "%";
        fetch('/api/control/threshold', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({threshold: val/100})
        }).then(r => r.json()).then(d => console.log("Threshold Update:", d));
    }

    // --- RENDERING FUNCTIONS ---
    function drawMap(isAttack) {
        if (!mapCtx) return;
        mapCtx.clearRect(0, 0, mapCanvas.width, mapCanvas.height);
        
        const imgAspect = 2;
        const canvasAspect = mapCanvas.width / mapCanvas.height;
        let drawW, drawH, offsetX, offsetY;
        
        if (canvasAspect > imgAspect) {
             drawH = mapCanvas.height;
             drawW = drawH * imgAspect;
             offsetX = (mapCanvas.width - drawW) / 2;
             offsetY = 0;
        } else {
             drawW = mapCanvas.width;
             drawH = drawW / imgAspect;
             offsetX = 0;
             offsetY = (mapCanvas.height - drawH) / 2;
        }
        
        if (mapImg.complete && mapImg.naturalWidth > 0) {
            mapCtx.globalAlpha = 1.0;
            mapCtx.drawImage(mapImg, offsetX, offsetY, drawW, drawH);
        }
        
        const cx = offsetX + drawW / 2;
        const cy = offsetY + drawH / 2;
        
        clientLogs.forEach(log => {
            if (log.geo && log.geo.lat !== 0) {
                const x = offsetX + (log.geo.lon + 180) * (drawW / 360);
                const y = offsetY + ((-log.geo.lat) + 90) * (drawH / 180);
                
                mapCtx.beginPath();
                mapCtx.moveTo(x, y);
                mapCtx.lineTo(cx, cy);
                
                if (log.source === 'REAL') {
                    mapCtx.strokeStyle = '#00f3ff';
                    mapCtx.lineWidth = 1.5;
                } else {
                    if (log.result.alert_level === 'CRITICAL') mapCtx.strokeStyle = 'rgba(255, 0, 0, 0.4)';
                    else if (log.result.alert_level === 'HIGH') mapCtx.strokeStyle = 'rgba(255, 165, 0, 0.3)';
                    else mapCtx.strokeStyle = 'rgba(0, 255, 0, 0.1)';
                    mapCtx.lineWidth = 1;
                }
                mapCtx.stroke();
                
                mapCtx.fillStyle = mapCtx.strokeStyle;
                mapCtx.beginPath();
                mapCtx.arc(x, y, 4, 0, Math.PI * 2);
                mapCtx.fill();
                
                if(log.source === 'REAL' || Math.random() > 0.95) { 
                     mapCtx.fillStyle = '#fff';
                     mapCtx.font = '12px "Rajdhani", monospace';
                     const label = log.geo.city !== 'Unknown' ? `${log.geo.city}, ${log.geo.country}` : log.geo.country;
                     mapCtx.fillText(label, x + 8, y + 4);
                }
            }
        });
    }

    function addLogEntry(data) {
        clientLogs.push(data);
        if(clientLogs.length > 50) clientLogs.shift();

        if (data.result.is_attack) playAlertSound(data.result.alert_level);

        const div = document.createElement('div');
        div.className = `log-entry ${data.result.is_attack ? 'attack' : 'normal'}`;
        
        const sourceBadge = data.source === "REAL" ? '<span class="badge-real">LIVE</span>' : '';
        const loc = data.geo.city !== 'Unknown' ? `[${data.geo.city}, ${data.geo.country}]` : '';
        
        div.innerHTML = `<span class="log-time">[${data.timestamp}]</span> <span class="log-ip">${sourceBadge} ${data.ip}</span> <span class="log-msg">${loc} ${data.result.message}</span>`;
        consoleWindow.insertBefore(div, consoleWindow.firstChild);
        if (consoleWindow.children.length > 50) consoleWindow.removeChild(consoleWindow.lastChild);
    }

    function updateChart(probability) {
        if (!attackChart) return;
        attackChart.data.datasets[0].data.shift();
        attackChart.data.datasets[0].data.push(probability);
        
        const isHigh = probability > 0.35;
        attackChart.data.datasets[0].borderColor = isHigh ? '#ff0055' : '#00f3ff';
        attackChart.data.datasets[0].backgroundColor = isHigh ? 'rgba(255, 0, 85, 0.2)' : 'rgba(0, 243, 255, 0.1)';
        attackChart.update();
    }
    
    // --- API POLLING ---
    function fetchSimulation() {
        fetch('/api/simulate')
            .then(r => r.json())
            .then(data => {
                if(data.status === 'idle') return;
                addLogEntry(data);
                updateChart(data.result.attack_probability);
                drawMap(data.result.is_attack);
            })
            .catch(err => console.error("📡 Simulation API Error:", err));
    }
    
    function updateStats() {
        fetch('/api/stats')
            .then(r => r.json())
            .then(data => {
                if (!data || !data.stats) return;
                const stats = data.stats;
                totalScansEl.innerText = stats.total_requests;
                attacksBlockedEl.innerText = stats.attacks_blocked;
                
                threatLevelEl.innerText = stats.current_threat_level;
                threatLevelEl.className = 'stat-value ' + stats.current_threat_level;

                if(data.system) {
                    cpuEl.innerText = data.system.cpu + "%";
                    ramEl.innerText = data.system.ram + "%";
                    netEl.innerText = data.system.net + "Mbps";
                }

                if(stats.attack_types && distributionChart) {
                    distributionChart.data.datasets[0].data = [
                        stats.attack_types["DDoS"] || 0,
                        stats.attack_types["Brute Force"] || 0,
                        stats.attack_types["Malware"] || 0,
                        stats.attack_types["Other"] || 0
                    ];
                    distributionChart.update();
                }
            })
            .catch(err => console.error("📊 Stats API Error:", err));
    }

    // --- MATRIX EFFECT ---
    const matrixCtx = document.getElementById('matrixCanvas').getContext('2d');
    let mW = matrixCanvas.width = window.innerWidth;
    let mH = matrixCanvas.height = window.innerHeight;
    const ypos = Array(Math.floor(mW / 20)).fill(0);

    setInterval(() => {
        matrixCtx.fillStyle = '#0001';
        matrixCtx.fillRect(0, 0, mW, mH);
        matrixCtx.fillStyle = '#0f0';
        matrixCtx.font = '15px monospace';
        ypos.forEach((y, ind) => {
            matrixCtx.fillText(String.fromCharCode(Math.random() * 128), ind * 20, y);
            if (y > 100 + Math.random() * 10000) ypos[ind] = 0;
            else ypos[ind] = y + 20;
        });
    }, 50);

    // --- AUDIO ---
    function initAudio() {
        if (!audioCtx) {
            audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        }
        if (audioCtx.state === 'suspended') audioCtx.resume();
    }
    document.addEventListener('click', initAudio, {once: true});

    window.toggleMute = function() {
        initAudio();
        isMuted = !isMuted;
        document.getElementById('muteBtn').innerText = isMuted ? '🔇' : '🔊';
    }

    function playAlertSound(level) {
        if (isMuted || !audioCtx) return;
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        
        if (level === 'CRITICAL') {
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(800, audioCtx.currentTime);
            osc.frequency.linearRampToValueAtTime(1200, audioCtx.currentTime + 0.1);
            gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.5);
            osc.start(); osc.stop(audioCtx.currentTime + 0.5);
        } else {
            osc.type = 'square';
            osc.frequency.setValueAtTime(600, audioCtx.currentTime);
            gain.gain.setValueAtTime(0.05, audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.2);
            osc.start(); osc.stop(audioCtx.currentTime + 0.2);
        }
    }

    // --- FIREWALL ---
    window.addRule = function(type) {
        const ip = document.getElementById('rule-ip').value.trim();
        if (!ip.match(/^\d+\.\d+\.\d+\.\d+$/)) return alert("Invalid IP");
        
        fetch('/api/rules/update', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'add', ip: ip, type: type})
        }).then(r => r.json()).then(data => {
            if(data.status === 'ok') {
                document.getElementById('rule-ip').value = '';
                updateRulesList(data.rules);
            }
        });
    }

    window.removeRule = function(ip, type) {
        fetch('/api/rules/update', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'remove', ip: ip, type: type})
        }).then(r => r.json()).then(data => {
            if(data.status === 'ok') updateRulesList(data.rules);
        });
    }

    function updateRulesList(rules) {
        const listEl = document.getElementById('active-rules');
        listEl.innerHTML = '';
        ['whitelist', 'blacklist'].forEach(type => {
            rules[type].forEach(ip => {
                const div = document.createElement('div');
                div.className = `rule-item ${type === 'whitelist' ? 'rule-allow' : 'rule-block'}`;
                div.innerHTML = `<span>${type === 'whitelist' ? '✅' : '🚫'} ${ip}</span> <button class="btn-sm" onclick="removeRule('${ip}', '${type}')">✕</button>`;
                listEl.appendChild(div);
            });
        });
    }

    // --- INITIALIZATION ---
    fetch('/api/rules').then(r => r.json()).then(updateRulesList);
    
    console.log("⏱️ Starting Intervals...");
    setInterval(fetchSimulation, 1000); 
    setInterval(updateStats, 2000);
    console.log("✨ Dashboard Fully Initialized");
});
