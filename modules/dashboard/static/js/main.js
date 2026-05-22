document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const scanForm = document.getElementById('scan-form');
    const pkgInput = document.getElementById('package-input');
    const ecoSelect = document.getElementById('ecosystem-select');
    const scanBtn = document.getElementById('scan-btn');
    const historySearch = document.getElementById('history-search');
    const historyList = document.getElementById('history-items');
    const refreshBtn = document.getElementById('refresh-btn');
    const detailCard = document.getElementById('detail-card');
    const reportTemplate = document.getElementById('report-template');
    
    // Toggles
    const toggleRep = document.getElementById('toggle-rep');
    const toggleStatic = document.getElementById('toggle-static');
    const toggleDynamic = document.getElementById('toggle-dynamic');

    // Stats Elements
    const statTotal = document.getElementById('stat-total');
    const statAvg = document.getElementById('stat-avg');
    const statHigh = document.getElementById('stat-high');
    const statSafe = document.getElementById('stat-safe');
    
    let currentHistory = [];
    let pollingInterval = null;

    // Initialize
    checkStatus();
    loadHistory();
    loadStats();

    // Event Listeners
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pkgName = pkgInput.value.trim();
        const eco = ecoSelect.value;
        const skipRep = !toggleRep.checked;
        const skipStatic = !toggleStatic.checked;
        const skipDynamic = !toggleDynamic.checked;

        if (!pkgName) return;

        setLoading(true);

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    package: pkgName,
                    ecosystem: eco,
                    skip_reputation: skipRep,
                    skip_static: skipStatic,
                    skip_dynamic: skipDynamic
                })
            });
            const data = await res.json();

            if (res.ok) {
                pkgInput.value = '';
                loadHistory(); // load immediate placeholder
                startPolling(data.scan_id);
            } else {
                alert('Error: ' + data.error);
                setLoading(false);
            }
        } catch (err) {
            console.error(err);
            alert('Failed to trigger scan.');
            setLoading(false);
        }
    });

    refreshBtn.addEventListener('click', () => {
        loadHistory();
        loadStats();
    });

    historySearch.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        renderHistoryList(currentHistory.filter(item => item.package_name.toLowerCase().includes(query)));
    });

    // Core Functions
    async function checkStatus() {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            const ind = document.getElementById('docker-status');
            const txt = document.getElementById('docker-text');
            if (data.docker_available) {
                ind.classList.add('online');
                txt.textContent = 'Docker Sandbox Active';
            } else {
                ind.classList.add('offline');
                txt.textContent = 'Sandbox Offline';
                console.warn('Docker not available. Dynamic analysis will fail or be skipped.');
            }
        } catch (e) {
            console.error('Failed to check status', e);
        }
    }

    async function loadStats() {
        try {
            const res = await fetch('/api/stats');
            const data = await res.json();
            animateValue(statTotal, data.total_scans);
            animateValue(statAvg, data.avg_score);
            animateValue(statHigh, data.high_risk_count);
            animateValue(statSafe, data.safe_count);
        } catch (e) {
            console.error('Failed to load stats', e);
        }
    }

    async function loadHistory() {
        try {
            const res = await fetch('/api/history');
            const data = await res.json();
            currentHistory = data;
            renderHistoryList(data);
        } catch (err) {
            console.error('Failed to load history', err);
        }
    }

    function renderHistoryList(items) {
        historyList.innerHTML = '';
        if (items.length === 0) {
            historyList.innerHTML = `
                <div class="list-placeholder">
                    <i class="fa-solid fa-layer-group"></i>
                    <p>No scans found.</p>
                </div>`;
            return;
        }

        items.forEach(item => {
            const el = document.createElement('div');
            el.className = 'history-item';
            el.dataset.id = item.id;
            
            let statusClass = 'score-low';
            if (item.score === -1) {
                statusClass = '';
            } else if (item.score >= 70 || item.risk_level === 'Failed') {
                statusClass = 'score-high';
            } else if (item.score >= 15) {
                statusClass = 'score-medium';
            }

            const scoreText = item.score === -1 ? '<i class="fa-solid fa-circle-notch fa-spin"></i>' : `${item.score}/100`;

            el.innerHTML = `
                <div class="hi-main">
                    <span class="hi-name">${item.package_name} <span style="font-size:0.7rem; color:#888;">${item.ecosystem}</span></span>
                    <span class="hi-time">${timeAgo(new Date(item.scanned_at))}</span>
                </div>
                <div class="hi-score ${statusClass}">${scoreText}</div>
            `;
            
            el.addEventListener('click', () => {
                document.querySelectorAll('.history-item').forEach(i => i.classList.remove('active'));
                el.classList.add('active');
                loadReport(item.id);
            });

            historyList.appendChild(el);
        });
    }

    async function loadReport(scanId) {
        detailCard.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-circle-notch fa-spin" style="font-size: 3rem; color: var(--accent-cyan);"></i>
                <h3 style="margin-top:1rem;">Fetching Analysis...</h3>
            </div>
        `;

        try {
            const res = await fetch(`/api/scan/${scanId}`);
            const data = await res.json();
            if (res.ok) {
                renderReport(data);
            } else {
                detailCard.innerHTML = `<div class="empty-state text-danger"><i class="fa-solid fa-triangle-exclamation" style="font-size:3rem;"></i><h3>Error</h3><p>${data.error}</p></div>`;
            }
        } catch (e) {
            console.error(e);
            detailCard.innerHTML = `<div class="empty-state text-danger"><i class="fa-solid fa-triangle-exclamation" style="font-size:3rem;"></i><h3>Connection Error</h3></div>`;
        }
    }

    function renderReport(data) {
        if (data.score === -1) {
            // Still scanning
            detailCard.innerHTML = `
                <div class="empty-state">
                    <div class="logo-wrap" style="width:80px;height:80px;margin: 0 auto 1.5rem auto;">
                        <i class="fa-solid fa-microscope" style="font-size:2.5rem;color:var(--accent-cyan);z-index:2;"></i>
                        <div class="logo-ring"></div>
                    </div>
                    <h3>Analysis in Progress...</h3>
                    <p>The sandbox is currently analyzing ${data.package_name}. This usually takes 30-90 seconds.</p>
                </div>
            `;
            return;
        }

        // Render template
        const clone = reportTemplate.content.cloneNode(true);
        detailCard.innerHTML = '';
        detailCard.appendChild(clone);
        detailCard.classList.remove('empty-state');

        // Verdict Banner
        const verdictBanner = document.getElementById('verdict-banner');
        const verdictIcon = document.getElementById('verdict-icon');
        const verdictText = document.getElementById('verdict-text');
        
        if (data.score >= 70) {
            verdictBanner.className = 'verdict-banner malware';
            verdictIcon.className = 'fa-solid fa-skull-crossbones';
            verdictText.textContent = 'MALWARE DETECTED';
        } else if (data.score >= 15) {
            verdictBanner.className = 'verdict-banner';
            verdictBanner.style.background = 'rgba(255,184,0,0.1)';
            verdictBanner.style.borderColor = 'rgba(255,184,0,0.4)';
            verdictBanner.style.color = 'var(--warning)';
            verdictIcon.className = 'fa-solid fa-triangle-exclamation';
            verdictText.textContent = 'SUSPICIOUS (REVIEW REQUIRED)';
        } else {
            verdictBanner.className = 'verdict-banner legit';
            verdictIcon.className = 'fa-solid fa-circle-check';
            verdictText.textContent = 'LEGITIMATE';
        }

        // Header Population
        document.getElementById('eco-badge').textContent = data.ecosystem;
        document.getElementById('report-pkg-name').textContent = data.package_name;
        document.getElementById('report-version').textContent = data.version || 'Unknown';
        document.getElementById('report-time').textContent = timeAgo(new Date(data.scanned_at));

        // SVG Gauge
        const scoreVal = document.getElementById('report-score-number');
        const scoreLbl = document.getElementById('report-score-level');
        const scoreCard = document.getElementById('report-score-card');
        const arc = document.getElementById('gauge-arc');
        
        let sClass = 'gauge-low';
        if (data.score >= 70) sClass = 'gauge-high';
        else if (data.score >= 15) sClass = 'gauge-medium';
        scoreCard.classList.add(sClass);
        
        scoreLbl.textContent = data.risk_level.toUpperCase();
        
        // Animate gauge arc length. Max dasharray is 326.72
        // offset = total - (total * score / 100)
        setTimeout(() => {
            const offset = 326.72 - (326.72 * (data.score / 100));
            arc.style.strokeDashoffset = offset;
            animateValue(scoreVal, data.score);
        }, 100);

        // Score Breakdown
        let repScore = 0, statScore = 0, dynScore = 0;
        if (data.reasons) {
            // Reconstruct breakdown points if possible, or just default roughly
            const rsStr = data.reasons.join(" ");
            if(rsStr.includes("Typosquatting")) repScore += 70;
            if(rsStr.includes("Suspicious metadata")) repScore += 10;
            if(rsStr.includes("Known malicious")) repScore += 50;
            
            if(rsStr.includes("Obfuscated")) statScore += 25;
            if(rsStr.includes("Dangerous AST")) statScore += 20;
            
            if(rsStr.includes("Suspicious runtime")) dynScore += 70;
        }

        // Apply visual widths
        const totalMax = 185; // 75+45+70 (if we assume new dynamic max of 70)
        document.getElementById('bar-rep').style.width = Math.min((repScore/totalMax)*100, 40) + '%';
        document.getElementById('bar-stat').style.width = Math.min((statScore/totalMax)*100, 30) + '%';
        document.getElementById('bar-dyn').style.width = Math.min((dynScore/totalMax)*100, 30) + '%';
        
        animateValue(document.getElementById('val-rep'), Math.min(repScore, 75));
        animateValue(document.getElementById('val-stat'), Math.min(statScore, 45));
        animateValue(document.getElementById('val-dyn'), Math.min(dynScore, 70));

        // Metadata
        const rep = data.reputation_data || {};
        document.getElementById('meta-author').textContent = rep.author || 'Unknown';
        document.getElementById('meta-email').textContent = rep.author_email || 'Unknown';
        document.getElementById('meta-created').textContent = rep.created_at ? rep.created_at.split('T')[0] : 'Unknown';
        document.getElementById('meta-releases').textContent = rep.releases_count || 0;

        // Reasons List
        const rList = document.getElementById('report-reasons-list');
        (data.reasons || []).forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            rList.appendChild(li);
        });

        // Tabs Logic
        setupTabs();

        // Populate Vulns
        const vulns = rep.vulnerabilities || [];
        document.getElementById('count-vulns').textContent = vulns.length;
        if (vulns.length > 0) {
            document.getElementById('empty-vulns-msg').style.display = 'none';
            const vList = document.getElementById('vuln-items-list');
            vulns.forEach(v => {
                const el = document.createElement('div');
                el.className = 'vuln-item';
                el.innerHTML = `
                    <div class="item-header">
                        <span class="item-title">${v.id}</span>
                        <a href="https://osv.dev/vulnerability/${v.id}" target="_blank" style="color:var(--accent-cyan);font-size:0.8rem;text-decoration:none;"><i class="fa-solid fa-arrow-up-right-from-square"></i></a>
                    </div>
                    <div class="item-desc">${v.summary || 'Vulnerability found in this version.'}</div>
                `;
                vList.appendChild(el);
            });
        }

        // Populate Static
        const stat = data.static_data || {};
        const alerts = stat.alerts || [];
        document.getElementById('count-static').textContent = alerts.length;
        if (alerts.length > 0) {
            document.getElementById('empty-static-msg').style.display = 'none';
            const sList = document.getElementById('static-alerts-items');
            alerts.forEach(a => {
                const el = document.createElement('div');
                el.className = `alert-item ${a.severity}`;
                el.innerHTML = `
                    <div class="item-header">
                        <span class="item-title">${a.rule}</span>
                        <span class="item-badge ${a.severity}">${a.severity}</span>
                    </div>
                    <div class="item-desc">${a.description}</div>
                    ${a.snippet ? `<div class="item-code">${a.snippet.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>` : ''}
                `;
                sList.appendChild(el);
            });
        }

        // Populate Dynamic
        const dyn = data.dynamic_data || {};
        const events = dyn.events || [];
        document.getElementById('count-dynamic').textContent = events.length;
        if (events.length > 0) {
            document.getElementById('empty-dynamic-msg').style.display = 'none';
            const dList = document.getElementById('dynamic-events-items');
            events.forEach(ev => {
                const el = document.createElement('div');
                el.className = `event-item`;
                el.innerHTML = `
                    <div class="item-header">
                        <span class="item-title">${ev.type}</span>
                    </div>
                    <div class="item-code">${ev.details.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>
                `;
                dList.appendChild(el);
            });
        }

        // Terminal Output
        const term = document.getElementById('sandbox-term-body');
        if (dyn.installation_log) {
            document.getElementById('empty-dynamic-msg').style.display = 'none';
            // Format log slightly
            let formattedLog = dyn.installation_log
                .replace(/</g, "&lt;").replace(/>/g, "&gt;")
                .replace(/warning/gi, '<span class="warn">Warning</span>')
                .replace(/error|failed|exception/gi, '<span class="err">$&</span>')
                .replace(/success|successfully/gi, '<span class="ok">$&</span>');
            term.innerHTML = formattedLog;
        }

        // Exports
        document.getElementById('export-pdf-link').href = `/api/scan/${data.id}/export/pdf`;
        document.getElementById('export-html-link').href = `/api/scan/${data.id}/export/html`;
        document.getElementById('export-md-link').href = `/api/scan/${data.id}/export/md`;
    }

    function setupTabs() {
        const btns = document.querySelectorAll('.tab-btn');
        const panels = document.querySelectorAll('.tab-panel');
        btns.forEach(btn => {
            btn.addEventListener('click', () => {
                btns.forEach(b => b.classList.remove('active'));
                panels.forEach(p => p.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(`panel-${btn.dataset.tab}`).classList.add('active');
            });
        });
    }

    function startPolling(scanId) {
        if (pollingInterval) clearInterval(pollingInterval);
        
        // Open empty state immediately
        document.querySelectorAll('.history-item').forEach(i => i.classList.remove('active'));
        loadReport(scanId);

        pollingInterval = setInterval(async () => {
            try {
                const res = await fetch(`/api/scan/${scanId}`);
                const data = await res.json();
                if (data.score !== -1) {
                    clearInterval(pollingInterval);
                    setLoading(false);
                    loadHistory();
                    loadStats();
                    loadReport(scanId);
                }
            } catch (e) {
                console.error('Polling error', e);
            }
        }, 2000);
    }

    function setLoading(isLoading) {
        if (isLoading) {
            scanForm.classList.add('scanning');
            scanBtn.disabled = true;
            pkgInput.disabled = true;
        } else {
            scanForm.classList.remove('scanning');
            scanBtn.disabled = false;
            pkgInput.disabled = false;
        }
    }

    function timeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        let interval = seconds / 31536000;
        if (interval > 1) return Math.floor(interval) + " yrs ago";
        interval = seconds / 2592000;
        if (interval > 1) return Math.floor(interval) + " mos ago";
        interval = seconds / 86400;
        if (interval > 1) return Math.floor(interval) + " d ago";
        interval = seconds / 3600;
        if (interval > 1) return Math.floor(interval) + " hrs ago";
        interval = seconds / 60;
        if (interval > 1) return Math.floor(interval) + " mins ago";
        if (seconds < 10) return "just now";
        return Math.floor(seconds) + " s ago";
    }

    function animateValue(obj, end, duration = 1000) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * end);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }
});
