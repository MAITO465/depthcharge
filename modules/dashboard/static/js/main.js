/* ═══════════════════════════════════════════════════════════════
   DEPTHCHARGE — SPA Frontend
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

    /* ── State ─────────────────────────────────────────────────── */
    const state = {
        view: 'overview',
        history: [],
        pollingInterval: null,
        charts: { donut: null, line: null },
        findingsCache: [],
        inventoryCache: []
    };

    /* ── DOM refs ──────────────────────────────────────────────── */
    const $ = id => document.getElementById(id);
    const $$ = sel => document.querySelectorAll(sel);

    /* ════════════════════════════════════════════════════════════
       NAVIGATION
    ════════════════════════════════════════════════════════════ */
    function navigate(view) {
        state.view = view;
        $$('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
        $$('.view').forEach(el => el.classList.toggle('active', el.id === `view-${view}`));
        if (view === 'overview')  loadOverview();
        if (view === 'findings')  loadFindings();
        if (view === 'inventory') loadInventory();
    }

    $$('.nav-item').forEach(el => {
        el.addEventListener('click', e => { e.preventDefault(); navigate(el.dataset.view); });
    });

    // Expose for HTML onclick buttons
    window.navigate = navigate;

    /* ════════════════════════════════════════════════════════════
       STATUS CHECK
    ════════════════════════════════════════════════════════════ */
    async function checkStatus() {
        try {
            const d = await apiFetch('/api/status');
            const dot = $('docker-dot');
            const lbl = $('docker-label');
            if (d.docker_available) {
                dot.className = 'docker-dot online';
                lbl.textContent = 'Docker Sandbox Active';
            } else {
                dot.className = 'docker-dot offline';
                lbl.textContent = 'Docker Offline';
            }
        } catch {}
    }

    /* ════════════════════════════════════════════════════════════
       OVERVIEW
    ════════════════════════════════════════════════════════════ */
    async function loadOverview() {
        try {
            const [stats, history] = await Promise.all([
                apiFetch('/api/stats'),
                apiFetch('/api/history')
            ]);

            // KPIs
            animateValue($('kpi-total'), stats.total_scans);
            animateValue($('kpi-high'),  stats.high_risk_count);
            animateValue($('kpi-avg'),   Math.round(stats.avg_score));
            animateValue($('kpi-safe'),  stats.safe_count);

            // Donut
            const medium = stats.total_scans - stats.high_risk_count - stats.safe_count;
            const total  = stats.total_scans || 1;
            renderDonut(stats.high_risk_count, Math.max(medium, 0), stats.safe_count);
            $('donut-center-text').querySelector('.donut-big').textContent = stats.total_scans;

            // Line chart
            const last20 = history.filter(h => h.score >= 0).slice(0, 20).reverse();
            renderLineChart(last20);

            // Recent threats
            const threats = history.filter(h => h.score >= 70).slice(0, 6);
            renderRecentThreats(threats);

        } catch (e) { console.error('loadOverview error', e); }
    }

    function renderDonut(high, medium, low) {
        const ctx = $('chart-donut').getContext('2d');
        if (state.charts.donut) state.charts.donut.destroy();
        const noData = (high + medium + low) === 0;
        state.charts.donut = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['High', 'Medium', 'Low'],
                datasets: [{
                    data: noData ? [1, 0, 0] : [high, medium, low],
                    backgroundColor: noData
                        ? ['rgba(0,200,255,0.06)']
                        : ['#ff2d6b', '#ff8c00', '#00ff88'],
                    borderColor: noData
                        ? ['rgba(0,200,255,0.12)']
                        : ['rgba(255,45,107,0.6)', 'rgba(255,140,0,0.6)', 'rgba(0,255,136,0.6)'],
                    borderWidth: 1,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                cutout: '72%',
                plugins: { legend: { display: false }, tooltip: { callbacks: {
                    label: ctx => ` ${ctx.label}: ${noData ? 0 : ctx.parsed}`
                }}}
            }
        });
    }

    function renderLineChart(items) {
        const ctx = $('chart-line').getContext('2d');
        if (state.charts.line) state.charts.line.destroy();
        const labels = items.map(i => i.package_name.slice(0, 12));
        const scores = items.map(i => i.score);
        state.charts.line = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Risk Score',
                    data: scores,
                    borderColor: '#00c8ff',
                    backgroundColor: 'rgba(0,200,255,0.05)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: scores.map(s =>
                        s >= 70 ? '#ff2d6b' : s >= 15 ? '#ff8c00' : '#00ff88'),
                    pointBorderColor: 'rgba(0,200,255,0.3)',
                    pointBorderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        min: 0, max: 100,
                        grid: { color: 'rgba(0,200,255,0.05)' },
                        ticks: { color: '#5a7a9a', font: { size: 10 } }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#5a7a9a', font: { size: 10 }, maxRotation: 45 }
                    }
                },
                plugins: { legend: { display: false }, tooltip: {
                    backgroundColor: 'rgba(3,7,17,0.95)',
                    borderColor: 'rgba(0,200,255,0.3)',
                    borderWidth: 1,
                    titleColor: '#00c8ff',
                    bodyColor: '#5a7a9a',
                    padding: 10
                }}
            }
        });
    }

    function renderRecentThreats(threats) {
        const el = $('recent-threats-list');
        if (!threats.length) {
            el.innerHTML = '<div class="empty-msg"><i class="fa-solid fa-shield-halved"></i><p>No high-risk packages detected yet.</p></div>';
            return;
        }
        el.innerHTML = `
            <table class="threats-table">
                <thead><tr>
                    <th>Package</th><th>Ecosystem</th><th>Version</th>
                    <th>Score</th><th>Scanned</th><th></th>
                </tr></thead>
                <tbody>
                ${threats.map(t => `
                    <tr>
                        <td style="font-weight:600;color:var(--text)">${escHtml(t.package_name)}</td>
                        <td><span style="font-size:0.7rem;color:var(--text-muted);text-transform:uppercase;">${escHtml(t.ecosystem)}</span></td>
                        <td class="mono" style="font-size:0.78rem;color:var(--text-muted)">${escHtml(t.version||'?')}</td>
                        <td><span class="score-pill high">${t.score}/100</span></td>
                        <td style="font-size:0.75rem;color:var(--text-muted)">${timeAgo(new Date(t.scanned_at))}</td>
                        <td><button class="btn-link" onclick="navigate('scanner');setTimeout(()=>loadReport(${t.id}),100)">View →</button></td>
                    </tr>`).join('')}
                </tbody>
            </table>`;
    }

    /* ════════════════════════════════════════════════════════════
       SCANNER VIEW
    ════════════════════════════════════════════════════════════ */

    // Scan form
    $('scan-form').addEventListener('submit', async e => {
        e.preventDefault();
        const pkg  = $('package-input').value.trim();
        const eco  = $('ecosystem-select').value;
        if (!pkg) return;
        setScanLoading(true);
        try {
            const data = await apiFetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    package: pkg, ecosystem: eco,
                    skip_reputation: !$('toggle-rep').checked,
                    skip_static:     !$('toggle-static').checked,
                    skip_dynamic:    !$('toggle-dynamic').checked
                })
            });
            const pkgName = pkg;
            $('package-input').value = '';
            loadHistory();
            startSSE(data.scan_id, pkgName);
        } catch (err) {
            setScanLoading(false);
            showError('Failed to start scan: ' + err.message);
        }
    });

    // Bulk scan
    $('bulk-scan-btn').addEventListener('click', async () => {
        const content = $('bulk-input').value.trim();
        const eco     = $('bulk-ecosystem').value;
        if (!content) return;
        $('bulk-scan-btn').disabled = true;
        try {
            const data = await apiFetch('/api/scan/bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, ecosystem: eco })
            });
            $('bulk-result').style.display = 'block';
            $('bulk-result').textContent = `✓ Started ${data.total} scan${data.total !== 1 ? 's' : ''}. Check History for results.`;
            loadHistory();
        } catch (err) {
            showError('Bulk scan failed: ' + err.message);
        } finally {
            $('bulk-scan-btn').disabled = false;
        }
    });

    // Scan tabs
    $$('.scan-tab').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.scan-tab').forEach(b => b.classList.remove('active'));
            $$('.scan-tab-panel').forEach(p => { p.classList.remove('active'); p.style.display = 'none'; });
            btn.classList.add('active');
            const panel = $('panel-' + btn.dataset.scanTab);
            if (panel) { panel.classList.add('active'); panel.style.display = 'block'; }
        });
    });

    // History search & refresh
    $('history-search').addEventListener('input', e => {
        const q = e.target.value.toLowerCase();
        renderHistoryList(state.history.filter(i => i.package_name.toLowerCase().includes(q)));
    });
    $('refresh-btn').addEventListener('click', () => { loadHistory(); loadStats(); });

    async function loadHistory() {
        try {
            const data = await apiFetch('/api/history');
            state.history = data;
            renderHistoryList(data);
        } catch {}
    }

    async function loadStats() {
        try {
            const d = await apiFetch('/api/stats');
            animateValue($('kpi-total'), d.total_scans);
            animateValue($('kpi-high'),  d.high_risk_count);
            animateValue($('kpi-avg'),   Math.round(d.avg_score));
            animateValue($('kpi-safe'),  d.safe_count);
        } catch {}
    }

    function renderHistoryList(items) {
        const el = $('history-items');
        if (!items.length) {
            el.innerHTML = '<div class="empty-msg small"><i class="fa-solid fa-inbox"></i><p>No scans yet</p></div>';
            return;
        }
        el.innerHTML = '';
        items.forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';
            div.dataset.id = item.id;

            let cls = 'score-low';
            if (item.score === -1 || item.score === null)  cls = '';
            else if (item.risk_level === 'Failed')         cls = 'score-medium';
            else if (item.score >= 70)                     cls = 'score-high';
            else if (item.score >= 15)                     cls = 'score-medium';

            const scoreHtml = (item.score === -1 || item.score === null)
                ? '<i class="fa-solid fa-circle-notch spinning"></i>'
                : item.risk_level === 'Failed'
                    ? '<i class="fa-solid fa-xmark"></i> Failed'
                    : `${item.score}/100`;

            div.innerHTML = `
                <div class="hi-info">
                    <div class="hi-name">${escHtml(item.package_name)}</div>
                    <div class="hi-time">${escHtml(item.ecosystem)} · ${timeAgo(new Date(item.scanned_at))}</div>
                </div>
                <div class="hi-score ${cls}">${scoreHtml}</div>
            `;

            div.addEventListener('click', () => {
                $$('.history-item').forEach(i => i.classList.remove('active'));
                div.classList.add('active');
                loadReport(item.id);
                if (state.view !== 'scanner') navigate('scanner');
            });

            el.appendChild(div);
        });
    }

    // Expose loadReport for overview quick links
    window.loadReport = loadReport;

    async function loadReport(scanId) {
        const dc = $('detail-card');
        dc.className = 'card report-card';
        dc.innerHTML = `<div class="empty-state"><div class="empty-icon-ring"><i class="fa-solid fa-circle-notch spinning"></i></div><h3>Fetching analysis…</h3></div>`;
        try {
            const data = await apiFetch(`/api/scan/${scanId}`);
            if (data.score === -1) {
                dc.innerHTML = `<div class="empty-state"><div class="empty-icon-ring"><i class="fa-solid fa-microscope"></i></div><h3>Analysis in Progress…</h3><p>Scanning ${escHtml(data.package_name)}. Usually 30–90 seconds.</p></div>`;
            } else {
                renderReport(data);
            }
        } catch (e) {
            dc.innerHTML = `<div class="empty-state"><i class="fa-solid fa-triangle-exclamation" style="font-size:2rem;color:var(--red);"></i><h3>Load Error</h3></div>`;
        }
    }

    function renderReport(data) {
        const dc = $('detail-card');
        dc.className = 'card report-card';

        // Clone template
        const clone = document.getElementById('report-template').content.cloneNode(true);
        dc.innerHTML = '';
        dc.appendChild(clone);

        /* ── Verdict ── */
        const vb = $('verdict-banner');
        const vi = $('verdict-icon');
        const vt = $('verdict-text');
        if (data.risk_level === 'Failed') {
            vb.className = 'verdict-banner warning';
            vi.className = 'fa-solid fa-circle-exclamation';
            vt.textContent = 'SCAN FAILED';
        } else if (data.score >= 70) {
            vb.className = 'verdict-banner malware';
            vi.className = 'fa-solid fa-skull-crossbones';
            vt.textContent = 'MALWARE DETECTED';
        } else if (data.score >= 15) {
            vb.className = 'verdict-banner warning';
            vi.className = 'fa-solid fa-triangle-exclamation';
            vt.textContent = 'SUSPICIOUS — REVIEW REQUIRED';
        } else {
            vb.className = 'verdict-banner legit';
            vi.className = 'fa-solid fa-circle-check';
            vt.textContent = 'LEGITIMATE';
        }

        /* ── Exports ── */
        $('export-pdf-link').href  = `/api/scan/${data.id}/export/pdf`;
        $('export-html-link').href = `/api/scan/${data.id}/export/html`;
        $('export-md-link').href   = `/api/scan/${data.id}/export/md`;

        /* ── Package identity ── */
        $('eco-badge').textContent       = data.ecosystem.toUpperCase();
        $('report-pkg-name').textContent = data.package_name;
        $('report-version').textContent  = data.version ? `v${data.version}` : '';
        $('report-time').textContent     = timeAgo(new Date(data.scanned_at));

        /* ── Gauge ── */
        const wrap = $('report-score-card');
        const arc  = $('gauge-arc');
        const val  = $('report-score-number');
        const lbl  = $('report-score-level');

        const isFailed = data.risk_level === 'Failed';
        wrap.className = 'gauge-wrap ' + (isFailed || data.score >= 70 ? 'gauge-high' : data.score >= 15 ? 'gauge-med' : 'gauge-low');
        lbl.textContent = (data.risk_level || 'LOW').toUpperCase();

        // Animate
        setTimeout(() => {
            const circ   = 2 * Math.PI * 50; // 314.16
            const score  = isFailed ? 0 : (data.score || 0);
            const offset = circ - (circ * (score / 100));
            arc.style.strokeDashoffset = isFailed ? circ : offset;
            val.textContent = isFailed ? '—' : '0';
            if (!isFailed) animateValue(val, score);
        }, 80);

        /* ── Breakdown bar (reconstruct from reasons text) ── */
        const reasons = data.reasons || [];
        const rsStr   = reasons.join(' ');
        let repS = 0, statS = 0, dynS = 0;
        if (rsStr.includes('Typosquatting'))       repS += 70;
        if (rsStr.includes('suspiciously new'))    repS += 15;
        if (rsStr.includes('Known malicious'))     repS += 50;
        if (rsStr.includes('Obfusc') || rsStr.includes('obfusc')) statS += 25;
        if (rsStr.includes('Dangerous AST'))        statS += 20;
        if (rsStr.includes('taint'))                statS += 10;
        if (rsStr.includes('IoC'))                  statS += 15;
        if (rsStr.includes('Suspicious runtime'))   dynS  += 70;
        const tot = Math.max(repS + statS + dynS, 1);
        const pct = v => Math.round((v / tot) * 100);
        setTimeout(() => {
            $('bar-rep').style.width  = pct(repS)  + '%';
            $('bar-stat').style.width = pct(statS) + '%';
            $('bar-dyn').style.width  = pct(dynS)  + '%';
            animateValue($('val-rep'),  repS);
            animateValue($('val-stat'), statS);
            animateValue($('val-dyn'),  dynS);
        }, 100);

        /* ── Metadata ── */
        const rep = data.reputation_data || {};
        $('meta-author').textContent   = rep.author        || '—';
        $('meta-email').textContent    = rep.author_email  || '—';
        $('meta-created').textContent  = rep.created_at ? rep.created_at.split('T')[0] : '—';
        $('meta-releases').textContent = rep.releases_count != null ? rep.releases_count : '—';
        $('meta-vulns').textContent    = (rep.vulnerabilities || []).length;
        // Use != null so that 0 renders as "0" not "—"
        const filesScanned = (data.static_data || {}).files_scanned;
        $('meta-files').textContent    = filesScanned != null ? filesScanned : '—';

        // Maintainer change warning
        if (rep.maintainer_changed) {
            const warn = document.createElement('div');
            warn.style.cssText = `margin-bottom:1rem;padding:0.65rem 1rem;background:var(--yellow-dim);border:1px solid rgba(202,138,4,0.2);border-radius:8px;font-size:0.8rem;color:var(--yellow);display:flex;gap:0.5rem;align-items:center;`;
            warn.innerHTML = `<i class="fa-solid fa-user-gear"></i> <strong>Maintainer change detected</strong> — previous: ${escHtml(rep.previous_maintainer_email || 'unknown')}`;
            const metaGrid = document.querySelector('#detail-card .meta-grid') || document.getElementById('meta-grid');
            if (metaGrid) metaGrid.insertAdjacentElement('afterend', warn);
        }

        /* ── Reasons ── */
        const rList = $('report-reasons-list');
        reasons.forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            rList.appendChild(li);
        });

        /* ── Tab logic ── */
        setupReportTabs();

        /* Detect typosquatting / non-existent package (no source available) */
        const isTyposquat = !!(rep.typosquatting_detected) || !!(data.static_data || {}).typosquatting;
        const typoInfo = rep.typosquatting_info || (data.static_data || {}).typosquatting || {};
        const typoSimilarTo = typoInfo.target || 'a known package';

        /* ── Vulnerabilities ── */
        const vulns = rep.vulnerabilities || [];
        $('count-vulns').textContent = vulns.length;
        if (!vulns.length) {
            const ep = $('empty-vulns').querySelector('p');
            const ei = $('empty-vulns').querySelector('i');
            if (isTyposquat) {
                if (ep) ep.textContent = 'Package does not exist on PyPI — CVE lookups require a valid package version.';
                if (ei) { ei.className = 'fa-solid fa-triangle-exclamation'; ei.style.color = 'var(--yellow)'; }
            } else if (isFailed) {
                if (ep) ep.textContent = 'Scan failed — vulnerability lookup was not completed.';
                if (ei) { ei.className = 'fa-solid fa-circle-exclamation'; ei.style.color = 'var(--text-muted)'; }
            }
        }
        if (vulns.length) {
            $('empty-vulns').style.display = 'none';
            const vl = $('vulns-list');
            vulns.forEach(v => {
                const el = document.createElement('div');
                el.className = 'finding-card';
                el.style.borderLeftColor = 'var(--red)';
                el.innerHTML = `
                    <div class="fc-header">
                        <div class="fc-icon ioc"><i class="fa-solid fa-circle-exclamation"></i></div>
                        <span class="fc-title">${escHtml(v.id)}</span>
                        <div class="fc-badges">
                            <a href="https://osv.dev/vulnerability/${escHtml(v.id)}" target="_blank"
                               style="color:var(--cyan);font-size:0.75rem;text-decoration:none;">
                                <i class="fa-solid fa-arrow-up-right-from-square"></i>
                            </a>
                        </div>
                    </div>
                    <div class="fc-body open">
                        <div class="fc-message">${escHtml(v.summary || 'Vulnerability found in this version.')}</div>
                    </div>`;
                vl.appendChild(el);
            });
        }

        /* ── Static alerts ── */
        const staticData = data.static_data || {};
        const alerts = staticData.alerts || [];
        $('count-static').textContent = alerts.length;

        if (isTyposquat) {
            // Package doesn't exist — no source scan ran, but we have a typosquatting finding to show
            $('empty-static').style.display = 'none';
            if (alerts.length) {
                const sl = $('static-alerts-list');
                alerts.forEach(a => sl.appendChild(makeFindingCard(a)));
            }
        } else if (isFailed) {
            $('empty-static').style.display = 'none';
            $('static-alerts-list').insertAdjacentHTML('beforebegin', `
                <div class="typosquat-notice">
                    <i class="fa-solid fa-circle-exclamation"></i>
                    <div>
                        <strong>Static analysis was not performed</strong>
                        <p>The scan failed during the reputation phase before any source code could be downloaded or analyzed.
                        See the Risk Analysis Factors above for the specific failure reason.</p>
                    </div>
                </div>`);
        } else {
            // Always show a scan summary, even when clean
            const staticSummary = buildStaticSummary(staticData, data.package_name);
            $('static-alerts-list').insertAdjacentHTML('beforebegin', staticSummary);

            if (alerts.length) {
                $('empty-static').style.display = 'none';
                const sl = $('static-alerts-list');
                alerts.forEach(a => sl.appendChild(makeFindingCard(a)));
            } else {
                $('empty-static').querySelector('p').textContent =
                    filesScanned > 0
                        ? `${filesScanned} file${filesScanned !== 1 ? 's' : ''} scanned — no threats or suspicious patterns found.`
                        : 'No suspicious static patterns found.';
            }
        }

        /* ── Dynamic events ── */
        const dyn    = data.dynamic_data || {};
        const events = dyn.events || [];
        $('count-dynamic').textContent = events.length;

        // Dynamic empty state — explain what happened
        if (!events.length) {
            if (isTyposquat) {
                // Hide misleading green-check; inject a proper notice
                $('empty-dynamic').style.display = 'none';
                $('dynamic-events-list').insertAdjacentHTML('beforebegin', `
                    <div class="typosquat-notice">
                        <i class="fa-solid fa-triangle-exclamation"></i>
                        <div>
                            <strong>Dynamic analysis was not performed</strong>
                            <p><code>${escHtml(data.package_name)}</code> does not exist on PyPI — there is nothing to install in the sandbox.
                            Dynamic analysis requires a real, installable package.
                            This package was flagged purely by name-based typosquatting detection (matches <strong>${escHtml(typoSimilarTo)}</strong>).</p>
                        </div>
                    </div>`);
            } else if (isFailed) {
                $('empty-dynamic').style.display = 'none';
                $('dynamic-events-list').insertAdjacentHTML('beforebegin', `
                    <div class="typosquat-notice">
                        <i class="fa-solid fa-circle-exclamation"></i>
                        <div>
                            <strong>Dynamic analysis was not performed</strong>
                            <p>The scan failed before reaching the sandbox phase.
                            See the Risk Analysis Factors above for the specific failure reason.</p>
                        </div>
                    </div>`);
            } else {
                let dynMsg;
                if (dyn.docker_available === false)
                    dynMsg = 'Docker sandbox was unavailable — dynamic analysis was skipped. Install Docker and re-scan to enable it.';
                else if (dyn.error)
                    dynMsg = `Sandbox note: ${dyn.error}`;
                else
                    dynMsg = 'No suspicious sandbox activity detected.';
                $('empty-dynamic').querySelector('p').textContent = dynMsg;
            }
        }

        if (events.length) {
            $('empty-dynamic').style.display = 'none';
            const dl = $('dynamic-events-list');
            events.forEach(ev => {
                const el = document.createElement('div');
                el.className = 'finding-card';
                el.innerHTML = `
                    <div class="fc-header">
                        <div class="fc-icon dynamic"><i class="fa-solid fa-terminal"></i></div>
                        <span class="fc-title">${escHtml(ev.type)}</span>
                    </div>
                    <div class="fc-body open">
                        <div class="fc-message mono">${escHtml(ev.details)}</div>
                    </div>`;
                dl.appendChild(el);
            });
        }

        if (dyn.installation_log) {
            $('empty-dynamic').style.display = 'none';
            const tb = $('terminal-block');
            tb.style.display = 'block';
            const logEl = $('sandbox-log');
            logEl.innerHTML = escHtml(dyn.installation_log)
                .replace(/warning/gi, '<span class="warn">Warning</span>')
                .replace(/error|failed|exception/gi, '<span class="err">$&</span>')
                .replace(/success|successfully/gi, '<span class="ok">$&</span>');

            $('btn-copy-log').addEventListener('click', () => {
                navigator.clipboard.writeText(dyn.installation_log || '');
                $('btn-copy-log').innerHTML = '<i class="fa-solid fa-check"></i> Copied';
                setTimeout(() => $('btn-copy-log').innerHTML = '<i class="fa-regular fa-copy"></i> Copy', 1500);
            });
        }

        // Update findings count badge in nav
        updateFindingsNavCount();
    }

    /* ── Static scan summary (shown even for clean packages) ─── */
    function buildStaticSummary(staticData, pkgName) {
        const files   = staticData.files_scanned ?? 0;
        const alerts  = (staticData.alerts || []).length;
        const obf     = staticData.obfuscation_detected;
        const astDang = staticData.dangerous_ast_detected;
        const isWhitelisted = false; // determined by reasons in outer scope

        const checks = [
            { label: 'Files scanned',        value: files,                  ok: true },
            { label: 'Obfuscation detected',  value: obf  ? 'Yes' : 'No',  ok: !obf },
            { label: 'Dangerous AST patterns',value: astDang ? 'Yes' : 'No', ok: !astDang },
            { label: 'YARA / IoC alerts',     value: alerts + ' found',     ok: alerts === 0 },
        ];

        const rows = checks.map(c => `
            <div class="summary-check">
                <i class="fa-solid ${c.ok ? 'fa-circle-check' : 'fa-circle-exclamation'}"
                   style="color:${c.ok ? 'var(--green)' : 'var(--yellow)'};font-size:0.75rem;"></i>
                <span class="sc-label">${escHtml(c.label)}</span>
                <span class="sc-val ${c.ok ? '' : 'warn'}">${escHtml(String(c.value))}</span>
            </div>`).join('');

        return `<div class="scan-summary-block">${rows}</div>`;
    }

    /* ── Remediation hints per finding type ──────────────────── */
    const REMEDIATION = {
        typosquatting:
            'Verify the exact package name before installing. Run `pip index versions <package>` to confirm ' +
            'it exists on PyPI, and cross-check the official project URL. Never install packages with ' +
            'near-identical names to popular libraries — this is the primary vector for supply chain attacks. ' +
            'Use a dependency lock file (pip-compile / poetry.lock) to pin verified hashes.',
        taint_flow:
            'Review all data flows from environment variables into subprocess/exec calls. ' +
            'Never pass user-controlled or env-sourced data directly to shell commands. ' +
            'Use a strict allowlist if external input is required.',
        obfuscation:
            'Deobfuscate the code using tools like python-deobfuscator or manually trace ' +
            'the string reconstruction. If the obfuscated payload is a known malicious ' +
            'command, report to PyPI security (security@pypi.org).',
        chr_obfuscation:
            'chr()-based string reconstruction is a classic malware evasion technique. ' +
            'Reconstruct the string manually: e.g. chr(101)+chr(120)+chr(101)+chr(99) = "exec". ' +
            'Inspect what the resulting string does before running the package.',
        string_split_obfusc:
            'String concatenation to form dangerous function names (e.g. "sys"+"tem") is ' +
            'used to bypass naive string scanners. Concatenate the fragments and review ' +
            'what function or URL the full string resolves to.',
        ioc_match:
            'A hardcoded token or C2 URL was detected. Verify whether the flagged value ' +
            'is a legitimate API credential for an expected service. If it points to ' +
            'Telegram/Discord C2 infrastructure, do not install this package.',
        setup_hook_danger:
            'setup.py runs at install time with full OS access — before any sandbox can ' +
            'contain it. Audit the install hook carefully, or use --no-build-isolation to ' +
            'isolate it. Consider using pip install --dry-run first.',
        sensitive_data:
            'Environment variable access in an install hook can indicate credential ' +
            'harvesting. Audit which variables are read and where the data is sent. ' +
            'Check for outbound HTTP calls immediately after the env read.',
        dynamic_execution:
            'Dynamic code execution (eval/exec/Function()) outside of a test context is ' +
            'a high-risk pattern. Inspect what string is being evaluated and whether it ' +
            'can be influenced by attacker-controlled input.',
    };

    function makeFindingCard(a) {
        const typeIconMap = {
            typosquatting:   ['ioc',       'fa-user-secret',       'Typosquatting'],
            taint_flow:      ['taint',     'fa-code-branch',       'Taint Flow'],
            obfuscation:     ['obfusc',    'fa-eye-slash',         'Obfuscation'],
            chr_obfuscation: ['obfusc',    'fa-font',              'Chr() Obfuscation'],
            string_split_obfusc: ['obfusc','fa-scissors',         'String Split'],
            ioc_match:       ['ioc',       'fa-location-dot',      'IoC Match'],
            setup_hook_danger:['hook',     'fa-skull',             'Hook Danger'],
            sensitive_data:  ['sensitive', 'fa-lock',              'Sensitive Data'],
            dynamic_execution:['dynamic', 'fa-play',              'Dynamic Exec'],
        };
        const [iconCls, iconName, typeLabel] = typeIconMap[a.type] || ['default', 'fa-bug', a.type || 'finding'];

        const mitreTag  = a.mitre_id && a.mitre_id !== 'T0000'
            ? `<span class="badge mitre">${escHtml(a.mitre_id)}</span>` : '';
        const confTag   = a.confidence
            ? `<span class="badge conf">${escHtml(a.confidence)}</span>` : '';
        const sevTag    = `<span class="badge ${a.severity || 'medium'}">${(a.severity||'medium').toUpperCase()}</span>`;
        const location  = a.file ? `<div class="fc-location"><i class="fa-solid fa-file-code"></i> ${escHtml(a.file)}${a.line ? ':' + a.line : ''}</div>` : '';
        const compliance = Array.isArray(a.compliance) && a.compliance.length
            ? `<div class="fc-compliance">${a.compliance.map(c => `<span class="badge compliance">${escHtml(c)}</span>`).join('')}</div>` : '';

        const hint = REMEDIATION[a.type];
        const remediation = hint
            ? `<div class="fc-remediation">
                   <span class="fc-rem-label"><i class="fa-solid fa-screwdriver-wrench"></i> Remediation</span>
                   <p>${escHtml(hint)}</p>
               </div>` : '';

        const el = document.createElement('div');
        el.className = `finding-card ${a.severity || 'medium'}`;
        el.innerHTML = `
            <div class="fc-header" onclick="this.nextElementSibling.classList.toggle('open')">
                <div class="fc-icon ${iconCls}"><i class="fa-solid ${iconName}"></i></div>
                <span class="fc-title">${escHtml(typeLabel)}</span>
                <div class="fc-badges">${sevTag}${mitreTag}${confTag}</div>
                <i class="fa-solid fa-chevron-down" style="color:var(--text-muted);font-size:0.7rem;margin-left:auto;"></i>
            </div>
            <div class="fc-body">
                ${location}
                <div class="fc-message">${escHtml(a.message || '')}</div>
                ${compliance}
                ${remediation}
            </div>`;
        return el;
    }

    function setupReportTabs() {
        $$('.rtab').forEach(btn => {
            btn.addEventListener('click', () => {
                $$('.rtab').forEach(b => b.classList.remove('active'));
                $$('.rtab-panel').forEach(p => { p.classList.remove('active'); p.style.display = 'none'; });
                btn.classList.add('active');
                const panel = $('rpanel-' + btn.dataset.rtab);
                if (panel) { panel.classList.add('active'); panel.style.display = 'block'; }
            });
        });
    }

    /* ════════════════════════════════════════════════════════════
       LIVE PROGRESS — SSE
    ════════════════════════════════════════════════════════════ */

    const PHASE_ICONS = {
        running: '<i class="fa-solid fa-circle-notch spinning"></i>',
        done:    '<i class="fa-solid fa-check"></i>',
        warn:    '<i class="fa-solid fa-triangle-exclamation"></i>',
        error:   '<i class="fa-solid fa-xmark"></i>',
        skip:    '<i class="fa-solid fa-minus"></i>',
        pending: '<i class="fa-solid fa-circle"></i>',
    };

    function showProgressPanel(pkgName) {
        const pp = $('progress-panel');
        $('progress-pkg-label').textContent = `Analyzing: ${pkgName}`;
        // Reset all phases to pending
        pp.querySelectorAll('.phase-step').forEach(s => {
            s.dataset.state = 'pending';
            s.querySelector('.phase-icon').className = 'phase-icon pending';
            s.querySelector('.phase-icon').innerHTML = PHASE_ICONS.pending;
            s.querySelector('.phase-msg').textContent = 'Waiting…';
        });
        pp.style.display = 'block';
        $('detail-card').style.display = 'none';
    }

    function updateProgressPanel(evt) {
        const { phase, status, message } = evt;
        if (phase === 'complete') return;

        const step = document.querySelector(`#phase-list .phase-step[data-phase="${phase}"]`);
        if (!step) return;

        step.dataset.state = status;
        const iconEl = step.querySelector('.phase-icon');
        iconEl.className = `phase-icon ${status}`;
        iconEl.innerHTML = PHASE_ICONS[status] || PHASE_ICONS.pending;
        step.querySelector('.phase-msg').textContent = message;
    }

    function hideProgressPanel() {
        $('progress-panel').style.display = 'none';
        $('detail-card').style.display = 'block';
    }

    function startSSE(scanId, pkgName) {
        $('nav-scanning-badge').style.display = 'inline';
        showProgressPanel(pkgName);

        const es = new EventSource(`/api/scan/${scanId}/stream`);

        es.onmessage = evt => {
            const data = JSON.parse(evt.data);
            updateProgressPanel(data);

            if (data.phase === 'complete') {
                es.close();
                $('nav-scanning-badge').style.display = 'none';
                setScanLoading(false);
                loadHistory();
                loadOverview();
                hideProgressPanel();
                loadReport(scanId);
                updateFindingsNavCount();
            }
        };

        es.onerror = () => {
            es.close();
            // Gracefully fall back to polling if SSE fails
            startPolling(scanId);
        };
    }

    /* Fallback polling (used if SSE not available) */
    function startPolling(scanId) {
        if (state.pollingInterval) clearInterval(state.pollingInterval);
        $('nav-scanning-badge').style.display = 'inline';
        loadReport(scanId);

        state.pollingInterval = setInterval(async () => {
            try {
                const data = await apiFetch(`/api/scan/${scanId}`);
                if (data.score !== -1) {
                    clearInterval(state.pollingInterval);
                    $('nav-scanning-badge').style.display = 'none';
                    setScanLoading(false);
                    hideProgressPanel();
                    loadHistory();
                    loadOverview();
                    loadReport(scanId);
                    updateFindingsNavCount();
                }
            } catch {}
        }, 2500);
    }

    function setScanLoading(on) {
        $('scan-btn').disabled      = on;
        $('package-input').disabled = on;
        $('scan-btn-text').textContent = on ? 'Scanning…' : 'Execute Scan';
        $('scan-spinner').style.display = on ? 'inline-block' : 'none';
    }

    /* ════════════════════════════════════════════════════════════
       FINDINGS VIEW
    ════════════════════════════════════════════════════════════ */
    async function loadFindings(params = {}) {
        const wrap = $('findings-table-wrap');
        wrap.innerHTML = '<div class="spinner-row"><i class="fa-solid fa-circle-notch spinning"></i></div>';

        try {
            // Server-side filters (severity, type, package)
            let url = '/api/findings';
            const qs = [];
            if (params.severity) qs.push(`severity=${params.severity}`);
            if (params.type)     qs.push(`type=${params.type}`);
            if (params.package)  qs.push(`package=${encodeURIComponent(params.package)}`);
            if (qs.length) url += '?' + qs.join('&');

            let findings = await apiFetch(url);

            // Client-side MITRE filter (not in API, filter locally)
            if (params.mitre) {
                findings = findings.filter(f =>
                    f.mitre_id && f.mitre_id.startsWith(params.mitre)
                );
            }

            state.findingsCache = findings;
            renderFindingsTable(findings);
            updateFindingsNavCount();
        } catch (e) {
            wrap.innerHTML = '<div class="empty-msg"><i class="fa-solid fa-circle-exclamation"></i><p>Error loading findings</p></div>';
        }
    }

    function renderFindingsTable(findings) {
        const wrap = $('findings-table-wrap');
        const summary = $('findings-summary');

        if (!findings.length) {
            summary.style.display = 'none';
            wrap.innerHTML = '<div class="empty-msg"><i class="fa-solid fa-bug"></i><p>No findings match the current filters.</p></div>';
            return;
        }

        // Summary
        summary.style.display = 'flex';
        $('findings-count-badge').textContent = `${findings.length} finding${findings.length !== 1 ? 's' : ''}`;
        const sevCounts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity]||0)+1; return acc; }, {});
        $('findings-sev-chips').innerHTML = Object.entries(sevCounts)
            .sort((a,b) => ['high','medium','low'].indexOf(a[0]) - ['high','medium','low'].indexOf(b[0]))
            .map(([s,c]) => `<span class="badge ${s}">${c} ${s}</span>`).join('');

        const rows = findings.map(f => `
            <tr>
                <td class="pkg-col">${escHtml(f.package_name)}</td>
                <td style="font-size:0.72rem;color:var(--text-muted)">${escHtml(f.ecosystem)}</td>
                <td><span class="badge ${f.severity || 'medium'}">${(f.severity||'med').toUpperCase()}</span></td>
                <td style="font-size:0.78rem;color:var(--text-dim)">${escHtml(f.type||'—')}</td>
                <td>${f.mitre_id && f.mitre_id!=='T0000' ? `<span class="badge mitre">${escHtml(f.mitre_id)}</span>` : '—'}</td>
                <td class="mono msg-col" title="${escHtml(f.file||'')}${f.line ? ':'+f.line : ''}">${escHtml(f.file||'—')}</td>
                <td class="msg-col" title="${escHtml(f.message||'')}">${escHtml((f.message||'').slice(0,80))}${(f.message||'').length > 80 ? '…' : ''}</td>
                <td style="font-size:0.72rem;color:var(--text-muted)">${timeAgo(new Date(f.scanned_at))}</td>
            </tr>`).join('');

        wrap.innerHTML = `
            <div class="findings-table-outer">
                <table class="findings-table">
                    <thead><tr>
                        <th>Package</th><th>Eco</th><th>Severity</th>
                        <th>Type</th><th>MITRE</th><th>File</th>
                        <th>Message</th><th>Scanned</th>
                    </tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>`;
    }

    $('findings-apply-btn').addEventListener('click', () => {
        loadFindings({
            severity: $('filter-severity').value,
            type:     $('filter-type').value,
            package:  $('filter-package').value,
            mitre:    $('filter-mitre').value
        });
    });

    $('findings-refresh-btn').addEventListener('click', () => loadFindings());

    /* ════════════════════════════════════════════════════════════
       INVENTORY VIEW
    ════════════════════════════════════════════════════════════ */
    async function loadInventory() {
        const wrap = $('inventory-table-wrap');
        wrap.innerHTML = '<div class="spinner-row"><i class="fa-solid fa-circle-notch spinning"></i></div>';

        try {
            const items = await apiFetch('/api/inventory');
            state.inventoryCache = items;
            renderInventoryTable(items);
        } catch {
            wrap.innerHTML = '<div class="empty-msg"><i class="fa-solid fa-circle-exclamation"></i><p>Error loading inventory</p></div>';
        }
    }

    function renderInventoryTable(items) {
        const wrap = $('inventory-table-wrap');
        if (!items.length) {
            wrap.innerHTML = '<div class="empty-msg"><i class="fa-solid fa-boxes-stacked"></i><p>No inventory data yet. Run some scans first.</p></div>';
            return;
        }

        const rows = items.map(pkg => {
            const hist    = pkg.score_history || [];
            const last    = pkg.last_score ?? '—';
            const cls     = last >= 70 ? 'high' : last >= 15 ? 'medium' : 'low';
            const trend   = makeTrend(hist);
            const spark   = makeSparkline(hist.slice(-8).map(h => h.score));
            return `<tr>
                <td style="font-weight:600;color:var(--text)">${escHtml(pkg.package_name)}</td>
                <td style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase">${escHtml(pkg.ecosystem)}</td>
                <td class="mono" style="font-size:0.75rem;color:var(--text-muted)">${escHtml(pkg.last_version||'?')}</td>
                <td><span class="score-pill ${cls}">${last !== '—' ? last+'/100' : '—'}</span></td>
                <td>${spark}</td>
                <td class="inv-trend ${trend.dir}">${trend.icon}</td>
                <td style="font-size:0.75rem;color:var(--text-muted);text-align:center">${pkg.scan_count}</td>
                <td style="font-size:0.75rem;color:var(--text-muted)">${pkg.last_seen ? timeAgo(new Date(pkg.last_seen)) : '—'}</td>
            </tr>`;
        }).join('');

        wrap.innerHTML = `
            <table class="inv-table">
                <thead><tr>
                    <th>Package</th><th>Eco</th><th>Version</th>
                    <th>Last Score</th><th>Trend</th><th>Δ</th>
                    <th style="text-align:center">Scans</th><th>Last Seen</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>`;
    }

    function makeTrend(hist) {
        if (hist.length < 2) return { dir: 'flat', icon: '—' };
        const prev = hist[hist.length - 2].score;
        const last = hist[hist.length - 1].score;
        if (last > prev + 5)  return { dir: 'up',   icon: '↑ ' + (last - prev) };
        if (last < prev - 5)  return { dir: 'down', icon: '↓ ' + (prev - last) };
        return { dir: 'flat', icon: '→' };
    }

    function makeSparkline(scores) {
        if (!scores.length) return '<span style="color:var(--text-muted);font-size:0.7rem">—</span>';
        const max = Math.max(...scores, 1);
        return `<div class="sparkline">${scores.map(s => {
            const h  = Math.round((s / max) * 24);
            const bg = s >= 70 ? 'var(--red)' : s >= 15 ? 'var(--yellow)' : 'var(--green)';
            return `<div class="spark-bar" style="height:${Math.max(h,2)}px;background:${bg}"></div>`;
        }).join('')}</div>`;
    }

    $('inventory-refresh-btn').addEventListener('click', loadInventory);

    /* ════════════════════════════════════════════════════════════
       NAV BADGE
    ════════════════════════════════════════════════════════════ */
    async function updateFindingsNavCount() {
        try {
            const findings = await apiFetch('/api/findings');
            const highCount = findings.filter(f => f.severity === 'high').length;
            const badge = $('nav-findings-count');
            badge.textContent = highCount;
            badge.style.display = highCount > 0 ? 'inline' : 'none';
        } catch {}
    }

    /* ════════════════════════════════════════════════════════════
       HELPERS
    ════════════════════════════════════════════════════════════ */
    async function apiFetch(url, opts = {}) {
        const res = await fetch(url, opts);
        if (!res.ok) {
            const err = await res.json().catch(() => ({ error: res.statusText }));
            throw new Error(err.error || res.statusText);
        }
        return res.json();
    }

    function escHtml(str) {
        if (str == null) return '';
        return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function timeAgo(date) {
        const s = Math.floor((Date.now() - date) / 1000);
        if (s < 60)      return 'just now';
        if (s < 3600)    return Math.floor(s/60) + ' min ago';
        if (s < 86400)   return Math.floor(s/3600) + ' hr ago';
        if (s < 2592000) return Math.floor(s/86400) + ' d ago';
        return Math.floor(s/2592000) + ' mo ago';
    }

    function animateValue(el, end, dur = 800) {
        if (!el) return;
        let start = 0, t0 = null;
        const step = t => {
            if (!t0) t0 = t;
            const p = Math.min((t - t0) / dur, 1);
            el.textContent = Math.floor(p * end);
            if (p < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
    }

    function showError(msg) {
        const dc = $('detail-card');
        if (dc) dc.innerHTML = `<div class="empty-state"><i class="fa-solid fa-triangle-exclamation" style="font-size:2rem;color:var(--red);"></i><h3>Error</h3><p>${escHtml(msg)}</p></div>`;
    }

    /* ════════════════════════════════════════════════════════════
       SUPPLY CHAIN NETWORK TOPOLOGY VISUALIZATION
    ════════════════════════════════════════════════════════════ */
    function initVisualization() {
        const canvas = $('viz-canvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const wrap = canvas.parentElement;

        function resize() {
            canvas.width  = wrap.clientWidth  || 620;
            canvas.height = wrap.clientHeight || 520;
        }
        resize();
        window.addEventListener('resize', resize);

        // ── Strict monochromatic palette ─────────────────────────
        const C = {
            blue:      '#00c8ff',
            blueMid:   'rgba(0,200,255,0.55)',
            blueDim:   'rgba(0,200,255,0.20)',
            edge:      'rgba(0,200,255,0.14)',
            nodeBg:    'rgba(4,10,24,0.97)',
            textBright:'rgba(196,218,242,0.88)',
            textDim:   'rgba(86,116,150,0.60)',
            grid:      'rgba(0,200,255,0.022)',
        };

        // ── Pipeline node definitions (fractional positions) ─────
        const NODES = [
            // Registry sources — left column
            { id:'pypi',    label:'PyPI',    sub:'registry', xf:0.09, yf:0.30, r:21, tier:'src'  },
            { id:'npm',     label:'npm',     sub:'registry', xf:0.09, yf:0.50, r:21, tier:'src'  },
            { id:'github',  label:'git',     sub:'source',   xf:0.09, yf:0.70, r:21, tier:'src'  },
            // Ingest hub
            { id:'ingest',  label:'INGEST',  sub:'fetch',    xf:0.29, yf:0.50, r:25, tier:'hub'  },
            // Analysis layer
            { id:'static',  label:'STATIC',  sub:'ast·yara', xf:0.52, yf:0.23, r:24, tier:'proc' },
            { id:'sandbox', label:'SANDBOX', sub:'dynamic',  xf:0.52, yf:0.41, r:24, tier:'proc' },
            { id:'repute',  label:'REPUTE',  sub:'trust',    xf:0.52, yf:0.59, r:24, tier:'proc' },
            { id:'cve',     label:'CVE',     sub:'intel',    xf:0.52, yf:0.77, r:24, tier:'proc' },
            // Risk engine
            { id:'engine',  label:'RISK',    sub:'engine',   xf:0.74, yf:0.50, r:27, tier:'hub'  },
            // Final verdict
            { id:'verdict', label:'VERDICT', sub:null,       xf:0.93, yf:0.50, r:34, tier:'out'  },
        ];

        const EDGES = [
            { from:'pypi',    to:'ingest'  },
            { from:'npm',     to:'ingest'  },
            { from:'github',  to:'ingest'  },
            { from:'ingest',  to:'static'  },
            { from:'ingest',  to:'sandbox' },
            { from:'ingest',  to:'repute'  },
            { from:'ingest',  to:'cve'     },
            { from:'static',  to:'engine'  },
            { from:'sandbox', to:'engine'  },
            { from:'repute',  to:'engine'  },
            { from:'cve',     to:'engine'  },
            { from:'engine',  to:'verdict' },
        ];

        // ── Flowing particles ────────────────────────────────────
        const particles = [];
        for (let i = 0; i < 24; i++) {
            particles.push({
                edge:  EDGES[i % EDGES.length],
                t:     Math.random(),
                speed: 0.003 + Math.random() * 0.005,
                size:  1.4 + Math.random() * 1.6,
                alpha: 0.45 + Math.random() * 0.55,
            });
        }

        // Cubic bezier interpolation
        function bz(p0, p1, p2, p3, t) {
            const u = 1 - t;
            return u*u*u*p0 + 3*u*u*t*p1 + 3*u*t*t*p2 + t*t*t*p3;
        }

        function buildNodeMap(W, H) {
            const m = {};
            NODES.forEach(n => { m[n.id] = { ...n, x: n.xf * W, y: n.yf * H }; });
            return m;
        }

        let frame = 0;

        function draw() {
            const W = canvas.width;
            const H = canvas.height;
            const nm = buildNodeMap(W, H);

            ctx.clearRect(0, 0, W, H);

            // ── Background grid ───────────────────────────────────
            ctx.save();
            ctx.strokeStyle = C.grid;
            ctx.lineWidth = 0.5;
            const gs = Math.max(W, H) / 14;
            for (let x = 0; x < W; x += gs) {
                ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
            }
            for (let y = 0; y < H; y += gs) {
                ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
            }
            ctx.restore();

            // ── Edges (bezier, animated dash) ─────────────────────
            EDGES.forEach(e => {
                const a = nm[e.from], b = nm[e.to];
                if (!a || !b) return;
                const cpx = a.x + (b.x - a.x) * 0.5;

                ctx.save();
                ctx.strokeStyle = C.edge;
                ctx.lineWidth   = 1;
                ctx.setLineDash([3, 7]);
                ctx.lineDashOffset = -(frame * 0.20);
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.bezierCurveTo(cpx, a.y, cpx, b.y, b.x, b.y);
                ctx.stroke();
                ctx.setLineDash([]);
                ctx.restore();
            });

            // ── Particles ─────────────────────────────────────────
            particles.forEach(p => {
                const a = nm[p.edge.from], b = nm[p.edge.to];
                if (!a || !b) return;
                const cpx = a.x + (b.x - a.x) * 0.5;
                const px = bz(a.x, cpx, cpx, b.x, p.t);
                const py = bz(a.y, a.y,  b.y,  b.y, p.t);
                const fade = Math.sin(p.t * Math.PI);

                ctx.save();
                ctx.globalAlpha = p.alpha * fade;
                ctx.shadowColor = C.blue;
                ctx.shadowBlur  = 7;
                ctx.fillStyle   = C.blue;
                ctx.beginPath();
                ctx.arc(px, py, p.size, 0, Math.PI * 2);
                ctx.fill();
                ctx.restore();

                p.t += p.speed;
                if (p.t >= 1) {
                    p.edge  = EDGES[Math.floor(Math.random() * EDGES.length)];
                    p.t     = 0;
                    p.speed = 0.003 + Math.random() * 0.005;
                    p.alpha = 0.45 + Math.random() * 0.55;
                }
            });

            // ── Nodes ─────────────────────────────────────────────
            NODES.forEach(nd => {
                const n  = nm[nd.id];
                const isOut  = n.tier === 'out';
                const isHub  = n.tier === 'hub';
                const isSrc  = n.tier === 'src';

                // Outer pulsing ring (verdict only)
                if (isOut) {
                    const pr = n.r + 9 + 3 * Math.sin(frame * 0.05);
                    const pa = 0.16 + 0.09 * Math.sin(frame * 0.05);
                    ctx.save();
                    ctx.strokeStyle = `rgba(0,200,255,${pa})`;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.arc(n.x, n.y, pr, 0, Math.PI * 2);
                    ctx.stroke();
                    ctx.restore();
                }

                // Node fill + border
                ctx.save();
                ctx.shadowColor = C.blue;
                ctx.shadowBlur  = isOut ? 22 : (isHub ? 9 : 0);

                if (isOut) {
                    const g = ctx.createRadialGradient(n.x, n.y - n.r*0.25, 2, n.x, n.y, n.r);
                    g.addColorStop(0, 'rgba(0,150,220,0.22)');
                    g.addColorStop(1, 'rgba(0,35,100,0.12)');
                    ctx.fillStyle   = g;
                    ctx.strokeStyle = 'rgba(0,200,255,0.65)';
                    ctx.lineWidth   = 1.5;
                } else {
                    ctx.fillStyle   = C.nodeBg;
                    ctx.strokeStyle = isHub ? 'rgba(0,200,255,0.46)' : (isSrc ? 'rgba(0,200,255,0.28)' : 'rgba(0,200,255,0.22)');
                    ctx.lineWidth   = 1;
                }

                ctx.beginPath();
                ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
                ctx.fill();
                ctx.stroke();
                ctx.restore();

                // Labels
                ctx.save();
                ctx.textAlign = 'center';

                ctx.fillStyle    = isOut ? C.blue : (isHub ? 'rgba(200,220,242,0.90)' : 'rgba(175,205,238,0.72)');
                ctx.font         = `600 ${isOut ? 8.5 : 8}px "JetBrains Mono", monospace`;
                ctx.textBaseline = n.sub ? 'bottom' : 'middle';
                if (isOut) { ctx.shadowColor = C.blue; ctx.shadowBlur = 9; }
                ctx.fillText(n.label, n.x, n.sub ? n.y + 1 : n.y);

                if (n.sub) {
                    ctx.font         = `400 6.5px "JetBrains Mono", monospace`;
                    ctx.fillStyle    = C.textDim;
                    ctx.textBaseline = 'top';
                    ctx.shadowBlur   = 0;
                    ctx.fillText(n.sub, n.x, n.y + 2);
                }
                ctx.restore();
            });

            frame++;
            requestAnimationFrame(draw);
        }

        draw();
    }

    /* ════════════════════════════════════════════════════════════
       INIT
    ════════════════════════════════════════════════════════════ */
    checkStatus();
    loadOverview();
    loadHistory();
    updateFindingsNavCount();
    initVisualization();
});
