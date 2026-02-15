/* ================================================================
   ARCHON Dashboard — interactive client
   ================================================================ */

class ArchonDashboard {
    constructor() {
        /** @type {EventSource|null} */
        this.sse = null;
        this.counts = { findings: 0, actions: 0 };
        this._depData = null;
        this._secretData = null;
        this.reports = { security: null, operational: null };
        this.el = {};
        this._init();
    }

    /* ----------------------------------------------------------------
       Bootstrap
       ---------------------------------------------------------------- */
    _init() {
        this._cache();
        this._bind();
    }

    _cache() {
        const id = (s) => document.getElementById(s);
        this.el = {
            input:       id('repo-input'),
            btn:         id('analyze-btn'),
            scanBar:     id('scan-bar'),
            riskBanner:  id('risk-banner'),
            riskLevel:   id('overall-risk-level'),
            // health ring
            ringFg:      id('ring-fg'),
            ringScore:   id('ring-score'),
            ringGrade:   id('ring-grade'),
            healthRecs:  id('health-recs'),
            // cards
            commitVal:   id('commit-risk-val'),
            commitDet:   id('commit-risk-detail'),
            commitStats: id('commit-stats'),
            prVal:       id('pr-risk-val'),
            prDet:       id('pr-risk-detail'),
            prStats:     id('pr-stats'),
            secVal:      id('sec-risk-val'),
            secDet:      id('sec-risk-detail'),
            secStats:    id('sec-stats'),
            // feeds
            findFeed:    id('findings-feed'),
            findCount:   id('findings-count'),
            findEmpty:   id('findings-empty'),
            actFeed:     id('actions-feed'),
            actCount:    id('actions-count'),
            actEmpty:    id('actions-empty'),
            // panels
            corrPanel:   id('correlation-panel'),
            corrBody:    id('correlation-body'),
            reportPanel: id('report-panel'),
            reportBody:  id('report-body'),
        };
    }

    _bind() {
        this.el.btn.addEventListener('click', () => this._start());
        this.el.input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this._start();
        });
        document.querySelectorAll('.quick-btn').forEach((b) => {
            b.addEventListener('click', () => {
                this.el.input.value = b.dataset.repo;
                this._start();
            });
        });
        document.querySelectorAll('.tab').forEach((t) => {
            t.addEventListener('click', () => this._switchTab(t.dataset.tab));
        });
    }

    /* ----------------------------------------------------------------
       Analysis lifecycle
       ---------------------------------------------------------------- */
    _start() {
        const raw = this.el.input.value.trim();
        if (!raw.includes('/')) return;
        const [owner, repo] = raw.split('/');
        if (!owner || !repo) return;

        this._reset();
        this._setRunning(true);

        this.sse = new EventSource(`/api/analyze/${owner}/${repo}`);

        const on = (evt, fn) => this.sse.addEventListener(evt, (e) => fn.call(this, JSON.parse(e.data)));
        on('phase',       this._onPhase);
        on('signal',      this._onSignal);
        on('finding',     this._onFinding);
        on('correlation', this._onCorrelation);
        on('decision',    this._onDecision);
        on('action',      this._onAction);
        on('report',      this._onReport);
        on('complete',    this._onComplete);
        on('error_event', this._onError);

        this.sse.onerror = () => {
            this.sse.close();
            this._setRunning(false);
        };
    }

    _setRunning(v) {
        this.el.btn.disabled = v;
        this.el.btn.classList.toggle('is-running', v);
        this.el.scanBar.classList.toggle('hidden', !v);
    }

    /* ----------------------------------------------------------------
       Event handlers
       ---------------------------------------------------------------- */
    _onPhase({ phase, status }) {
        document.querySelectorAll('.pipeline-step').forEach((s) => {
            if (s.dataset.phase !== phase) return;
            s.classList.toggle('is-active', status === 'active');
            s.classList.toggle('is-done', status === 'complete');
        });
        if (status === 'complete') {
            document.querySelectorAll('.pipeline-line').forEach((l) => {
                if (l.dataset.after === phase) l.classList.add('is-filled');
            });
        }
    }

    _onSignal({ type, data }) {
        switch (type) {
            case 'health':       return this._setHealth(data);
            case 'commits':      return this._setCommits(data);
            case 'prs':          return this._setPRs(data);
            case 'dependencies': return this._setDeps(data);
            case 'secrets':      return this._setSecrets(data);
        }
    }

    _onFinding(f) {
        this.counts.findings++;
        this.el.findCount.textContent = this.counts.findings;
        if (this.el.findEmpty) { this.el.findEmpty.remove(); this.el.findEmpty = null; }

        const sev = f.severity || 'medium';
        const item = document.createElement('div');
        item.className = `feed-item sev-${sev}`;
        item.innerHTML = `
            <span class="sev-dot"></span>
            <div class="fi-body">
                <div class="fi-title">${this._esc(f.title)}</div>
                <div class="fi-detail">${this._esc(f.detail)}</div>
            </div>
            <span class="sev-badge">${sev}</span>`;
        this.el.findFeed.appendChild(item);
        item.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    _onCorrelation(data) {
        this.el.corrPanel.classList.remove('hidden');

        const sr = data.signal_risks;
        let html = '<div class="corr-grid"><div class="corr-section"><h4>Signal Risks</h4>';
        const labels = { health: 'Health', commits: 'Commits', pull_requests: 'Pull Requests',
                         dependencies: 'Dependencies', secrets: 'Secrets' };
        for (const [key, label] of Object.entries(labels)) {
            const val = typeof sr[key] === 'object' ? `${sr[key].score}/100 (${sr[key].grade})` : sr[key];
            const cls = typeof sr[key] === 'object' ? this._gradeColor(sr[key].grade) : `rl-${sr[key]}`;
            html += `<div class="corr-row"><span>${label}</span><span class="${cls}">${val}</span></div>`;
        }
        html += '</div><div class="corr-section"><h4>Correlation Insights</h4>';
        for (const c of (data.correlations || [])) {
            html += `<div class="corr-insight"><span class="corr-insight-icon">&#9670;</span><span>${this._esc(c)}</span></div>`;
        }
        html += '</div></div>';
        this.el.corrBody.innerHTML = html;
    }

    _onDecision(data) {
        this._addAction('⚖️', `Decision: ${data.overall_risk.toUpperCase()} risk`, data.reasoning);
        // Add recommendations
        for (const r of (data.recommendations || [])) {
            this._addAction('💡', r, '');
        }
    }

    _onAction(data) {
        const icons = { report_generated: '📄', operational_report: '📊',
                        issue_created: '🎫', action_logged: '📝' };
        this._addAction(icons[data.type] || '✓', data.detail, data.id ? `ID: ${data.id}` : '');
    }

    _onReport(data) {
        this.reports.security = data.security;
        this.reports.operational = data.operational;
        this.el.reportPanel.classList.remove('hidden');
        this._switchTab('security');
    }

    _onComplete(data) {
        this._setRunning(false);
        if (this.sse) this.sse.close();

        // Show banner
        this.el.riskBanner.classList.remove('hidden');
        this.el.riskBanner.className = `risk-banner rl-${data.overall_risk}`;
        this.el.riskLevel.textContent = data.overall_risk.toUpperCase();
    }

    _onError(data) {
        this._setRunning(false);
        if (this.sse) this.sse.close();
        this._onFinding({ type: 'error', severity: 'high', title: 'Analysis Error',
                          detail: data.message || 'Unknown error' });
    }

    /* ----------------------------------------------------------------
       Card updaters
       ---------------------------------------------------------------- */
    _setHealth(d) {
        const score = d.health_score ?? 0;
        const grade = d.grade || '?';
        this.el.ringScore.textContent = score;
        this.el.ringGrade.textContent = `Grade ${grade}`;

        const circ = 2 * Math.PI * 52;                     // r=52
        const offset = circ * (1 - score / 100);
        this.el.ringFg.style.strokeDashoffset = offset;

        const colors = { A: '#2ea043', B: '#00d4ff', C: '#d29922', D: '#f0883e', F: '#f85149' };
        this.el.ringFg.style.stroke = colors[grade] || '#8b949e';

        const recs = (d.recommendations || []).slice(0, 2).join('; ') || 'No recommendations';
        this.el.healthRecs.textContent = recs;

        this._loadCard('card-health');
    }

    _setCommits(d) {
        const risk = d.aggregate_risk_level || 'none';
        const count = d.commits_analyzed || 0;
        const dist = d.risk_distribution || {};
        this.el.commitVal.textContent = risk.toUpperCase();
        this.el.commitVal.className = `rc-risk-value rl-${risk}`;
        this.el.commitDet.textContent = `${count} commits analyzed`;
        this.el.commitStats.textContent = `High: ${dist.high || 0} · Med: ${dist.medium || 0} · Low: ${dist.low || 0}`;
        this._loadCard('card-commits');
    }

    _setPRs(d) {
        const risk = d.aggregate_risk_level || 'none';
        const count = d.open_prs_analyzed ?? d.pull_requests?.length ?? 0;
        this.el.prVal.textContent = risk.toUpperCase();
        this.el.prVal.className = `rc-risk-value rl-${risk}`;
        this.el.prDet.textContent = `${count} open PRs analyzed`;

        const dist = d.risk_distribution || {};
        this.el.prStats.textContent = `High: ${dist.high || 0} · Med: ${dist.medium || 0} · Low: ${dist.low || 0}`;
        this._loadCard('card-prs');
    }

    _setDeps(d) {
        this._depData = d;
        this._refreshSecurity();
    }

    _setSecrets(d) {
        this._secretData = d;
        this._refreshSecurity();
    }

    _refreshSecurity() {
        const deps = this._depData || {};
        const sec  = this._secretData || {};
        const ord = (l) => ({ none: 0, low: 1, medium: 2, high: 3, critical: 4 }[l] ?? 0);
        const dR = deps.risk_level || 'none';
        const sR = sec.risk_level || 'none';
        const overall = ord(dR) >= ord(sR) ? dR : sR;

        this.el.secVal.textContent = overall.toUpperCase();
        this.el.secVal.className = `rc-risk-value rl-${overall}`;

        const vulns = (deps.vulnerabilities || []).length;
        const secrets = sec.finding_count || 0;
        this.el.secDet.textContent = `${vulns} CVEs · ${secrets} secrets`;
        this.el.secStats.textContent = `Deps scanned: ${deps.packages_scanned || 0} · Files scanned: ${sec.files_scanned || 0}`;
        this._loadCard('card-security');
    }

    /* ----------------------------------------------------------------
       Helpers
       ---------------------------------------------------------------- */
    _loadCard(id) {
        document.getElementById(id)?.classList.add('is-loaded');
    }

    _addAction(icon, title, detail) {
        this.counts.actions++;
        this.el.actCount.textContent = this.counts.actions;
        if (this.el.actEmpty) { this.el.actEmpty.remove(); this.el.actEmpty = null; }

        const item = document.createElement('div');
        item.className = 'feed-item';
        item.innerHTML = `
            <span class="action-icon">${icon}</span>
            <div class="fi-body">
                <div class="fi-title">${this._esc(title)}</div>
                ${detail ? `<div class="fi-detail">${this._esc(detail)}</div>` : ''}
            </div>`;
        this.el.actFeed.appendChild(item);
        item.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    _switchTab(tab) {
        document.querySelectorAll('.tab').forEach((t) =>
            t.classList.toggle('active', t.dataset.tab === tab)
        );
        const md = this.reports[tab] || '_No report generated yet._';
        this.el.reportBody.innerHTML = (typeof marked !== 'undefined' && marked.parse)
            ? marked.parse(md) : md.replace(/\n/g, '<br>');
    }

    _gradeColor(g) {
        return { A: 'rl-low', B: 'rl-low', C: 'rl-medium', D: 'rl-high', F: 'rl-critical' }[g] || '';
    }

    _esc(s) {
        const d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    }

    _reset() {
        this.counts = { findings: 0, actions: 0 };
        this._depData = null;
        this._secretData = null;
        this.reports = { security: null, operational: null };

        this.el.findCount.textContent = '0';
        this.el.actCount.textContent = '0';

        // Reset feeds
        this.el.findFeed.innerHTML = '<div class="feed-empty" id="findings-empty">Collecting signals…</div>';
        this.el.findEmpty = document.getElementById('findings-empty');
        this.el.actFeed.innerHTML = '<div class="feed-empty" id="actions-empty">Waiting for decisions…</div>';
        this.el.actEmpty = document.getElementById('actions-empty');

        // Reset cards
        this.el.ringScore.textContent = '—';
        this.el.ringGrade.textContent = '—';
        this.el.ringFg.style.strokeDashoffset = 2 * Math.PI * 52;
        this.el.ringFg.style.stroke = '#484f58';
        this.el.healthRecs.textContent = '';
        for (const k of ['commitVal', 'prVal', 'secVal']) {
            this.el[k].textContent = '—';
            this.el[k].className = 'rc-risk-value';
        }
        for (const k of ['commitDet', 'prDet', 'secDet']) {
            this.el[k].textContent = 'Scanning…';
        }
        for (const k of ['commitStats', 'prStats', 'secStats']) {
            this.el[k].textContent = '';
        }
        document.querySelectorAll('.risk-card').forEach((c) => c.classList.remove('is-loaded'));

        // Reset pipeline
        document.querySelectorAll('.pipeline-step').forEach((s) =>
            s.classList.remove('is-active', 'is-done'));
        document.querySelectorAll('.pipeline-line').forEach((l) =>
            l.classList.remove('is-filled'));

        // Hide panels
        this.el.riskBanner.classList.add('hidden');
        this.el.corrPanel.classList.add('hidden');
        this.el.reportPanel.classList.add('hidden');
    }
}

/* Boot */
document.addEventListener('DOMContentLoaded', () => {
    window.archon = new ArchonDashboard();
});
