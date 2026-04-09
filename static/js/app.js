// JSHunter — Frontend Engine
// Desenvolvido por HuntBox
// Empresa 100% ofensiva — Pentest • Red Team • Bug Bounty

let currentResults = null;
let activeFilter = 'all';
let currentSessionId = null;
let allFilesData = [];

// ========================================
// EVENT LISTENERS
// ========================================

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        if (btn.id === 'clearAllBtn') return;
        const tab = btn.dataset.tab;
        if (!tab) return;
        document.querySelectorAll('.tab-btn').forEach(b => {
            if (b.id !== 'clearAllBtn') b.classList.remove('active');
        });
        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
        btn.classList.add('active');
        document.getElementById(`${tab}-tab`).classList.remove('hidden');
    });
});

// Clear all
document.getElementById('clearAllBtn').addEventListener('click', clearAll);

// Single URL
document.getElementById('analyzeBtn').addEventListener('click', () => analyzeSingle());
document.getElementById('jsUrl').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') analyzeSingle();
});

// Multiple URLs
document.getElementById('analyzeMultipleBtn').addEventListener('click', analyzeMultiple);

// File upload
document.getElementById('urlFile').addEventListener('change', handleFileSelect);
document.getElementById('analyzeFileBtn').addEventListener('click', analyzeFile);

// Back to files
document.getElementById('backToFiles').addEventListener('click', () => {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('files-section').classList.remove('hidden');
    document.getElementById('backToFiles').classList.add('hidden');
});

// Export
document.getElementById('exportBtn').addEventListener('click', exportResults);

// Filters
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.dataset.filter;
        if (currentResults) displayResults(currentResults);
    });
});

// ========================================
// CORE FUNCTIONS
// ========================================

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) {
        document.getElementById('fileName').textContent = `> ${file.name} (${formatBytes(file.size)})`;
        document.getElementById('fileName').classList.remove('hidden');
        document.getElementById('analyzeFileBtn').disabled = false;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function clearAll() {
    document.getElementById('jsUrl').value = '';
    document.getElementById('multipleUrls').value = '';
    document.getElementById('urlFile').value = '';
    document.getElementById('fileName').textContent = '';
    document.getElementById('fileName').classList.add('hidden');
    document.getElementById('analyzeFileBtn').disabled = true;
    document.getElementById('results').classList.add('hidden');
    document.getElementById('files-section').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('backToFiles').classList.add('hidden');
    currentResults = null;
    currentSessionId = null;
    allFilesData = [];
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('[data-filter="all"]').classList.add('active');
    activeFilter = 'all';
    const singleTabBtn = document.querySelector('[data-tab="single"]');
    if (singleTabBtn) singleTabBtn.click();
}

async function analyzeSingle() {
    const url = document.getElementById('jsUrl').value.trim();
    if (!url) {
        showError('Insira uma URL de target');
        return;
    }
    try { new URL(url); } catch (e) {
        showError('URL invalida');
        return;
    }
    let finalUrl = url;
    if (url.includes('0.0.0.0')) {
        if (!confirm('0.0.0.0 detectado. Substituir por localhost?')) return;
        finalUrl = url.replace('0.0.0.0', 'localhost');
        document.getElementById('jsUrl').value = finalUrl;
    }
    await analyzeUrls([finalUrl]);
}

async function analyzeMultiple() {
    const textarea = document.getElementById('multipleUrls');
    const urls = textarea.value.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));

    if (urls.length === 0) {
        showError('Insira pelo menos uma URL');
        return;
    }
    const fixedUrls = urls.map(url => url.includes('0.0.0.0') ? url.replace('0.0.0.0', 'localhost') : url);
    await analyzeUrls(fixedUrls);
}

async function analyzeFile() {
    const fileInput = document.getElementById('urlFile');
    const file = fileInput.files[0];
    if (!file) {
        showError('Selecione um arquivo');
        return;
    }
    const formData = new FormData();
    formData.append('file', file);
    await analyzeUrls(null, formData);
}

async function analyzeUrls(urls, formData = null) {
    const loading = document.getElementById('loading');
    const loadingText = document.getElementById('loading-text');
    const error = document.getElementById('error');
    const results = document.getElementById('results');
    const filesSection = document.getElementById('files-section');

    error.classList.add('hidden');
    results.classList.add('hidden');
    filesSection.classList.add('hidden');
    loading.classList.remove('hidden');

    try {
        let response;
        // AbortController with 5 min timeout for large files
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 300000);

        if (formData) {
            loadingText.textContent = 'Uploading e analisando target...';
            response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData,
                signal: controller.signal,
            });
        } else {
            const count = urls ? urls.length : 0;
            loadingText.textContent = `Hunting ${count} target${count > 1 ? 's' : ''}... (arquivos grandes podem demorar)`;
            response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls }),
                signal: controller.signal,
            });
        }

        clearTimeout(timeoutId);

        if (!response.ok) {
            const errorText = await response.text();
            let errorMsg = 'Falha na analise';
            try { errorMsg = JSON.parse(errorText).error || errorMsg; } catch (e) {}
            throw new Error(errorMsg);
        }

        const data = await response.json();
        if (!data || !data.results) throw new Error('Resposta invalida do servidor');

        currentSessionId = data.session_id;
        allFilesData = data.results;

        if (data.results.length === 1) {
            currentResults = data.results[0];
            displayResults(currentResults);
            results.classList.remove('hidden');
        } else {
            displayFileCards(data.results);
            filesSection.classList.remove('hidden');
        }

    } catch (err) {
        if (err.name === 'AbortError') {
            showError('Timeout: a analise demorou mais de 5 minutos. Tente com um arquivo menor.');
        } else {
            showError(err.message || 'Falha ao conectar com o servidor');
        }
    } finally {
        loading.classList.add('hidden');
    }
}

// ========================================
// DISPLAY FUNCTIONS
// ========================================

function displayFileCards(files) {
    const grid = document.getElementById('files-grid');
    grid.innerHTML = '';
    files.forEach((file) => {
        const card = document.createElement('div');
        card.className = 'file-card';
        card.dataset.fileId = file.file_id;
        card.onclick = () => showFileResults(file);

        const hasErrors = file.errors && file.errors.length > 0;
        const totalFindings = (file.api_keys?.length || 0) + (file.credentials?.length || 0) +
            (file.xss_vulnerabilities?.length || 0) + (file.high_entropy_strings?.length || 0);
        const riskScore = file.risk_score || 0;

        card.innerHTML = `
            <div class="file-card-header">
                <div class="file-number">TARGET ${file.file_id}</div>
                <div class="file-status ${hasErrors ? 'error' : 'completed'}">${hasErrors ? 'ERRO' : `SCORE: ${riskScore}`}</div>
            </div>
            <div class="file-url" title="${escapeHtml(file.url)}">${escapeHtml(file.url)}</div>
            <div class="file-stats">
                <div class="file-stat"><i class="fas fa-key"></i> ${file.api_keys?.length || 0} keys</div>
                <div class="file-stat"><i class="fas fa-exclamation-triangle"></i> ${file.xss_vulnerabilities?.length || 0} vulns</div>
                <div class="file-stat"><i class="fas fa-code-branch"></i> ${file.api_endpoints?.length || 0} endpoints</div>
                <div class="file-stat"><i class="fas fa-random"></i> ${file.high_entropy_strings?.length || 0} entropy</div>
            </div>
            ${hasErrors ? `<div style="margin-top: 10px; color: var(--critical); font-family: var(--font-mono); font-size: 0.75rem;">${escapeHtml(file.errors[0])}</div>` : ''}
        `;
        grid.appendChild(card);
    });
}

function showFileResults(file) {
    currentResults = file;
    displayResults(file);
    document.getElementById('files-section').classList.add('hidden');
    document.getElementById('results').classList.remove('hidden');
    document.getElementById('backToFiles').classList.remove('hidden');
    document.getElementById('results-title').textContent = `Target ${file.file_id}`;
    document.querySelectorAll('.file-card').forEach(card => {
        card.classList.remove('active');
        if (card.dataset.fileId == file.file_id) card.classList.add('active');
    });
}

function showError(message) {
    const error = document.getElementById('error');
    error.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${escapeHtml(message)}`;
    error.classList.remove('hidden');
}

function updateRiskScore(data) {
    // Calculate severity counts from findings if not provided by backend
    let counts = data.severity_counts;
    if (!counts || (counts.critical === 0 && counts.high === 0 && counts.medium === 0 && counts.low === 0 && counts.info === 0)) {
        counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        const allArrays = [
            data.api_keys, data.credentials, data.xss_vulnerabilities,
            data.xss_functions, data.high_entropy_strings,
            data.api_endpoints, data.emails, data.parameters,
            data.paths_directories, data.interesting_comments,
        ];
        allArrays.forEach(arr => {
            if (arr && Array.isArray(arr)) {
                arr.forEach(item => {
                    let sev = item.severity;
                    if (!sev || typeof sev === 'boolean') sev = 'info';
                    sev = String(sev).toLowerCase();
                    if (counts.hasOwnProperty(sev)) counts[sev]++;
                    else counts.info++;
                });
            }
        });
    }

    // Calculate risk score if not provided
    let score = data.risk_score || 0;
    if (score === 0 && (counts.critical > 0 || counts.high > 0)) {
        score = Math.min(
            counts.critical * 25 + counts.high * 15 + counts.medium * 8 + counts.low * 3 + counts.info * 1,
            100
        );
    }

    const circle = document.getElementById('risk-circle');
    const value = document.getElementById('risk-value');

    value.textContent = score;

    circle.className = 'risk-circle';
    if (score >= 75) circle.classList.add('critical');
    else if (score >= 50) circle.classList.add('high');
    else if (score >= 25) circle.classList.add('medium');
    else circle.classList.add('low');

    const setCount = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val || 0;
    };
    setCount('sev-critical', counts.critical);
    setCount('sev-high', counts.high);
    setCount('sev-medium', counts.medium);
    setCount('sev-low', counts.low);
    setCount('sev-info', counts.info);

    // Engine badge
    const engineBadge = document.getElementById('engine-badge');
    if (engineBadge) {
        const engine = data.analysis_engine || 'Unknown';
        engineBadge.innerHTML = `<i class="fas fa-microchip"></i> ENGINE: <strong>${escapeHtml(engine)}</strong>`;
    }
}

function updateStats(data) {
    const setIfExists = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    };
    setIfExists('stat-api-keys', data.api_keys?.length || 0);
    setIfExists('stat-credentials', data.credentials?.length || 0);
    setIfExists('stat-entropy', data.high_entropy_strings?.length || 0);
    setIfExists('stat-emails', data.emails?.length || 0);
    setIfExists('stat-xss', (data.xss_vulnerabilities?.length || 0) + (data.xss_functions?.length || 0));
    setIfExists('stat-endpoints', data.api_endpoints?.length || 0);
}

function displayResults(data) {
    const container = document.getElementById('findings-content');
    container.innerHTML = '';

    updateStats(data);
    updateRiskScore(data);

    // Source Map Alert
    if (data.source_map_detected) {
        const smAlert = document.createElement('div');
        smAlert.className = 'source-map-alert';
        smAlert.innerHTML = `<i class="fas fa-map"></i> <strong>SOURCE MAP DETECTADO</strong> — Codigo fonte original pode estar exposto: <a href="${escapeHtml(data.source_map_url)}" target="_blank">${escapeHtml(data.source_map_url)}</a>`;
        container.appendChild(smAlert);
    }

    const sections = [
        { key: 'api_keys', title: 'API Key', icon: 'fa-key' },
        { key: 'credentials', title: 'Credencial', icon: 'fa-lock' },
        { key: 'high_entropy_strings', title: 'Alta Entropia', icon: 'fa-random' },
        { key: 'xss_vulnerabilities', title: 'Vulnerabilidade', icon: 'fa-exclamation-triangle' },
        { key: 'xss_functions', title: 'Funcao de Risco', icon: 'fa-code' },
        { key: 'emails', title: 'Email', icon: 'fa-envelope' },
        { key: 'api_endpoints', title: 'Endpoint', icon: 'fa-code-branch' },
        { key: 'parameters', title: 'Parametro', icon: 'fa-list' },
        { key: 'paths_directories', title: 'Path', icon: 'fa-folder' },
        { key: 'interesting_comments', title: 'Comentario', icon: 'fa-comment' },
    ];

    let allItems = [];
    sections.forEach(section => {
        const items = data[section.key];
        if (items && Array.isArray(items) && items.length > 0) {
            items.forEach(item => {
                item._sectionTitle = section.title;
                item._icon = section.icon;
                item._category = section.key;

                // Normalize severity — can arrive as boolean true, string, or missing
                let sev = item.severity;
                if (!sev || typeof sev === 'boolean') {
                    if (section.key === 'api_keys' || section.key === 'credentials') sev = 'critical';
                    else if (section.key === 'high_entropy_strings') sev = 'high';
                    else if (section.key === 'xss_vulnerabilities' || section.key === 'xss_functions') sev = 'high';
                    else sev = 'info';
                }
                item.severity = String(sev).toLowerCase();
                allItems.push(item);
            });
        }
    });

    // Filter
    if (activeFilter === 'xss') {
        allItems = allItems.filter(i => i._category === 'xss_vulnerabilities' || i._category === 'xss_functions');
    } else if (activeFilter === 'paths') {
        allItems = allItems.filter(i => i._category === 'paths_directories');
    } else if (activeFilter === 'comments') {
        allItems = allItems.filter(i => i._category === 'interesting_comments');
    } else if (activeFilter !== 'all') {
        allItems = allItems.filter(i => i._category === activeFilter);
    }

    // Sort by severity
    const severityWeight = { 'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1 };
    const getWeight = (item) => {
        if (!item || !item.severity) return 0;
        return severityWeight[String(item.severity).toLowerCase()] || 0;
    };
    allItems.sort((a, b) => getWeight(b) - getWeight(a));

    if (allItems.length > 0) {
        // Group items by type for collapsible display
        const groups = new Map();
        allItems.forEach(item => {
            const groupKey = item.type || item._sectionTitle;
            if (!groups.has(groupKey)) {
                groups.set(groupKey, {
                    type: groupKey,
                    icon: item._icon,
                    category: item._category,
                    severity: item.severity,
                    sectionTitle: item._sectionTitle,
                    items: [],
                });
            }
            groups.get(groupKey).items.push(item);
        });

        // Sort groups by severity weight then by count
        const sortedGroups = [...groups.values()].sort((a, b) => {
            const wA = severityWeight[a.severity] || 0;
            const wB = severityWeight[b.severity] || 0;
            if (wB !== wA) return wB - wA;
            return b.items.length - a.items.length;
        });

        sortedGroups.forEach(group => {
            if (group.items.length === 1) {
                // Single item — render directly (no group wrapper)
                const el = createFindingItem(group.items[0], { title: group.sectionTitle, icon: group.icon, key: group.category });
                container.appendChild(el);
            } else {
                // Multiple items — render as collapsible group
                const el = createFindingGroup(group);
                container.appendChild(el);
            }
        });
    } else if (!data.source_map_detected) {
        container.innerHTML = `
            <div style="text-align: center; padding: 60px 20px; color: var(--text-muted);">
                <i class="fas fa-check-circle" style="font-size: 2rem; margin-bottom: 12px; display: block; color: var(--low);"></i>
                <div style="font-family: var(--font-mono); font-size: 0.85rem;">Nenhum finding para este filtro</div>
            </div>
        `;
    }
}

function createFindingGroup(group) {
    const sev = String(group.severity || 'info').toLowerCase();
    const wrapper = document.createElement('div');
    wrapper.className = `finding-group sev-${sev}`;

    // Group header (clickable)
    const header = document.createElement('div');
    header.className = 'finding-group-header';
    header.innerHTML = `
        <div class="finding-group-left">
            <i class="fas fa-chevron-right finding-group-arrow"></i>
            <i class="fas ${group.icon}" style="color: var(--red); margin-right: 6px;"></i>
            <span class="finding-type">${escapeHtml(group.type)}</span>
            <span class="finding-group-count">${group.items.length}x</span>
            <span class="finding-group-lines">L${group.items.map(i => i.line).join(', L')}</span>
        </div>
        <span class="severity ${sev}">${sev}</span>
    `;

    const body = document.createElement('div');
    body.className = 'finding-group-body hidden';

    group.items.forEach(item => {
        const el = createFindingItem(item, { title: group.sectionTitle, icon: group.icon, key: group.category });
        el.style.marginLeft = '12px';
        el.style.borderLeft = '2px solid var(--border)';
        body.appendChild(el);
    });

    header.onclick = () => {
        body.classList.toggle('hidden');
        const arrow = header.querySelector('.finding-group-arrow');
        arrow.classList.toggle('rotated');
    };

    wrapper.appendChild(header);
    wrapper.appendChild(body);
    return wrapper;
}

function createFindingItem(item, section) {
    const div = document.createElement('div');
    const sev = String(item.severity || 'info').toLowerCase();
    div.className = `finding-item sev-${sev}`;

    const header = document.createElement('div');
    header.className = 'finding-header';

    const left = document.createElement('div');
    const type = document.createElement('div');
    type.className = 'finding-type';

    if (section.key === 'high_entropy_strings') {
        type.innerHTML = `<i class="fas fa-random" style="color: var(--high); margin-right: 6px;"></i> Entropy: ${item.entropy}`;
    } else {
        type.innerHTML = `<i class="fas ${section.icon}" style="color: var(--red); margin-right: 6px;"></i> ${escapeHtml(item.type || section.title)}`;
    }

    const line = document.createElement('span');
    line.className = 'finding-line';
    line.textContent = `L${item.line}`;

    left.appendChild(type);
    left.appendChild(line);

    const right = document.createElement('div');
    right.style.display = 'flex';
    right.style.alignItems = 'center';
    right.style.gap = '8px';

    if (item.ai_verified) {
        const aiBadge = document.createElement('span');
        aiBadge.className = 'ai-badge';
        aiBadge.innerHTML = '<i class="fas fa-robot"></i> AI';
        aiBadge.title = item.ai_reason || 'Classificado por IA';
        right.appendChild(aiBadge);
    }

    if (item.severity) {
        const severity = document.createElement('span');
        severity.className = `severity ${sev}`;
        severity.textContent = sev;
        right.appendChild(severity);
    }

    header.appendChild(left);
    header.appendChild(right);
    div.appendChild(header);

    // AI reason
    if (item.ai_reason) {
        const aiReason = document.createElement('div');
        aiReason.className = 'ai-reason';
        aiReason.innerHTML = `<i class="fas fa-robot"></i> ${escapeHtml(item.ai_reason)}`;
        div.appendChild(aiReason);
    }

    if (item.match || item.parameter) {
        const match = document.createElement('div');
        match.className = 'finding-match';
        match.textContent = item.match || item.parameter || item.full_match;
        div.appendChild(match);
    }

    if (item.context || item.line_content) {
        const showCodeBtn = document.createElement('button');
        showCodeBtn.className = 'show-code-btn';
        showCodeBtn.textContent = '> VER CODIGO';
        showCodeBtn.onclick = () => toggleCode(showCodeBtn, item);
        div.appendChild(showCodeBtn);

        const codeContext = document.createElement('div');
        codeContext.className = 'code-context hidden';
        codeContext.appendChild(createCodeBlock(item));
        div.appendChild(codeContext);
    }

    return div;
}

function createCodeBlock(item) {
    const pre = document.createElement('pre');
    if (item.context) {
        const lines = item.context.split('\n');
        const startLine = item.context_start_line || (item.line - 2);
        lines.forEach((line, index) => {
            const lineNum = startLine + index;
            const codeLine = document.createElement('span');
            codeLine.className = `code-line ${lineNum === item.line ? 'highlight' : ''}`;
            const lineNumber = document.createElement('span');
            lineNumber.className = 'line-number';
            lineNumber.textContent = String(lineNum).padStart(4, ' ') + ' ';
            codeLine.appendChild(lineNumber);
            codeLine.appendChild(document.createTextNode(line || ' '));
            pre.appendChild(codeLine);
        });
    } else if (item.line_content) {
        const codeLine = document.createElement('span');
        codeLine.className = 'code-line highlight';
        const lineNumber = document.createElement('span');
        lineNumber.className = 'line-number';
        lineNumber.textContent = String(item.line).padStart(4, ' ') + ' ';
        codeLine.appendChild(lineNumber);
        codeLine.appendChild(document.createTextNode(item.line_content));
        pre.appendChild(codeLine);
    }
    return pre;
}

function toggleCode(btn, item) {
    const codeContext = btn.nextElementSibling;
    if (codeContext.classList.contains('hidden')) {
        codeContext.classList.remove('hidden');
        btn.textContent = '> OCULTAR CODIGO';
    } else {
        codeContext.classList.add('hidden');
        btn.textContent = '> VER CODIGO';
    }
}

function exportResults() {
    if (!currentResults) return;
    const exportData = {
        tool: 'JSHunter by HuntBox',
        version: '2.0',
        timestamp: new Date().toISOString(),
        target: currentResults.url,
        risk_score: currentResults.risk_score || 0,
        severity_counts: currentResults.severity_counts || {},
        analysis_engine: currentResults.analysis_engine || 'Unknown',
        findings: {
            api_keys: currentResults.api_keys || [],
            credentials: currentResults.credentials || [],
            xss_vulnerabilities: currentResults.xss_vulnerabilities || [],
            high_entropy_strings: currentResults.high_entropy_strings || [],
            api_endpoints: currentResults.api_endpoints || [],
            emails: currentResults.emails || [],
            parameters: currentResults.parameters || [],
            paths_directories: currentResults.paths_directories || [],
            interesting_comments: currentResults.interesting_comments || [],
        },
        source_map: {
            detected: currentResults.source_map_detected || false,
            url: currentResults.source_map_url || '',
        },
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `jshunter_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
