/* ──────────────────────────────────────────────
   LogNorm - Main JavaScript
   ────────────────────────────────────────────── */

// ── State ──
let currentSessionId = '';
let currentEvents    = [];
let currentPage      = 1;
let isNormalizing    = false;
let selectedSource   = '';

// ── Utility ──
function qs(sel, ctx) { return (ctx || document).querySelector(sel); }
function qsa(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }

function sevClass(n) {
    n = parseInt(n) || 0;
    if (n >= 70) return 'critical';
    if (n >= 40) return 'high';
    if (n >= 20) return 'medium';
    if (n > 0)   return 'low';
    return 'info';
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Active nav link ──
document.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
    qsa('.nav-link').forEach(a => {
        if (a.getAttribute('href') === path) a.classList.add('active');
    });
});

// ════════════════════════════════════════════════
// INDEX PAGE  — Upload + Normalize
// ════════════════════════════════════════════════

function initUploadPage() {
    const zone = qs('#upload-zone');
    if (!zone) return;

    const fileInput = qs('#file-input');
    const filename  = qs('#upload-filename');

    // Drag & drop
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length) {
            fileInput.files = files;
            showFilename(files[0].name);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) showFilename(fileInput.files[0].name);
    });

    function showFilename(name) {
        filename.textContent = '📄 ' + name;
        filename.style.display = 'block';
    }

    // Source selection
    qsa('.source-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            qsa('.source-btn').forEach(b => b.classList.remove('selected'));
            btn.classList.add('selected');
            selectedSource = btn.dataset.source;
            qs('#selected-source-display').textContent = selectedSource;
        });
    });

    // Normalize button
    qs('#normalize-btn').addEventListener('click', runNormalize);

    // Export buttons
    const exportJsonBtn = qs('#export-json-btn');
    const exportCsvBtn  = qs('#export-csv-btn');
    if (exportJsonBtn) exportJsonBtn.addEventListener('click', () => exportSession('json'));
    if (exportCsvBtn)  exportCsvBtn.addEventListener('click',  () => exportSession('csv'));
}

async function runNormalize() {
    if (isNormalizing) return;

    const fileInput = qs('#file-input');
    if (!fileInput || !fileInput.files.length) {
        showResultBar('Please select a file to normalize.', true);
        return;
    }
    if (!selectedSource) {
        showResultBar('Please select a source type.', true);
        return;
    }

    isNormalizing = true;
    const btn = qs('#normalize-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="btn-spinner"></span> Normalizing…';
    clearResults();

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('source_type', selectedSource);

    try {
        const resp = await fetch('/api/normalize/batch', { method: 'POST', body: formData });
        const data = await resp.json();

        if (!data.success) {
            showResultBar(data.error || 'Normalization failed.', true);
            return;
        }

        currentEvents    = data.events || [];
        currentSessionId = data.session_id || '';

        showResultBar(
            `Normalized <strong>${currentEvents.length}</strong> events` +
            (data.failed ? ` (${data.failed} failed)` : '') +
            ` from <strong>${data.filename || 'file'}</strong>` +
            ` · session <code>${currentSessionId.slice(0, 8)}</code>`,
            false,
        );

        renderEventsTable(currentEvents, 'results-table-body');
        updateResultStats(currentEvents, data.failed || 0);

        qs('#results-section').style.display = 'block';
        qs('#export-actions').style.display  = 'flex';

    } catch (err) {
        showResultBar('Request failed: ' + err.message, true);
    } finally {
        isNormalizing = false;
        btn.disabled  = false;
        btn.textContent = '⚡ Normalize';
    }
}

function showResultBar(msg, isError) {
    const bar = qs('#result-bar');
    if (!bar) return;
    bar.className = 'result-bar' + (isError ? ' error' : '');
    bar.innerHTML = msg;
    bar.style.display = 'flex';
}

function clearResults() {
    const bar = qs('#result-bar');
    if (bar) bar.style.display = 'none';
    const tbody = qs('#results-table-body');
    if (tbody) tbody.innerHTML = '';
    const sec = qs('#results-section');
    if (sec) sec.style.display = 'none';
    const ex = qs('#export-actions');
    if (ex)  ex.style.display = 'none';
}

function updateResultStats(events, failed) {
    const set = el => { const e = qs(el[0]); if (e) e.textContent = el[1]; };
    set(['#stat-total',   events.length + failed]);
    set(['#stat-success', events.length]);
    set(['#stat-failed',  failed]);
}

function exportSession(fmt) {
    const url = `/api/export?format=${fmt}` + (currentSessionId ? `&session_id=${currentSessionId}` : '');
    window.location.href = url;
}


// ════════════════════════════════════════════════
// SHARED — Event table rendering
// ════════════════════════════════════════════════

function renderEventsTable(events, tbodyId) {
    const tbody = qs('#' + tbodyId);
    if (!tbody) return;

    if (!events.length) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:32px;color:var(--text-muted);">No events</td></tr>`;
        return;
    }

    tbody.innerHTML = events.map((ev, i) => {
        const e     = ev.event    || {};
        const h     = ev.host     || {};
        const p     = ev.process  || {};
        const net   = ev.network  || {};
        const u     = ev.user     || {};
        const sev   = e.severity  || 0;
        const cat   = (e.category || []).join(', ');
        const src   = net.source      && net.source.ip      ? net.source.ip : '';
        const dst   = net.destination && net.destination.ip ? net.destination.ip : '';

        return `<tr>
            <td><span class="source-badge ${e.source_type||''}">${escapeHtml(e.source_type||'')}</span></td>
            <td class="truncate">${escapeHtml(e.created ? e.created.replace('T',' ').replace('Z','') : '')}</td>
            <td class="truncate">${escapeHtml(h.name||'')}</td>
            <td>${escapeHtml(cat)}</td>
            <td class="truncate">${escapeHtml(e.action||'')}</td>
            <td><span class="sev-dot ${sevClass(sev)}"></span>${sev}</td>
            <td class="truncate">${escapeHtml(p.name || u.name || src || '')}</td>
            <td>
                <button class="btn btn-secondary" style="padding:4px 10px;font-size:11px;"
                        onclick="openEventModal(${i})">View</button>
            </td>
        </tr>`;
    }).join('');
}


// ════════════════════════════════════════════════
// EVENT MODAL
// ════════════════════════════════════════════════

function openEventModal(indexOrId) {
    let ev;
    if (typeof indexOrId === 'number') {
        ev = currentEvents[indexOrId];
    } else {
        // fetch from API
        fetchAndShowEvent(indexOrId);
        return;
    }
    if (!ev) return;
    renderEventModal(ev);
}

async function fetchAndShowEvent(eventId) {
    try {
        const resp = await fetch(`/api/record/${eventId}`);
        const data = await resp.json();
        if (data.success) renderEventModal(data.event);
    } catch (e) { console.error(e); }
}

function renderEventModal(ev) {
    const modal = qs('#event-modal');
    if (!modal) return;

    const e   = ev.event    || {};
    const h   = ev.host     || {};
    const p   = ev.process  || {};
    const net = ev.network  || {};
    const f   = ev.file     || {};
    const reg = ev.registry || {};
    const u   = ev.user     || {};
    const log = ev.log      || {};
    const tags = ev.tags    || [];

    function row(key, val) {
        if (val === '' || val === null || val === undefined) return '';
        if (Array.isArray(val)) val = val.join(', ');
        return `<div class="event-field">
            <span class="event-key">${escapeHtml(key)}</span>
            <span class="event-value">${escapeHtml(String(val))}</span>
        </div>`;
    }

    function section(title, fields) {
        const rows = fields.filter(([,v]) => v !== '' && v !== null && v !== undefined);
        if (!rows.length) return '';
        return `<div class="event-section">
            <div class="event-section-title">${title}</div>
            ${rows.map(([k,v]) => row(k,v)).join('')}
        </div>`;
    }

    const dst = net.destination || {};
    const src = net.source      || {};
    const ph  = p.hash          || {};
    const pp  = p.parent        || {};
    const fh  = f.hash          || {};
    const rv  = reg.value       || {};
    const hos = h.os            || {};

    const html = [
        section('Event', [
            ['event.id',           e.id],
            ['event.created',      e.created],
            ['event.source_type',  e.source_type],
            ['event.category',     e.category],
            ['event.type',         e.type],
            ['event.action',       e.action],
            ['event.outcome',      e.outcome],
            ['event.severity',     e.severity],
            ['event.original_id',  e.original_event_id],
        ]),
        section('Host', [
            ['host.name',     h.name],
            ['host.ip',       h.ip],
            ['host.os.type',  hos.type],
            ['host.os.name',  hos.name],
        ]),
        section('Process', [
            ['process.pid',          p.pid],
            ['process.ppid',         p.ppid],
            ['process.name',         p.name],
            ['process.executable',   p.executable],
            ['process.command_line', p.command_line],
            ['process.hash.md5',     ph.md5],
            ['process.hash.sha256',  ph.sha256],
            ['parent.pid',           pp.pid],
            ['parent.name',          pp.name],
            ['parent.executable',    pp.executable],
            ['parent.command_line',  pp.command_line],
        ]),
        section('Network', [
            ['network.direction',      net.direction],
            ['network.transport',      net.transport],
            ['network.src.ip',         src.ip],
            ['network.src.port',       src.port],
            ['network.dst.ip',         dst.ip],
            ['network.dst.port',       dst.port],
            ['network.dst.domain',     dst.domain],
        ]),
        section('File', [
            ['file.path',       f.path],
            ['file.name',       f.name],
            ['file.extension',  f.extension],
            ['file.hash.md5',   fh.md5],
            ['file.hash.sha256',fh.sha256],
            ['file.size',       f.size],
        ]),
        section('Registry', [
            ['registry.path',        reg.path],
            ['registry.key',         reg.key],
            ['registry.value.name',  rv.name],
            ['registry.value.type',  rv.type],
            ['registry.value.data',  rv.data],
        ]),
        section('User', [
            ['user.name',   u.name],
            ['user.domain', u.domain],
            ['user.id',     u.id],
        ]),
        tags.length ? `<div class="event-section">
            <div class="event-section-title">Tags</div>
            <div class="event-field">
                <span class="event-value tag-value">${escapeHtml(tags.join('  '))}</span>
            </div>
        </div>` : '',
    ].join('');

    qs('#event-modal-body').innerHTML = html;
    qs('#event-modal-title').textContent = `Event — ${e.action || e.source_type || ''}`;
    modal.classList.add('active');
}

function closeModal() {
    const modal = qs('#event-modal');
    if (modal) modal.classList.remove('active');
}

// Close on overlay click
document.addEventListener('click', e => {
    const modal = qs('#event-modal');
    if (modal && e.target === modal) closeModal();
});


// ════════════════════════════════════════════════
// RECORDS PAGE
// ════════════════════════════════════════════════

let recordsPage = 1;

function initRecordsPage() {
    const container = qs('#records-container');
    if (!container) return;

    loadRecords();

    const searchInput = qs('#search-input');
    let searchTimer;
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => { recordsPage = 1; loadRecords(); }, 400);
        });
    }

    const sourceFilter = qs('#source-filter');
    if (sourceFilter) {
        sourceFilter.addEventListener('change', () => { recordsPage = 1; loadRecords(); });
    }

    const clearBtn = qs('#clear-records-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            if (!confirm('Delete ALL stored records? This cannot be undone.')) return;
            const resp = await fetch('/api/records', { method: 'DELETE' });
            const data = await resp.json();
            if (data.success) { recordsPage = 1; loadRecords(); }
        });
    }
}

async function loadRecords() {
    const search = (qs('#search-input') || {}).value || '';
    const source = (qs('#source-filter') || {}).value || '';

    const params = new URLSearchParams({
        page: recordsPage, per_page: 50,
        search, source_type: source,
    });

    const spinner = qs('#records-spinner');
    if (spinner) spinner.classList.add('active');

    try {
        const resp = await fetch('/api/records?' + params);
        const data = await resp.json();
        renderRecordsTable(data);
        renderPagination(data.page, data.pages, data.total);
    } catch (e) {
        console.error(e);
    } finally {
        if (spinner) spinner.classList.remove('active');
    }
}

function renderRecordsTable(data) {
    const tbody = qs('#records-tbody');
    if (!tbody) return;

    const records = data.records || [];
    if (!records.length) {
        tbody.innerHTML = `<tr><td colspan="8">
            <div class="empty-state">
                <div class="empty-icon">📭</div>
                <div class="empty-title">No records found</div>
                <div class="empty-sub">Normalize a log file to populate the database.</div>
            </div></td></tr>`;
        return;
    }

    tbody.innerHTML = records.map(rec => {
        const cat = rec.category ? JSON.parse(rec.category || '[]').join(', ') : '';
        const sev = rec.severity || 0;
        return `<tr>
            <td><span class="source-badge ${rec.source_type||''}">${escapeHtml(rec.source_type||'')}</span></td>
            <td class="truncate">${escapeHtml((rec.created_at||'').replace('T',' ').replace('Z',''))}</td>
            <td class="truncate">${escapeHtml(rec.host_name||'')}</td>
            <td>${escapeHtml(cat)}</td>
            <td class="truncate">${escapeHtml(rec.event_action||'')}</td>
            <td><span class="sev-dot ${sevClass(sev)}"></span>${sev}</td>
            <td class="truncate">${escapeHtml(rec.process_name || rec.user_name || rec.src_ip || '')}</td>
            <td>
                <button class="btn btn-secondary" style="padding:4px 10px;font-size:11px;"
                        onclick="fetchAndShowEvent('${escapeHtml(rec.event_id)}')">View</button>
            </td>
        </tr>`;
    }).join('');
}

function renderPagination(page, pages, total) {
    const pg = qs('#pagination');
    if (!pg) return;
    pg.innerHTML = `
        <span>${total} records</span>
        <button class="page-btn" onclick="changePage(${page-1})" ${page<=1?'disabled':''}>&#8249;</button>
        <span>Page ${page} of ${pages}</span>
        <button class="page-btn" onclick="changePage(${page+1})" ${page>=pages?'disabled':''}>&#8250;</button>
    `;
}

function changePage(n) {
    if (n < 1) return;
    recordsPage = n;
    loadRecords();
}

// ── Init on page load ──
document.addEventListener('DOMContentLoaded', () => {
    initUploadPage();
    initRecordsPage();
});
