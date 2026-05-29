/**
 * Scan Agent Web - JavaScript Application
 * ========================================
 * Maneja la interacción con la API y la UI
 */

// Configuración
const API_BASE = '/api';
let currentScanId = null;
let selectedProfile = null;
let pollInterval = null;
let manualLoaded = false;

// ============================================
// Inicialización
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadProfiles();
    setupFormHandlers();
    loadScansHistory();
});

// ============================================
// Navegación
// ============================================

function initNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const pageId = btn.dataset.page;
            showPage(pageId);
            
            // Actualizar botones activos
            navButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        });
    });
}

function showPage(pageId) {
    const pages = document.querySelectorAll('.page');
    pages.forEach(page => page.classList.remove('active'));

    const targetPage = document.getElementById(`${pageId}-page`);
    if (targetPage) {
        targetPage.classList.add('active');

        if (pageId === 'history') {
            loadScansHistory();
        } else if (pageId === 'manual') {
            loadManual();
        } else if (pageId === 'dashboard') {
            loadDashboard();
        }
    }
}

// ============================================
// Manual de Usuario
// ============================================

async function loadManual() {
    if (manualLoaded) return;

    const content = document.getElementById('manual-content');
    const tocList = document.getElementById('toc-list');

    try {
        const response = await fetch(`${API_BASE}/manual`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();

        // Render HTML content
        content.innerHTML = data.html || '<p class="info-text">Manual no disponible.</p>';

        // Build TOC
        if (data.toc && data.toc.length > 0) {
            tocList.innerHTML = data.toc.map(item => `
                <a class="toc-item toc-level-${item.level}" href="#${item.anchor}">
                    ${item.title}
                </a>
            `).join('');
        } else {
            tocList.innerHTML = '';
        }

        manualLoaded = true;

        // Highlight code blocks if any
        content.querySelectorAll('pre code').forEach(block => {
            block.classList.add('code-block');
        });

    } catch (error) {
        console.error('Error cargando manual:', error);
        content.innerHTML = '<p class="info-text">Error cargando el manual. Verifica que el servidor esté ejecutándose.</p>';
        tocList.innerHTML = '';
    }
}

// ============================================
// Gestión de Perfiles
// ============================================

async function loadProfiles() {
    const grid = document.getElementById('profiles-grid');
    
    try {
        const response = await fetch(`${API_BASE}/profiles/`);
        const profiles = await response.json();
        
        grid.innerHTML = '';
        
        profiles.forEach(profile => {
            const card = createProfileCard(profile);
            grid.appendChild(card);
        });
        
    } catch (error) {
        console.error('Error cargando perfiles:', error);
        grid.innerHTML = '<div class="error">Error cargando perfiles. Verifica que el servidor esté ejecutándose.</div>';
        showToast('Error cargando perfiles', 'error');
    }
}

function createProfileCard(profile) {
    const div = document.createElement('div');
    div.className = 'profile-card';
    div.dataset.profileId = profile.id;
    div.dataset.profile = profile.id;
    
    const badgeClass = profile.id;
    const requiresSudo = profile.requires_sudo ? '🔐 Requiere sudo' : '';
    
    div.innerHTML = `
        <div class="profile-header">
            <div class="profile-name">${profile.name}</div>
            <div style="display:flex;align-items:center;gap:6px;">
                <span class="profile-badge ${badgeClass}">${profile.id}</span>
                <button class="pd-info-btn" title="Ver herramientas y comandos"
                        onclick="event.stopPropagation();showProfileDetail('${profile.id}')">ℹ️ Detalle</button>
            </div>
        </div>
        <div class="profile-description">${profile.description}</div>
        <div class="profile-meta">
            <div>⏱️ Tiempo estimado: ${profile.estimated_time}</div>
            <div>🛠️ Herramientas: ${profile.tools.length}</div>
            ${requiresSudo ? `<div>${requiresSudo}</div>` : ''}
        </div>
        <div class="profile-tools">
            ${profile.tools.map(tool => `<span class="tool-tag">${tool}</span>`).join('')}
        </div>
    `;

    div.addEventListener('click', () => selectProfile(profile.id, div));
    
    return div;
}

function selectProfile(profileId, cardElement) {
    // Remover selección anterior
    document.querySelectorAll('.profile-card').forEach(card => {
        card.classList.remove('selected');
    });

    // Seleccionar nuevo perfil
    cardElement.classList.add('selected');
    selectedProfile = profileId;

    // Mostrar toggle de fases y resetear panel si el perfil cambió
    const toggleContainer = document.getElementById('phases-toggle-container');
    if (toggleContainer) {
        toggleContainer.style.display = 'block';
        if (_phasesLoadedFor !== profileId) {
            _resetPhasesPanel();
        }
    }

    // Mostrar formulario de configuración
    document.getElementById('scan-config-section').style.display = 'block';

    // Scroll suave al formulario
    document.getElementById('scan-config-section').scrollIntoView({
        behavior: 'smooth',
        block: 'start'
    });
}

// ============================================
// Formulario de Escaneo
// ============================================

function setupFormHandlers() {
    const form = document.getElementById('scan-form');
    const resetBtn = document.getElementById('reset-form-btn');
    const newScanBtn = document.getElementById('new-scan-btn');

    form.addEventListener('submit', handleScanSubmit);
    resetBtn.addEventListener('click', resetForm);
    newScanBtn?.addEventListener('click', resetAll);
    document.getElementById('view-report-btn')?.addEventListener('click', () => {
        if (currentScanId) viewScanReport(currentScanId);
    });
    document.getElementById('cancel-scan-btn')?.addEventListener('click', () => {
        // Leer el ID del DOM por si currentScanId es null (ej: tras recargar página)
        const id = currentScanId || document.getElementById('current-scan-id')?.textContent?.trim();
        if (id && id !== '-') cancelScan(id);
        else showToast('No hay escaneo activo para cancelar', 'warning');
    });

    // Validación en tiempo real del campo target
    const targetInput = document.getElementById('target');
    targetInput.addEventListener('input', validateTarget);
}

async function cancelScan(scanId) {
    const cancelBtn = document.getElementById('cancel-scan-btn');
    if (cancelBtn) { cancelBtn.disabled = true; cancelBtn.textContent = '⏳ Cancelando...'; }
    try {
        const r = await fetch(`${API_BASE}/scans/${scanId}`, { method: 'DELETE' });
        const data = await r.json();
        if (!r.ok) {
            showToast(data.detail || 'Error al cancelar', 'error');
            if (cancelBtn) { cancelBtn.disabled = false; cancelBtn.innerHTML = '<span class="icon">⛔</span> Cancelar Escaneo'; }
            return;
        }
        showToast(`Escaneo ${scanId} cancelado`, 'warning');
        if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
        document.getElementById('scan-progress-section').style.display = 'none';
        document.getElementById('scan-config-section').style.display = 'block';
        const btn = document.getElementById('start-scan-btn');
        if (btn) { btn.disabled = false; btn.innerHTML = '<span class="icon">▶️</span> Iniciar Escaneo'; }
        if (cancelBtn) { cancelBtn.disabled = false; cancelBtn.innerHTML = '<span class="icon">⛔</span> Cancelar Escaneo'; }
        if (typeof window.pollActiveScans === 'function') window.pollActiveScans();
    } catch (e) {
        showToast('Error al cancelar el escaneo', 'error');
        if (cancelBtn) { cancelBtn.disabled = false; cancelBtn.innerHTML = '<span class="icon">⛔</span> Cancelar Escaneo'; }
    }
}

function validateTarget(e) {
    const input = e.target;
    const error = document.getElementById('target-error');
    
    if (!input.value) {
        error.style.display = 'none';
        return;
    }
    
    const isValid = input.checkValidity();
    
    if (!isValid) {
        error.textContent = 'Ingresa una dirección IP válida o un nombre de dominio';
        error.style.display = 'block';
    } else {
        error.style.display = 'none';
    }
}

async function handleScanSubmit(e) {
    e.preventDefault();
    
    if (!selectedProfile) {
        showToast('Por favor selecciona un perfil de escaneo', 'error');
        return;
    }
    
    const formData = new FormData(e.target);
    const target = formData.get('target');
    
    // Obtener formatos seleccionados
    const formats = [];
    formData.getAll('format').forEach(fmt => formats.push(fmt));
    
    if (formats.length === 0) {
        showToast('Selecciona al menos un formato de reporte', 'error');
        return;
    }
    
    const saveToDb = document.getElementById('save-to-db').checked;
    
    const selectedSteps = _getSelectedStepsPayload();
    const scanRequest = {
        target: target,
        profile: selectedProfile,
        output_formats: formats,
        save_to_db: saveToDb,
        selected_steps: selectedSteps,
    };
    
    try {
        // Deshabilitar botón
        const submitBtn = document.getElementById('start-scan-btn');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="icon">⏳</span> Iniciando...';
        
        const response = await fetch(`${API_BASE}/scans/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(scanRequest)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Error iniciando escaneo');
        }
        
        const result = await response.json();
        currentScanId = result.scan_id;
        
        showToast('Escaneo iniciado correctamente', 'success');
        
        // Mostrar sección de progreso
        showProgressSection(result);
        
        // Iniciar polling de estado
        startProgressPolling(currentScanId);
        
    } catch (error) {
        console.error('Error:', error);
        showToast(error.message, 'error');
        
        // Re-habilitar botón
        const submitBtn = document.getElementById('start-scan-btn');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span class="icon">▶️</span> Iniciar Escaneo';
    }
}

function resetForm() {
    document.getElementById('scan-form').reset();
    document.getElementById('target-error').style.display = 'none';
}

function resetAll() {
    resetForm();
    selectedProfile = null;
    currentScanId = null;

    // Remover selección de perfiles
    document.querySelectorAll('.profile-card').forEach(card => {
        card.classList.remove('selected');
    });

    // Resetear panel de fases
    _resetPhasesPanel();
    const toggleContainer = document.getElementById('phases-toggle-container');
    if (toggleContainer) toggleContainer.style.display = 'none';
    
    // Ocultar secciones
    document.getElementById('scan-config-section').style.display = 'none';
    document.getElementById('scan-progress-section').style.display = 'none';
    document.getElementById('scan-results-section').style.display = 'none';
    const discoveredSection = document.getElementById('discovered-hosts-section');
    if (discoveredSection) discoveredSection.style.display = 'none';
    // Limpiar lista de etapas
    const stepsList = document.getElementById('scan-steps-list');
    if (stepsList) { stepsList.innerHTML = ''; stepsList.style.display = 'none'; }
    
    // Re-habilitar botón
    const submitBtn = document.getElementById('start-scan-btn');
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span class="icon">▶️</span> Iniciar Escaneo';
    
    // Scroll al inicio
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ============================================
// Progreso del Escaneo
// ============================================

function showProgressSection(scanStatus) {
    // Ocultar formulario
    document.getElementById('scan-config-section').style.display = 'none';

    // Restaurar botón cancelar (pudo haber quedado oculto del scan anterior)
    const cancelBtn = document.getElementById('cancel-scan-btn');
    if (cancelBtn) { cancelBtn.style.display = ''; cancelBtn.disabled = false; cancelBtn.innerHTML = '<span class="icon">⛔</span> Cancelar Escaneo'; }

    // Mostrar progreso
    const section = document.getElementById('scan-progress-section');
    section.style.display = 'block';
    
    // Actualizar información
    document.getElementById('current-scan-id').textContent = scanStatus.scan_id;
    document.getElementById('current-target').textContent = scanStatus.target;
    document.getElementById('current-profile').textContent = scanStatus.profile;
    
    updateProgress(scanStatus);
    
    // Scroll a la sección
    section.scrollIntoView({ behavior: 'smooth' });
}

function updateProgress(scanStatus) {
    const progressFill = document.getElementById('progress-fill');
    const statusText = document.getElementById('scan-status-text');
    const percentage = document.getElementById('scan-percentage');

    progressFill.style.width = `${scanStatus.progress}%`;
    statusText.textContent = scanStatus.message;
    percentage.textContent = `${scanStatus.progress}%`;

    if (scanStatus.steps && scanStatus.steps.length > 0) {
        renderSteps(scanStatus.steps);
    }
}

const _STEP_ICONS = {
    pending:   '○',
    running:   '▶',
    retrying:  '↻',
    completed: '✓',
    failed:    '✗',
    skipped:   '—',
    aborted:   '⊘',
};
const _STEP_LABELS = {
    pending:   'pendiente',
    running:   'ejecutando...',
    retrying:  'reintentando...',
    completed: 'completado',
    failed:    'falló',
    skipped:   'omitida',
    aborted:   'no ejecutada',
};

function renderSteps(steps) {
    const container = document.getElementById('scan-steps-list');
    if (!container) return;
    container.style.display = 'flex';

    container.innerHTML = steps.map(s => {
        const icon  = _STEP_ICONS[s.status]  || '?';
        const label = _STEP_LABELS[s.status] || s.status;
        const num   = s.orig_index + 1;
        return `<div class="scan-step ${s.status}">
            <span class="step-icon">${icon}</span>
            <span class="step-label">Paso ${num}: <strong>${s.tool}</strong></span>
            <span class="step-badge">${label}</span>
        </div>`;
    }).join('');
}

function startProgressPolling(scanId) {
    // Limpiar polling anterior si existe
    if (pollInterval) {
        clearInterval(pollInterval);
    }
    
    // Polling cada 2 segundos
    pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE}/scans/status/${scanId}`);
            if (!response.ok) return;
            const status = await response.json();

            updateProgress(status);

            // Si completó o falló, detener polling
            if (status.status === 'completed') {
                clearInterval(pollInterval);
                pollInterval = null;
                showResults(scanId);
            } else if (status.status === 'failed') {
                clearInterval(pollInterval);
                pollInterval = null;
                showToast(`Escaneo fallido: ${status.message}`, 'error');
            } else if (status.status === 'cancelled') {
                clearInterval(pollInterval);
                pollInterval = null;
                document.getElementById('scan-progress-section').style.display = 'none';
                document.getElementById('scan-config-section').style.display = 'block';
                const btn = document.getElementById('start-scan-btn');
                if (btn) { btn.disabled = false; btn.innerHTML = '<span class="icon">▶️</span> Iniciar Escaneo'; }
            }

        } catch (error) {
            console.error('Error polling status:', error);
        }
    }, 2000);
}

async function showResults(scanId) {
    // Mantener la sección de progreso visible (con las etapas en estado final)
    // Solo ocultar el botón de cancelar (ya no aplica)
    const cancelBtn = document.getElementById('cancel-scan-btn');
    if (cancelBtn) cancelBtn.style.display = 'none';

    // Mostrar resultados
    const section = document.getElementById('scan-results-section');
    const content = document.getElementById('scan-results-content');
    
    try {
        const response = await fetch(`${API_BASE}/reports/${scanId}/preview`);
        const data = await response.json();
        
        const vulnCount = data.vulnerabilities?.length || 0;
        const severity = analyzeSeverity(data.vulnerabilities || []);
        const activeHosts = data.active_hosts || [];
        const hostsCard = activeHosts.length > 0
            ? `<div class="stat-card">
                    <div class="stat-value" style="color: var(--info-color, #3498db);">${activeHosts.length}</div>
                    <div class="stat-label">Hosts Activos</div>
               </div>`
            : '';

        content.innerHTML = `
            <div class="results-summary">
                <div class="stat-card">
                    <div class="stat-value">${vulnCount}</div>
                    <div class="stat-label">Vulnerabilidades Encontradas</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--danger-color);">${severity.critical + severity.high}</div>
                    <div class="stat-label">Críticas y Altas</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--warning-color);">${severity.medium}</div>
                    <div class="stat-label">Medias</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--success-color);">${severity.low}</div>
                    <div class="stat-label">Bajas</div>
                </div>
                ${hostsCard}
            </div>
        `;
        
        section.style.display = 'block';
        section.scrollIntoView({ behavior: 'smooth' });

        showToast('Escaneo completado exitosamente', 'success');

        // Cargar hosts descubiertos (solo relevant en escaneos de red CIDR)
        if (typeof loadDiscoveredHosts === 'function') {
            loadDiscoveredHosts(scanId);
        }

    } catch (error) {
        content.innerHTML = '<p class="info-text">Resultados generados. Descarga el reporte para ver los detalles.</p>';
        section.style.display = 'block';

        if (typeof loadDiscoveredHosts === 'function') {
            loadDiscoveredHosts(scanId);
        }
    }
}

function analyzeSeverity(vulnerabilities) {
    const severity = { critical: 0, high: 0, medium: 0, low: 0 };
    
    vulnerabilities.forEach(vuln => {
        const sev = (vuln.severity || '').toLowerCase();
        if (sev.includes('critical') || sev.includes('crítico')) severity.critical++;
        else if (sev.includes('high') || sev.includes('alto')) severity.high++;
        else if (sev.includes('medium') || sev.includes('medio')) severity.medium++;
        else severity.low++;
    });
    
    return severity;
}

// ============================================
// Historial de Escaneos
// ============================================

async function loadScansHistory() {
    const tbody = document.getElementById('scans-tbody');
    
    try {
        const response = await fetch(`${API_BASE}/scans/list?limit=50`);
        const scans = await response.json();
        
        if (scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="info-text">No hay escaneos registrados</td></tr>';
            return;
        }
        
        tbody.innerHTML = scans.map(scan => {
            const isActive = scan.status === 'running' || scan.status === 'pending';
            const cancelBtn = isActive
                ? `<button class="btn btn-danger btn-sm" onclick="cancelScan('${scan.scan_id}')">⛔ Cancelar</button>`
                : '';
            const reportBtn = scan.status === 'completed'
                ? `<button class="btn btn-secondary btn-sm" onclick="viewScanReport('${scan.scan_id}')">📄 Reporte</button>
                   <select class="btn btn-secondary btn-sm" style="padding:3px 6px;font-size:0.78rem;cursor:pointer;"
                       onchange="if(this.value){viewScanReport('${scan.scan_id}',this.value);this.value='';}">
                       <option value="">🔽 filtrar</option>
                       <option value="CRITICAL">🔴 Crítico</option>
                       <option value="HIGH">🟠 Alto</option>
                       <option value="MEDIUM">🟡 Medio</option>
                       <option value="LOW">🟢 Bajo</option>
                   </select>`
                : '';
            // Fase 13: botón Re-escanear y columna Hallazgos
            const reScanBtn = `<button class="btn btn-secondary btn-sm"
                onclick="reScanFrom('${scan.target.replace(/'/g,"\\'")}','${scan.profile}')"
                title="Rellenar formulario con este objetivo y perfil">↩ Re-escanear</button>`;
            const vulnBadge = (scan.vulnerabilities_count != null)
                ? `<span style="font-weight:600; color:${scan.vulnerabilities_count > 0 ? '#f97316' : '#10b981'};">
                       ${scan.vulnerabilities_count}
                   </span>`
                : '<span style="color:#64748b;">—</span>';
            return `
            <tr>
                <td><code>${scan.scan_id}</code></td>
                <td>${scan.target}</td>
                <td>
                    <span class="profile-badge ${scan.profile}">${scan.profile}</span>
                    ${scan.selected_steps != null
                        ? `<span title="Perfil personalizado — solo ${(scan.selected_steps || []).length} fase(s) ejecutadas"
                            style="margin-left:5px; background:#1e3a5f; color:#93c5fd; border-radius:4px; padding:1px 7px; font-size:0.72rem; cursor:help;">⚙ personalizado</span>`
                        : ''}
                </td>
                <td style="text-align:center;">${vulnBadge}</td>
                <td><span class="status-badge ${scan.status}">${getStatusLabel(scan.status)}</span></td>
                <td>${formatDate(scan.started_at)}</td>
                <td style="display:flex;gap:5px;flex-wrap:wrap;">
                    ${reportBtn}
                    ${cancelBtn}
                    ${reScanBtn}
                    <button class="btn btn-secondary btn-sm" onclick="showProfileDetail('${scan.profile}')">ℹ️ Perfil</button>
                </td>
            </tr>`;
        }).join('');
        
    } catch (error) {
        console.error('Error loading history:', error);
        tbody.innerHTML = '<tr><td colspan="6" class="error">Error cargando historial</td></tr>';
    }
}

function getStatusLabel(status) {
    const labels = {
        'completed': 'Completado',
        'running': 'En ejecución',
        'failed': 'Fallido',
        'pending': 'Pendiente',
        'cancelled': 'Cancelado'
    };
    return labels[status] || status;
}

function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleString('es-ES');
}

function viewScanReport(scanId, severity = null, category = null) {
    let url = `${API_BASE}/reports/${scanId}/download/html`;
    const parts = [];
    if (severity) parts.push(`severity=${encodeURIComponent(severity)}`);
    if (category) parts.push(`category=${encodeURIComponent(category)}`);
    if (parts.length) url += '#' + parts.join('&');
    window.open(url, '_blank');
}

// ============================================
// Modal Detalle de Perfil
// ============================================

function _diffBadgeClass(difficulty) {
    const map = { 'básico': 'pd-badge-diff-basico', 'intermedio': 'pd-badge-diff-intermedio', 'avanzado': 'pd-badge-diff-avanzado' };
    return map[difficulty] || 'pd-badge-opt';
}

function _toggleCmdBody(idx) {
    const body = document.getElementById(`pd-cmd-body-${idx}`);
    const chev = document.getElementById(`pd-cmd-chev-${idx}`);
    if (!body) return;
    const isOpen = body.classList.toggle('open');
    if (chev) chev.classList.toggle('open', isOpen);
}

function _renderCommandCard(cmd, idx) {
    const reqBadge = `<span class="pd-badge ${cmd.required ? 'pd-badge-req' : 'pd-badge-opt'}">${cmd.required ? 'Requerido' : 'Opcional'}</span>`;
    const sudoBadge = cmd.sudo ? `<span class="pd-badge pd-badge-sudo">sudo</span>` : '';
    const timeBadge = `<span class="pd-badge pd-badge-time">${cmd.timeout_seconds}s</span>`;
    const diffBadge = cmd.difficulty && cmd.difficulty !== '—'
        ? `<span class="pd-badge ${_diffBadgeClass(cmd.difficulty)}">${cmd.difficulty}</span>` : '';

    const findsHtml = (cmd.what_it_finds || []).map(f =>
        `<span class="pd-find-tag">${f}</span>`
    ).join('');

    const owaspHtml = cmd.owasp_ref && cmd.owasp_ref !== '—'
        ? `<div class="pd-owasp-ref">🔗 <strong>OWASP:</strong> ${cmd.owasp_ref}</div>` : '';

    const outputHtml = cmd.output_file
        ? `<div class="pd-cmd-output">📄 Salida: ${cmd.output_file}</div>` : '';

    return `
    <div class="pd-command-row">
        <div class="pd-cmd-summary" onclick="_toggleCmdBody(${idx})">
            <div class="pd-cmd-left">
                <div class="pd-cmd-tool-row">
                    <span class="pd-cmd-tool">${cmd.icon} ${cmd.tool.toUpperCase()}</span>
                    ${reqBadge} ${sudoBadge} ${timeBadge} ${diffBadge}
                </div>
                ${cmd.purpose ? `<div class="pd-cmd-purpose">${cmd.purpose}</div>` : ''}
            </div>
            <span class="pd-cmd-chevron" id="pd-cmd-chev-${idx}">▼</span>
        </div>
        <div class="pd-cmd-body" id="pd-cmd-body-${idx}">
            ${cmd.explanation ? `<p class="pd-cmd-explanation">${cmd.explanation}</p>` : ''}
            ${findsHtml ? `
                <div class="pd-cmd-finds-title">Detecta / Identifica:</div>
                <div class="pd-cmd-finds">${findsHtml}</div>` : ''}
            ${owaspHtml}
            <div class="pd-cmd-finds-title">Comando ejecutado:</div>
            <div class="pd-cmd-full">$ ${cmd.tool} ${cmd.args}</div>
            ${outputHtml}
        </div>
    </div>`;
}

async function showProfileDetail(profileId) {
    const modal = document.getElementById('profile-detail-modal');
    if (!modal) return;

    // Reset
    document.getElementById('pd-name').textContent = 'Cargando...';
    document.getElementById('pd-description').textContent = '';
    document.getElementById('pd-id').textContent = '';
    document.getElementById('pd-time').textContent = '';
    document.getElementById('pd-sudo').textContent = '';
    document.getElementById('pd-commands-list').innerHTML =
        '<div style="color:#64748b;font-size:0.85rem;padding:8px 0;">Cargando...</div>';
    const eduBlock = document.getElementById('pd-edu-block');
    if (eduBlock) eduBlock.style.display = 'none';
    modal.style.display = 'flex';

    try {
        const r = await fetch(`${API_BASE}/profiles/${profileId}/detail`);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const p = await r.json();

        document.getElementById('pd-name').textContent = p.name;
        document.getElementById('pd-description').textContent = p.description;
        document.getElementById('pd-id').textContent = profileId;
        document.getElementById('pd-time').textContent = '⏱️ ' + p.estimated_time;
        document.getElementById('pd-sudo').textContent = p.requires_sudo ? '🔐 Requiere sudo' : '';

        // Bloque educativo del perfil
        const hasEdu = (p.learning_objectives && p.learning_objectives.length) || p.when_to_use || p.limitations;
        if (eduBlock && hasEdu) {
            const objList = document.getElementById('pd-objectives-list');
            if (objList && p.learning_objectives) {
                objList.innerHTML = p.learning_objectives.map(o => `<li>${o}</li>`).join('');
            }
            const whenEl = document.getElementById('pd-when-to-use');
            if (whenEl) whenEl.textContent = p.when_to_use || '';
            const limEl = document.getElementById('pd-limitations');
            if (limEl) limEl.textContent = p.limitations || '';
            eduBlock.style.display = 'block';
        }

        // Comandos
        const list = document.getElementById('pd-commands-list');
        if (!p.commands || !p.commands.length) {
            list.innerHTML = '<div style="color:#64748b;font-size:0.85rem;">Sin comandos definidos</div>';
            return;
        }
        list.innerHTML = p.commands.map((cmd, i) => _renderCommandCard(cmd, i)).join('');

        // Abrir el primer comando por defecto
        if (p.commands.length) _toggleCmdBody(0);

    } catch (e) {
        document.getElementById('pd-name').textContent = 'Error';
        document.getElementById('pd-commands-list').innerHTML =
            `<div style="color:#f87171;font-size:0.85rem;">Error cargando detalle: ${e.message}</div>`;
    }
}

function closeProfileModal() {
    const modal = document.getElementById('profile-detail-modal');
    if (modal) modal.style.display = 'none';
}

document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeProfileModal();
});

// ============================================
// Notificaciones Toast
// ============================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);
    
    // Auto-remover después de 5 segundos
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// ============================================
// Filtros de Historial
// ============================================

document.getElementById('refresh-history-btn')?.addEventListener('click', loadScansHistory);

document.getElementById('search-scans')?.addEventListener('input', filterScans);
document.getElementById('filter-status')?.addEventListener('change', filterScans);

function filterScans() {
    const searchTerm = document.getElementById('search-scans').value.toLowerCase();
    const statusFilter = document.getElementById('filter-status').value;
    const rows = document.querySelectorAll('#scans-tbody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const status = row.querySelector('.status-badge')?.classList[1] || '';
        
        const matchesSearch = text.includes(searchTerm);
        const matchesStatus = !statusFilter || status === statusFilter;
        
        row.style.display = (matchesSearch && matchesStatus) ? '' : 'none';
    });
}

// Agregar estilos adicionales para resultados
const additionalStyles = `
<style>
.results-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1.5rem;
    margin: 1.5rem 0;
}

.stat-card {
    background: var(--bg-color);
    padding: 1.5rem;
    border-radius: var(--radius);
    text-align: center;
}

.stat-value {
    font-size: 2.5rem;
    font-weight: 700;
    color: var(--primary-color);
    margin-bottom: 0.5rem;
}

.stat-label {
    color: var(--text-secondary);
    font-size: 0.9rem;
}

.btn-sm {
    padding: 0.5rem 1rem;
    font-size: 0.85rem;
}
</style>
`;

document.head.insertAdjacentHTML('beforeend', additionalStyles);

// ============================================================
// Fase 10 — Selección manual de fases por escaneo
// ============================================================

let _phasesLoadedFor = null;      // profileId del que se cargaron las fases
let _phasesData = [];             // array de commands del perfil
let _phasesPanelOpen = false;     // estado del panel

function _resetPhasesPanel() {
    _phasesLoadedFor = null;
    _phasesData = [];
    _phasesPanelOpen = false;
    const panel = document.getElementById('phases-panel');
    const icon  = document.getElementById('phases-toggle-icon');
    const list  = document.getElementById('phases-list');
    const summary = document.getElementById('phases-summary-inline');
    if (panel)   panel.style.display = 'none';
    if (icon)    icon.textContent = '▶';
    if (list)    list.innerHTML = '<div style="color:#64748b; font-size:0.82rem;">Cargando fases...</div>';
    if (summary) summary.textContent = '';
    // Restaurar botón de inicio
    _updateStartBtnForPhases(true);
}

async function togglePhasesPanel() {
    const panel = document.getElementById('phases-panel');
    const icon  = document.getElementById('phases-toggle-icon');
    if (!panel) return;

    if (_phasesPanelOpen) {
        panel.style.display = 'none';
        icon.textContent = '▶';
        _phasesPanelOpen = false;
        // Al cerrar sin cambios, restablecer selección total
        _resetPhasesPanel();
        _updateStartBtnForPhases(true);
        return;
    }

    panel.style.display = 'block';
    icon.textContent = '▼';
    _phasesPanelOpen = true;

    if (_phasesLoadedFor !== selectedProfile) {
        await _loadPhasesForProfile(selectedProfile);
    }
    _renderPresets(selectedProfile);
}

async function _loadPhasesForProfile(profileId) {
    const list = document.getElementById('phases-list');
    if (!list || !profileId) return;
    list.innerHTML = '<div style="color:#64748b; font-size:0.82rem;">Cargando fases...</div>';

    try {
        const r = await fetch(`/api/profiles/${profileId}/detail`);
        if (!r.ok) throw new Error('Error ' + r.status);
        const data = await r.json();
        _phasesData = data.commands || [];
        _phasesLoadedFor = profileId;
        _renderPhaseCards(_phasesData);
    } catch (e) {
        list.innerHTML = `<p style="color:#ef4444;font-size:0.82rem;">Error cargando fases: ${e.message}</p>`;
    }
}

const _DIFF_COLORS = { básico: '#22c55e', intermedio: '#eab308', avanzado: '#f97316' };

function _renderPhaseCards(commands) {
    const list = document.getElementById('phases-list');
    if (!list) return;

    list.innerHTML = commands.map((cmd, i) => {
        const estMin = Math.ceil((cmd.timeout_seconds || 120) / 60);
        const isReq  = cmd.required !== false;
        const diffColor = _DIFF_COLORS[cmd.difficulty] || '#94a3b8';
        return `
        <div class="phase-card" id="phase-card-${i}"
            style="background:#0d1824; border:1px solid #1e3a5f; border-radius:8px; padding:10px 14px; display:flex; align-items:flex-start; gap:12px;">
            <input type="checkbox" id="phase-cb-${i}" data-index="${i}" checked
                onchange="_onPhaseToggle(${i})"
                style="width:16px; height:16px; margin-top:3px; accent-color:#3b82f6; cursor:pointer; flex-shrink:0;">
            <div style="flex:1; min-width:0;">
                <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px;">
                    <span style="font-size:1rem;">${cmd.icon || '⚙️'}</span>
                    <span style="font-weight:700; color:#e2e8f0; font-size:0.9rem;">${cmd.tool}</span>
                    ${isReq
                        ? `<span style="background:#1e3a5f; color:#93c5fd; border-radius:4px; padding:1px 8px; font-size:0.72rem;">Requerida</span>`
                        : `<span style="background:#1a2332; color:#64748b; border-radius:4px; padding:1px 8px; font-size:0.72rem;">Opcional</span>`}
                    ${cmd.difficulty ? `<span style="color:${diffColor}; font-size:0.72rem;">${cmd.difficulty}</span>` : ''}
                    <span style="color:#475569; font-size:0.72rem; margin-left:auto;">⏱ ~${estMin} min</span>
                </div>
                <p style="color:#94a3b8; font-size:0.8rem; margin:0 0 2px;">${cmd.purpose || ''}</p>
                ${cmd.owasp_ref ? `<span style="color:#475569; font-size:0.72rem;">${cmd.owasp_ref}</span>` : ''}
                <div id="phase-warn-${i}" style="display:none; margin-top:5px; padding:4px 8px; background:#2d1a00; border:1px solid #78350f; border-radius:4px; font-size:0.78rem; color:#fbbf24;">
                    ⚠️ Esta fase es requerida por el perfil — omitirla puede generar un reporte incompleto.
                </div>
            </div>
        </div>`;
    }).join('');

    _updatePhasesFooter();
}

function _onPhaseToggle(index) {
    const cmd  = _phasesData[index];
    const warn = document.getElementById(`phase-warn-${index}`);
    const cb   = document.getElementById(`phase-cb-${index}`);
    if (warn && cmd && cmd.required !== false) {
        warn.style.display = cb && !cb.checked ? 'block' : 'none';
    }
    _updatePhasesFooter();
}

function _getSelectedIndices() {
    return _phasesData
        .map((_, i) => ({ i, cb: document.getElementById(`phase-cb-${i}`) }))
        .filter(({ cb }) => cb && cb.checked)
        .map(({ i }) => i);
}

function _updatePhasesFooter() {
    const selected = _getSelectedIndices();
    const total    = _phasesData.length;
    const totalSec = selected.reduce((s, i) => s + (_phasesData[i]?.timeout_seconds || 120), 0);
    const totalMin = Math.ceil(totalSec / 60);

    const countEl = document.getElementById('phases-count-label');
    const timeEl  = document.getElementById('phases-time-label');
    const inlineEl = document.getElementById('phases-summary-inline');

    if (countEl) countEl.textContent = `${selected.length} de ${total} fases seleccionadas`;
    if (timeEl)  timeEl.textContent  = `~${totalMin} min estimados`;
    if (inlineEl && _phasesPanelOpen)
        inlineEl.textContent = `${selected.length}/${total} fases · ~${totalMin} min`;

    // Deshabilitar "Iniciar" si 0 seleccionadas
    _updateStartBtnForPhases(selected.length > 0);
}

function _updateStartBtnForPhases(enabled) {
    const btn = document.getElementById('start-scan-btn');
    if (!btn) return;
    if (_phasesPanelOpen && !enabled) {
        btn.disabled = true;
        btn.title = 'Debes seleccionar al menos una fase';
    } else {
        btn.disabled = false;
        btn.title = '';
    }
}

function selectAllPhases(checked) {
    _phasesData.forEach((_, i) => {
        const cb = document.getElementById(`phase-cb-${i}`);
        if (cb) cb.checked = checked;
        const warn = document.getElementById(`phase-warn-${i}`);
        if (warn) warn.style.display = 'none';
    });
    _updatePhasesFooter();
}

// ── Presets en localStorage ───────────────────────────────────────────────

function _presetsKey(profileId) { return `scan_phase_presets_${profileId}`; }

function _getPresets(profileId) {
    try { return JSON.parse(localStorage.getItem(_presetsKey(profileId)) || '[]'); }
    catch (_) { return []; }
}

function _savePresets(profileId, presets) {
    localStorage.setItem(_presetsKey(profileId), JSON.stringify(presets));
}

function savePhasePreset() {
    if (!selectedProfile || !_phasesData.length) return;
    const selected = _getSelectedIndices();
    if (!selected.length) { showToast('Selecciona al menos una fase para guardar el preset', 'warning'); return; }
    const name = window.prompt('Nombre del preset:');
    if (!name || !name.trim()) return;
    const presets = _getPresets(selectedProfile);
    presets.push({ name: name.trim(), steps: selected, created: Date.now() });
    _savePresets(selectedProfile, presets);
    _renderPresets(selectedProfile);
    showToast(`Preset "${name.trim()}" guardado`, 'success');
}

function _applyPreset(steps) {
    _phasesData.forEach((_, i) => {
        const cb = document.getElementById(`phase-cb-${i}`);
        if (cb) cb.checked = steps.includes(i);
        const warn = document.getElementById(`phase-warn-${i}`);
        if (warn) warn.style.display = 'none';
    });
    _updatePhasesFooter();
}

function _deletePreset(profileId, idx) {
    const presets = _getPresets(profileId);
    presets.splice(idx, 1);
    _savePresets(profileId, presets);
    _renderPresets(profileId);
}

function _renderPresets(profileId) {
    const bar = document.getElementById('phases-presets-bar');
    if (!bar) return;
    const presets = _getPresets(profileId);
    if (!presets.length) { bar.style.display = 'none'; return; }
    bar.style.display = 'flex';
    bar.style.cssText += 'gap:8px; flex-wrap:wrap; align-items:center;';
    bar.innerHTML = '<span style="color:#64748b; font-size:0.78rem; white-space:nowrap;">💾 Presets:</span>' +
        presets.map((p, i) => `
            <span style="display:inline-flex; align-items:center; gap:4px; background:#0d1824; border:1px solid #2d4a6e; border-radius:5px; padding:2px 8px 2px 10px; font-size:0.78rem;">
                <button type="button" onclick="_applyPreset([${p.steps.join(',')}])"
                    style="background:none; border:none; color:#93c5fd; cursor:pointer; font-size:0.78rem; padding:0;">
                    ${p.name}
                </button>
                <button type="button" onclick="_deletePreset('${profileId}', ${i})"
                    title="Eliminar preset"
                    style="background:none; border:none; color:#64748b; cursor:pointer; font-size:0.75rem; padding:0 2px;">✕</button>
            </span>`).join('');
}

// ── Integración con el envío del formulario ───────────────────────────────

// ============================================
// Fase 13 — Dashboard de Análisis
// ============================================

let _dashboardLoaded = false;

async function loadDashboard(force = false) {
    if (_dashboardLoaded && !force) return;

    try {
        const r = await fetch(`${API_BASE}/scans/stats`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const data = await r.json();

        // --- Tarjetas métricas ---
        document.getElementById('dash-total-scans').textContent  = data.total_scans ?? 0;
        document.getElementById('dash-total-vulns').textContent  = data.total_vulnerabilities ?? 0;
        const hiCrit = (data.by_severity?.critical ?? 0) + (data.by_severity?.high ?? 0);
        document.getElementById('dash-high-critical').textContent = hiCrit;
        document.getElementById('dash-top-profile').textContent  = data.most_used_profile ?? '—';

        // --- Gráfica de severidad ---
        const sevEl = document.getElementById('dash-severity-chart');
        const sevData = data.by_severity ?? {};
        const sevOrder = [
            { key: 'critical', label: 'Crítica',  cls: 'critical' },
            { key: 'high',     label: 'Alta',     cls: 'high'     },
            { key: 'medium',   label: 'Media',    cls: 'medium'   },
            { key: 'low',      label: 'Baja',     cls: 'low'      },
            { key: 'info',     label: 'Info',     cls: 'info'     },
        ];
        const sevMax = Math.max(1, ...sevOrder.map(s => sevData[s.key] ?? 0));
        if (Object.values(sevData).every(v => v === 0)) {
            sevEl.innerHTML = '<div class="dash-empty">Sin datos de severidad</div>';
        } else {
            sevEl.innerHTML = sevOrder.map(s => {
                const cnt = sevData[s.key] ?? 0;
                const pct = Math.round((cnt / sevMax) * 100);
                return `<div class="dash-bar-row">
                    <div class="dash-bar-label">${s.label}</div>
                    <div class="dash-bar-track">
                        <div class="dash-bar-fill ${s.cls}" style="width:${pct}%"></div>
                    </div>
                    <div class="dash-bar-count">${cnt}</div>
                </div>`;
            }).join('');
        }

        // --- Gráfica de perfiles ---
        const profEl = document.getElementById('dash-profile-chart');
        const profData = data.by_profile ?? {};
        const profEntries = Object.entries(profData).sort((a, b) => b[1] - a[1]).slice(0, 8);
        const profMax = Math.max(1, ...profEntries.map(([, v]) => v));
        if (!profEntries.length) {
            profEl.innerHTML = '<div class="dash-empty">Sin datos de perfiles</div>';
        } else {
            profEl.innerHTML = profEntries.map(([name, cnt]) => {
                const pct = Math.round((cnt / profMax) * 100);
                return `<div class="dash-bar-row">
                    <div class="dash-bar-label" style="text-align:right; font-size:0.78rem;">${name}</div>
                    <div class="dash-bar-track">
                        <div class="dash-bar-fill profile" style="width:${pct}%"></div>
                    </div>
                    <div class="dash-bar-count">${cnt}</div>
                </div>`;
            }).join('');
        }

        // --- Top vulnerabilidades ---
        const topEl = document.getElementById('dash-top-vulns-container');
        const topVulns = data.top_vulnerabilities ?? [];
        if (!topVulns.length) {
            topEl.innerHTML = '<div class="dash-empty">No hay escaneos completados aún</div>';
        } else {
            topEl.innerHTML = `<table class="dash-table">
                <thead><tr><th>#</th><th>Vulnerabilidad</th><th style="text-align:right;">Ocurrencias</th></tr></thead>
                <tbody>
                ${topVulns.map((v, i) => `
                    <tr>
                        <td style="color:#64748b; width:28px;">${i + 1}</td>
                        <td><div class="dash-vuln-name" title="${v.name}">${v.name}</div></td>
                        <td style="text-align:right;"><span class="dash-count-badge">${v.count}</span></td>
                    </tr>`).join('')}
                </tbody>
            </table>`;
        }

        // --- Actividad reciente ---
        const recentEl = document.getElementById('dash-recent-container');
        const recent = data.recent_scans ?? [];
        if (!recent.length) {
            recentEl.innerHTML = '<div class="dash-empty">Sin actividad reciente</div>';
        } else {
            recentEl.innerHTML = `<table class="dash-table">
                <thead><tr><th>ID</th><th>Objetivo</th><th>Perfil</th><th style="text-align:right;">Hallazgos</th></tr></thead>
                <tbody>
                ${recent.map(s => `
                    <tr>
                        <td><code style="font-size:0.8rem;">${s.scan_id}</code></td>
                        <td style="max-width:120px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${s.target}</td>
                        <td><span class="profile-badge ${s.profile}" style="font-size:0.72rem;">${s.profile}</span></td>
                        <td style="text-align:right; font-weight:600; color:${s.vuln_count > 0 ? '#f97316' : '#10b981'};">${s.vuln_count}</td>
                    </tr>`).join('')}
                </tbody>
            </table>`;
        }

        _dashboardLoaded = true;

    } catch (err) {
        console.error('Error cargando dashboard:', err);
        ['dash-severity-chart','dash-profile-chart','dash-top-vulns-container','dash-recent-container'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = `<div class="dash-empty" style="color:#ef4444;">Error cargando datos</div>`;
        });
    }
}

// ============================================
// Fase 13 — Re-escanear desde historial
// ============================================

function reScanFrom(target, profile) {
    // 1. Cambiar a la página Scanner
    showPage('scanner');
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    const scannerBtn = document.querySelector('[data-page="scanner"]');
    if (scannerBtn) scannerBtn.classList.add('active');

    // 2. Seleccionar la tarjeta del perfil
    const card = document.querySelector(`.profile-card[data-profile="${profile}"]`);
    if (card) {
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        selectProfile(profile, card);
    }

    // 3. Rellenar el target
    const targetInput = document.getElementById('target');
    if (targetInput) {
        targetInput.value = target;
        targetInput.dispatchEvent(new Event('input')); // trigger validation
    }

    // 4. Mostrar el formulario y hacer scroll
    const configSection = document.getElementById('scan-config-section');
    if (configSection) {
        configSection.style.display = 'block';
        setTimeout(() => configSection.scrollIntoView({ behavior: 'smooth', block: 'start' }), 250);
    }

    showToast(`Re-escaneo listo: ${target} con perfil "${profile}"`, 'success');
}

// ── Integración con el envío del formulario ───────────────────────────────

function _getSelectedStepsPayload() {
    if (!_phasesPanelOpen || !_phasesData.length) return null;
    const selected = _getSelectedIndices();
    // Si todos están seleccionados, enviar null (equivale a perfil completo)
    if (selected.length === _phasesData.length) return null;
    return selected;
}
