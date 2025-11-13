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
        
        // Cargar datos específicos de la página
        if (pageId === 'history') {
            loadScansHistory();
        }
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
    
    const badgeClass = profile.id;
    const requiresSudo = profile.requires_sudo ? '🔐 Requiere sudo' : '';
    
    div.innerHTML = `
        <div class="profile-header">
            <div class="profile-name">${profile.name}</div>
            <span class="profile-badge ${badgeClass}">${profile.id}</span>
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
    
    // Validación en tiempo real del campo target
    const targetInput = document.getElementById('target');
    targetInput.addEventListener('input', validateTarget);
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
    
    const scanRequest = {
        target: target,
        profile: selectedProfile,
        output_formats: formats,
        save_to_db: saveToDb
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
    
    // Ocultar secciones
    document.getElementById('scan-config-section').style.display = 'none';
    document.getElementById('scan-progress-section').style.display = 'none';
    document.getElementById('scan-results-section').style.display = 'none';
    
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
            const status = await response.json();
            
            updateProgress(status);
            
            // Si completó o falló, detener polling
            if (status.status === 'completed') {
                clearInterval(pollInterval);
                showResults(scanId);
            } else if (status.status === 'failed') {
                clearInterval(pollInterval);
                showToast(`Escaneo fallido: ${status.message}`, 'error');
            }
            
        } catch (error) {
            console.error('Error polling status:', error);
        }
    }, 2000);
}

async function showResults(scanId) {
    // Ocultar progreso
    document.getElementById('scan-progress-section').style.display = 'none';
    
    // Mostrar resultados
    const section = document.getElementById('scan-results-section');
    const content = document.getElementById('scan-results-content');
    
    try {
        const response = await fetch(`${API_BASE}/reports/${scanId}/preview`);
        const data = await response.json();
        
        const vulnCount = data.vulnerabilities?.length || 0;
        const severity = analyzeSeverity(data.vulnerabilities || []);
        
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
            </div>
        `;
        
        section.style.display = 'block';
        section.scrollIntoView({ behavior: 'smooth' });
        
        showToast('Escaneo completado exitosamente', 'success');
        
    } catch (error) {
        content.innerHTML = '<p class="info-text">Resultados generados. Descarga el reporte para ver los detalles.</p>';
        section.style.display = 'block';
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
        
        tbody.innerHTML = scans.map(scan => `
            <tr>
                <td><code>${scan.scan_id}</code></td>
                <td>${scan.target}</td>
                <td><span class="profile-badge ${scan.profile}">${scan.profile}</span></td>
                <td><span class="status-badge ${scan.status}">${getStatusLabel(scan.status)}</span></td>
                <td>${formatDate(scan.started_at)}</td>
                <td>
                    <button class="btn btn-secondary btn-sm" onclick="viewScanReport('${scan.scan_id}')">
                        Ver Reporte
                    </button>
                </td>
            </tr>
        `).join('');
        
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

async function viewScanReport(scanId) {
    window.open(`${API_BASE}/reports/${scanId}/download/html`, '_blank');
}

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
