-- ========================================
-- Scan Agent v2.0 - Database Schema
-- ========================================
-- SQLite Database Schema for storing scan results and analysis
-- Version: 2.1.0
-- Date: 2025-11-12

-- ========================================
-- Table: scans
-- ========================================
-- Stores metadata for each scan performed
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip TEXT NOT NULL,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    profile_used TEXT NOT NULL,
    duration_seconds INTEGER,
    status TEXT NOT NULL CHECK(status IN ('completed', 'failed', 'partial')),
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    max_cvss_score REAL DEFAULT 0.0,
    files_processed INTEGER DEFAULT 0,
    tools_used TEXT, -- Comma-separated list: "nmap,nikto,gobuster"
    scan_type TEXT, -- "active" or "passive"
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================================
-- Table: parsed_data
-- ========================================
-- Stores raw parsed JSON data for each scan
CREATE TABLE IF NOT EXISTS parsed_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    data_type TEXT NOT NULL CHECK(data_type IN ('parsed', 'analysis', 'raw')),
    json_data TEXT NOT NULL, -- Full JSON as TEXT
    file_path TEXT, -- Original file path if applicable
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ========================================
-- Table: vulnerabilities
-- ========================================
-- Stores individual vulnerabilities detected
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    cvss_score REAL,
    cvss_vector TEXT,
    category TEXT, -- OWASP category or vulnerability type
    owasp_mapping TEXT, -- e.g., "A01:2021-Broken Access Control"
    cve_id TEXT, -- CVE identifier if available
    affected_component TEXT, -- Port, service, endpoint affected
    evidence TEXT, -- Specific evidence from scan
    recommendation TEXT,
    references TEXT, -- URLs or documentation references
    false_positive BOOLEAN DEFAULT 0,
    verified BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ========================================
-- Table: services
-- ========================================
-- Stores discovered services and ports
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL, -- tcp/udp
    service_name TEXT,
    service_version TEXT,
    state TEXT, -- open/closed/filtered
    banner TEXT,
    extra_info TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ========================================
-- Table: endpoints
-- ========================================
-- Stores discovered web endpoints and directories
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    method TEXT DEFAULT 'GET',
    content_length INTEGER,
    discovered_by TEXT, -- Tool that found it: gobuster, nikto, etc.
    response_time_ms INTEGER,
    is_vulnerable BOOLEAN DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ========================================
-- Table: headers
-- ========================================
-- Stores HTTP headers analysis
CREATE TABLE IF NOT EXISTS headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT,
    is_security_header BOOLEAN DEFAULT 0,
    is_missing BOOLEAN DEFAULT 0, -- For recommended headers that are missing
    risk_level TEXT CHECK(risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ========================================
-- Table: scan_files
-- ========================================
-- Maps scan to generated files
CREATE TABLE IF NOT EXISTS scan_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    file_type TEXT NOT NULL CHECK(file_type IN ('nmap_service', 'nmap_nse', 'nikto', 'gobuster', 'curl', 'headers', 'report_txt', 'report_json', 'report_html', 'report_md')),
    file_path TEXT NOT NULL,
    file_size_bytes INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ========================================
-- Table: targets
-- ========================================
-- Stores unique targets scanned (for quick lookup)
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    hostname TEXT,
    first_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_scans INTEGER DEFAULT 1,
    last_scan_id INTEGER,
    notes TEXT,
    FOREIGN KEY (last_scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

-- ========================================
-- INDEXES
-- ========================================
-- Performance optimization indexes

-- Scans table indexes
CREATE INDEX IF NOT EXISTS idx_scans_target_ip ON scans(target_ip);
CREATE INDEX IF NOT EXISTS idx_scans_scan_date ON scans(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_profile ON scans(profile_used);

-- Vulnerabilities table indexes
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);

-- Services table indexes
CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);

-- Endpoints table indexes
CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);

-- Headers table indexes
CREATE INDEX IF NOT EXISTS idx_headers_scan_id ON headers(scan_id);

-- Scan files table indexes
CREATE INDEX IF NOT EXISTS idx_scan_files_scan_id ON scan_files(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_files_type ON scan_files(file_type);

-- Targets table indexes
CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip_address);
CREATE INDEX IF NOT EXISTS idx_targets_last_scanned ON targets(last_scanned DESC);

-- ========================================
-- VIEWS
-- ========================================
-- Useful views for common queries

-- Recent scans view
CREATE VIEW IF NOT EXISTS v_recent_scans AS
SELECT 
    s.id,
    s.target_ip,
    s.scan_date,
    s.profile_used,
    s.status,
    s.total_vulnerabilities,
    s.critical_count,
    s.high_count,
    s.medium_count,
    s.low_count,
    s.max_cvss_score,
    t.hostname
FROM scans s
LEFT JOIN targets t ON s.target_ip = t.ip_address
ORDER BY s.scan_date DESC;

-- Critical vulnerabilities view
CREATE VIEW IF NOT EXISTS v_critical_vulnerabilities AS
SELECT 
    v.id,
    v.scan_id,
    s.target_ip,
    s.scan_date,
    v.title,
    v.severity,
    v.cvss_score,
    v.category,
    v.cve_id,
    v.affected_component
FROM vulnerabilities v
JOIN scans s ON v.scan_id = s.id
WHERE v.severity IN ('CRITICAL', 'HIGH')
ORDER BY v.cvss_score DESC, s.scan_date DESC;

-- Target summary view
CREATE VIEW IF NOT EXISTS v_target_summary AS
SELECT 
    t.ip_address,
    t.hostname,
    t.total_scans,
    t.first_scanned,
    t.last_scanned,
    s.profile_used as last_profile,
    s.total_vulnerabilities as last_vulns,
    s.max_cvss_score as last_max_cvss
FROM targets t
LEFT JOIN scans s ON t.last_scan_id = s.id
ORDER BY t.last_scanned DESC;

-- ========================================
-- TRIGGERS
-- ========================================
-- Automatic timestamp updates

-- Update scans.updated_at on UPDATE
CREATE TRIGGER IF NOT EXISTS trigger_scans_updated_at
AFTER UPDATE ON scans
FOR EACH ROW
BEGIN
    UPDATE scans SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Update targets table when new scan is inserted
CREATE TRIGGER IF NOT EXISTS trigger_update_targets_on_scan
AFTER INSERT ON scans
FOR EACH ROW
BEGIN
    INSERT INTO targets (ip_address, first_scanned, last_scanned, total_scans, last_scan_id)
    VALUES (NEW.target_ip, NEW.scan_date, NEW.scan_date, 1, NEW.id)
    ON CONFLICT(ip_address) DO UPDATE SET
        last_scanned = NEW.scan_date,
        total_scans = total_scans + 1,
        last_scan_id = NEW.id;
END;

-- ========================================
-- INITIAL DATA / SEED (Optional)
-- ========================================
-- Uncomment to insert sample data for testing

-- INSERT INTO scans (target_ip, profile_used, duration_seconds, status, total_vulnerabilities, critical_count, high_count, medium_count, low_count, max_cvss_score)
-- VALUES ('192.168.1.100', 'quick', 300, 'completed', 15, 2, 5, 6, 2, 9.8);

-- ========================================
-- UTILITY QUERIES
-- ========================================

-- Get all scans for a specific IP (ordered by date DESC)
-- SELECT * FROM scans WHERE target_ip = '192.168.1.100' ORDER BY scan_date DESC;

-- Get all vulnerabilities for a scan
-- SELECT * FROM vulnerabilities WHERE scan_id = 1 ORDER BY cvss_score DESC;

-- Get scan statistics
-- SELECT 
--     COUNT(*) as total_scans,
--     COUNT(DISTINCT target_ip) as unique_targets,
--     SUM(total_vulnerabilities) as total_vulns,
--     AVG(max_cvss_score) as avg_max_cvss
-- FROM scans WHERE status = 'completed';

-- Find targets with critical vulnerabilities
-- SELECT DISTINCT s.target_ip, COUNT(v.id) as critical_count
-- FROM scans s
-- JOIN vulnerabilities v ON s.id = v.scan_id
-- WHERE v.severity = 'CRITICAL'
-- GROUP BY s.target_ip
-- ORDER BY critical_count DESC;

-- ========================================
-- MAINTENANCE
-- ========================================

-- Delete old scans (older than 90 days)
-- DELETE FROM scans WHERE scan_date < datetime('now', '-90 days');

-- Vacuum database to reclaim space
-- VACUUM;

-- Analyze database for query optimization
-- ANALYZE;
