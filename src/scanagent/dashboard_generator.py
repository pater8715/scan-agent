#!/usr/bin/env python3
"""
dashboard_generator.py - Dashboard HTML Generator for Scan Agent v2.1
=====================================================================

Generates interactive HTML dashboard with scan history organized by IP
and chronological timeline.

Features:
- Lists all scanned targets (IPs)
- Timeline view of scans per target
- Click on scan to view detailed report
- Severity-based color coding
- Responsive design
- No external dependencies (vanilla HTML/CSS/JS)

Author: Scan Agent Team
Version: 2.1.0
Date: 2025-11-12
"""

from datetime import datetime
from typing import List, Dict, Any
import os


class DashboardGenerator:
    """Generates HTML dashboard from database scan data."""
    
    # Color schemes for severity levels
    SEVERITY_COLORS = {
        'CRITICAL': '#dc3545',  # Red
        'HIGH': '#fd7e14',      # Orange
        'MEDIUM': '#ffc107',    # Yellow
        'LOW': '#0dcaf0',       # Blue
        'INFO': '#198754'       # Green
    }
    
    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize dashboard generator.
        
        Args:
            output_dir: Directory to save dashboard HTML
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate(
        self,
        targets: List[Dict],
        all_scans: List[Dict],
        output_file: str = "dashboard.html"
    ) -> str:
        """
        Generate complete dashboard HTML.
        
        Args:
            targets: List of target dictionaries from DB
            all_scans: List of all scans from DB
            output_file: Output filename
        
        Returns:
            Path to generated dashboard file
        """
        # Group scans by target IP
        scans_by_ip = self._group_scans_by_ip(all_scans)
        
        # Generate HTML
        html_content = self._generate_html(targets, scans_by_ip)
        
        # Write to file
        output_path = os.path.join(self.output_dir, output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[✓] Dashboard generado: {output_path}")
        return output_path
    
    def _group_scans_by_ip(self, scans: List[Dict]) -> Dict[str, List[Dict]]:
        """Group scans by target IP."""
        grouped = {}
        for scan in scans:
            ip = scan['target_ip']
            if ip not in grouped:
                grouped[ip] = []
            grouped[ip].append(scan)
        
        # Sort each group by date descending
        for ip in grouped:
            grouped[ip].sort(key=lambda s: s['scan_date'], reverse=True)
        
        return grouped
    
    def _generate_html(self, targets: List[Dict], scans_by_ip: Dict[str, List[Dict]]) -> str:
        """Generate complete HTML content."""
        
        stats = self._calculate_stats(targets, scans_by_ip)
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Agent - Dashboard Histórico</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="header-content">
                <h1>🛡️ Scan Agent Dashboard</h1>
                <p class="subtitle">Historial de Escaneos de Vulnerabilidades</p>
                <div class="stats-bar">
                    <div class="stat-item">
                        <span class="stat-label">Objetivos</span>
                        <span class="stat-value">{stats['total_targets']}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Escaneos</span>
                        <span class="stat-value">{stats['total_scans']}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Vulnerabilidades</span>
                        <span class="stat-value">{stats['total_vulns']}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Críticas</span>
                        <span class="stat-value critical">{stats['critical_vulns']}</span>
                    </div>
                </div>
            </div>
        </header>

        <div class="main-content">
            <!-- Sidebar: Target List -->
            <aside class="sidebar">
                <h2>🎯 Objetivos Escaneados</h2>
                <div class="target-list" id="targetList">
                    {self._generate_target_list(targets, scans_by_ip)}
                </div>
            </aside>

            <!-- Main: Scan Timeline -->
            <main class="timeline-container">
                <div id="scanTimeline">
                    {self._generate_all_timelines(targets, scans_by_ip)}
                </div>
            </main>
        </div>
    </div>

    <script>
        {self._get_javascript()}
    </script>
</body>
</html>"""
        
        return html
    
    def _generate_target_list(self, targets: List[Dict], scans_by_ip: Dict) -> str:
        """Generate sidebar target list HTML."""
        html_parts = []
        
        for target in targets:
            ip = target['ip_address']
            scans = scans_by_ip.get(ip, [])
            scan_count = len(scans)
            
            # Get latest scan info
            latest_scan = scans[0] if scans else None
            max_severity = self._get_max_severity(scans) if scans else 'INFO'
            
            last_scanned = target.get('last_scanned', '')
            if last_scanned:
                last_scanned = self._format_datetime(last_scanned)
            
            severity_class = max_severity.lower()
            
            html_parts.append(f"""
                <div class="target-item" data-target="{ip}" onclick="showTarget('{ip}')">
                    <div class="target-header">
                        <span class="target-ip">{ip}</span>
                        <span class="severity-badge {severity_class}">{max_severity}</span>
                    </div>
                    <div class="target-meta">
                        <span>📊 {scan_count} escaneos</span>
                        <span>🕐 {last_scanned}</span>
                    </div>
                </div>
            """)
        
        return '\n'.join(html_parts) if html_parts else '<p class="no-data">No hay objetivos escaneados</p>'
    
    def _generate_all_timelines(self, targets: List[Dict], scans_by_ip: Dict) -> str:
        """Generate timeline sections for all targets."""
        html_parts = []
        
        for target in targets:
            ip = target['ip_address']
            scans = scans_by_ip.get(ip, [])
            
            timeline_html = f"""
                <div class="timeline-section" id="timeline-{ip}" style="display: none;">
                    <div class="timeline-header">
                        <h2>📍 Historial de {ip}</h2>
                        <p>{len(scans)} escaneos realizados</p>
                    </div>
                    <div class="timeline">
                        {self._generate_scan_cards(scans)}
                    </div>
                </div>
            """
            html_parts.append(timeline_html)
        
        # Default view: show first target if exists
        if targets:
            html_parts.append(f"""
                <script>
                    document.addEventListener('DOMContentLoaded', function() {{
                        showTarget('{targets[0]['ip_address']}');
                    }});
                </script>
            """)
        
        return '\n'.join(html_parts) if html_parts else '<p class="no-data">No hay datos para mostrar</p>'
    
    def _generate_scan_cards(self, scans: List[Dict]) -> str:
        """Generate individual scan cards for timeline."""
        html_parts = []
        
        for scan in scans:
            scan_id = scan['id']
            profile = scan['profile_used']
            scan_date = self._format_datetime(scan['scan_date'])
            status = scan['status']
            total_vulns = scan['total_vulnerabilities']
            critical = scan.get('critical_count', 0)
            high = scan.get('high_count', 0)
            medium = scan.get('medium_count', 0)
            low = scan.get('low_count', 0)
            max_cvss = scan.get('max_cvss_score', 0.0)
            
            # Determine overall severity
            if critical > 0:
                severity = 'CRITICAL'
            elif high > 0:
                severity = 'HIGH'
            elif medium > 0:
                severity = 'MEDIUM'
            elif low > 0:
                severity = 'LOW'
            else:
                severity = 'INFO'
            
            severity_class = severity.lower()
            status_class = 'status-' + status
            
            # Report filename (assuming standard naming)
            report_file = f"informe_tecnico_{scan_id}.html"
            
            html_parts.append(f"""
                <div class="scan-card {severity_class}-border">
                    <div class="scan-card-header">
                        <div class="scan-date">
                            <span class="icon">📅</span>
                            <span>{scan_date}</span>
                        </div>
                        <span class="severity-badge {severity_class}">{severity}</span>
                    </div>
                    
                    <div class="scan-card-body">
                        <div class="scan-info">
                            <div class="info-row">
                                <span class="label">Perfil:</span>
                                <span class="value">{profile}</span>
                            </div>
                            <div class="info-row">
                                <span class="label">Estado:</span>
                                <span class="value {status_class}">{status}</span>
                            </div>
                            <div class="info-row">
                                <span class="label">CVSS Máximo:</span>
                                <span class="value cvss-score">{max_cvss:.1f}</span>
                            </div>
                        </div>
                        
                        <div class="vuln-summary">
                            <h4>Vulnerabilidades Detectadas: {total_vulns}</h4>
                            <div class="vuln-bars">
                                {self._generate_vuln_bar('Críticas', critical, 'critical')}
                                {self._generate_vuln_bar('Altas', high, 'high')}
                                {self._generate_vuln_bar('Medias', medium, 'medium')}
                                {self._generate_vuln_bar('Bajas', low, 'low')}
                            </div>
                        </div>
                    </div>
                    
                    <div class="scan-card-footer">
                        <a href="{report_file}" class="btn-view-report" target="_blank">
                            Ver Informe Completo →
                        </a>
                    </div>
                </div>
            """)
        
        return '\n'.join(html_parts)
    
    def _generate_vuln_bar(self, label: str, count: int, severity: str) -> str:
        """Generate vulnerability count bar."""
        if count == 0:
            return f'<div class="vuln-bar"><span class="vuln-label">{label}:</span> <span class="vuln-count">0</span></div>'
        
        return f"""
            <div class="vuln-bar">
                <span class="vuln-label">{label}:</span>
                <span class="vuln-count {severity}">{count}</span>
                <div class="vuln-progress">
                    <div class="vuln-fill {severity}" style="width: {min(count * 10, 100)}%;"></div>
                </div>
            </div>
        """
    
    def _calculate_stats(self, targets: List[Dict], scans_by_ip: Dict) -> Dict[str, int]:
        """Calculate overall statistics."""
        total_scans = sum(len(scans) for scans in scans_by_ip.values())
        total_vulns = 0
        critical_vulns = 0
        
        for scans in scans_by_ip.values():
            for scan in scans:
                total_vulns += scan.get('total_vulnerabilities', 0)
                critical_vulns += scan.get('critical_count', 0)
        
        return {
            'total_targets': len(targets),
            'total_scans': total_scans,
            'total_vulns': total_vulns,
            'critical_vulns': critical_vulns
        }
    
    def _get_max_severity(self, scans: List[Dict]) -> str:
        """Get maximum severity across all scans for a target."""
        severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        max_severity = 'INFO'
        
        for scan in scans:
            if scan.get('critical_count', 0) > 0:
                return 'CRITICAL'
            elif scan.get('high_count', 0) > 0 and severities.index('HIGH') > severities.index(max_severity):
                max_severity = 'HIGH'
            elif scan.get('medium_count', 0) > 0 and severities.index('MEDIUM') > severities.index(max_severity):
                max_severity = 'MEDIUM'
            elif scan.get('low_count', 0) > 0 and severities.index('LOW') > severities.index(max_severity):
                max_severity = 'LOW'
        
        return max_severity
    
    def _format_datetime(self, dt_string: str) -> str:
        """Format datetime string for display."""
        try:
            dt = datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
            return dt.strftime('%d/%m/%Y %H:%M')
        except:
            return dt_string
    
    def _get_css(self) -> str:
        """Get CSS styles for dashboard."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .header {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            color: #667eea;
            margin-bottom: 5px;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 20px;
        }
        
        .stats-bar {
            display: flex;
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat-item {
            flex: 1;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-label {
            display: block;
            font-size: 0.9rem;
            color: #666;
            margin-bottom: 5px;
        }
        
        .stat-value {
            display: block;
            font-size: 1.8rem;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-value.critical {
            color: #dc3545;
        }
        
        /* Main Content Layout */
        .main-content {
            display: grid;
            grid-template-columns: 350px 1fr;
            gap: 20px;
        }
        
        /* Sidebar */
        .sidebar {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            max-height: calc(100vh - 280px);
            overflow-y: auto;
        }
        
        .sidebar h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.3rem;
        }
        
        .target-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .target-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            border-left: 4px solid transparent;
        }
        
        .target-item:hover {
            background: #e9ecef;
            transform: translateX(5px);
        }
        
        .target-item.active {
            background: #e7e9ff;
            border-left-color: #667eea;
        }
        
        .target-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        
        .target-ip {
            font-weight: bold;
            font-size: 1.1rem;
        }
        
        .target-meta {
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            color: #666;
        }
        
        /* Timeline Container */
        .timeline-container {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            max-height: calc(100vh - 280px);
            overflow-y: auto;
        }
        
        .timeline-section {
            animation: fadeIn 0.3s;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .timeline-header {
            margin-bottom: 30px;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 15px;
        }
        
        .timeline-header h2 {
            color: #667eea;
            margin-bottom: 5px;
        }
        
        .timeline {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        /* Scan Cards */
        .scan-card {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            border-left: 5px solid #ccc;
            transition: all 0.3s;
        }
        
        .scan-card:hover {
            box-shadow: 0 6px 12px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }
        
        .scan-card.critical-border { border-left-color: #dc3545; }
        .scan-card.high-border { border-left-color: #fd7e14; }
        .scan-card.medium-border { border-left-color: #ffc107; }
        .scan-card.low-border { border-left-color: #0dcaf0; }
        .scan-card.info-border { border-left-color: #198754; }
        
        .scan-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .scan-date {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 500;
            color: #333;
        }
        
        .scan-card-body {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .scan-info {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
        }
        
        .info-row .label {
            color: #666;
            font-weight: 500;
        }
        
        .info-row .value {
            font-weight: bold;
        }
        
        .cvss-score {
            color: #dc3545;
        }
        
        .status-completed { color: #198754; }
        .status-failed { color: #dc3545; }
        .status-partial { color: #ffc107; }
        
        .vuln-summary h4 {
            color: #333;
            margin-bottom: 10px;
            font-size: 1rem;
        }
        
        .vuln-bars {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        
        .vuln-bar {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.9rem;
        }
        
        .vuln-label {
            min-width: 70px;
            color: #666;
        }
        
        .vuln-count {
            font-weight: bold;
            min-width: 25px;
        }
        
        .vuln-count.critical { color: #dc3545; }
        .vuln-count.high { color: #fd7e14; }
        .vuln-count.medium { color: #ffc107; }
        .vuln-count.low { color: #0dcaf0; }
        
        .vuln-progress {
            flex: 1;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .vuln-fill {
            height: 100%;
            transition: width 0.3s;
        }
        
        .vuln-fill.critical { background: #dc3545; }
        .vuln-fill.high { background: #fd7e14; }
        .vuln-fill.medium { background: #ffc107; }
        .vuln-fill.low { background: #0dcaf0; }
        
        .scan-card-footer {
            text-align: right;
            padding-top: 15px;
            border-top: 1px solid #dee2e6;
        }
        
        .btn-view-report {
            display: inline-block;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            transition: all 0.3s;
        }
        
        .btn-view-report:hover {
            background: #5568d3;
            transform: translateX(5px);
        }
        
        /* Severity Badges */
        .severity-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }
        
        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #0dcaf0; }
        .severity-badge.info { background: #198754; }
        
        .no-data {
            text-align: center;
            padding: 40px;
            color: #999;
            font-size: 1.1rem;
        }
        
        /* Responsive */
        @media (max-width: 1024px) {
            .main-content {
                grid-template-columns: 1fr;
            }
            
            .sidebar {
                max-height: 400px;
            }
            
            .scan-card-body {
                grid-template-columns: 1fr;
            }
        }
        
        /* Scrollbar Styling */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #f1f1f1;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #5568d3;
        }
        """
    
    def _get_javascript(self) -> str:
        """Get JavaScript for interactivity."""
        return """
        function showTarget(ip) {
            // Hide all timeline sections
            const sections = document.querySelectorAll('.timeline-section');
            sections.forEach(section => {
                section.style.display = 'none';
            });
            
            // Show selected timeline
            const selectedTimeline = document.getElementById('timeline-' + ip);
            if (selectedTimeline) {
                selectedTimeline.style.display = 'block';
            }
            
            // Update active state in sidebar
            const items = document.querySelectorAll('.target-item');
            items.forEach(item => {
                item.classList.remove('active');
                if (item.dataset.target === ip) {
                    item.classList.add('active');
                }
            });
        }
        
        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
        """


# =========================================
# USAGE EXAMPLE
# =========================================

if __name__ == "__main__":
    # Example with mock data
    mock_targets = [
        {'ip_address': '192.168.1.100', 'total_scans': 3, 'last_scanned': '2025-11-12 10:30:00'},
        {'ip_address': '10.0.0.50', 'total_scans': 2, 'last_scanned': '2025-11-12 09:15:00'}
    ]
    
    mock_scans = [
        {
            'id': 1,
            'target_ip': '192.168.1.100',
            'scan_date': '2025-11-12 10:30:00',
            'profile_used': 'standard',
            'status': 'completed',
            'total_vulnerabilities': 15,
            'critical_count': 2,
            'high_count': 5,
            'medium_count': 6,
            'low_count': 2,
            'max_cvss_score': 9.8
        },
        {
            'id': 2,
            'target_ip': '192.168.1.100',
            'scan_date': '2025-11-11 15:20:00',
            'profile_used': 'quick',
            'status': 'completed',
            'total_vulnerabilities': 8,
            'critical_count': 0,
            'high_count': 2,
            'medium_count': 4,
            'low_count': 2,
            'max_cvss_score': 7.5
        }
    ]
    
    generator = DashboardGenerator()
    generator.generate(mock_targets, mock_scans, "test_dashboard.html")
    print("[✓] Dashboard de ejemplo generado: reports/test_dashboard.html")
