#!/usr/bin/env python3
"""
database.py - Database Manager for Scan Agent v2.1
==================================================

Manages SQLite database for storing scan results, vulnerabilities,
and generating historical reports.

Features:
- Automatic schema initialization
- CRUD operations for scans, vulnerabilities, services, endpoints
- Query helpers for dashboard generation
- Transaction management
- Error handling and logging

Author: Scan Agent Team
Version: 2.1.0
Date: 2025-11-12
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


class DatabaseManager:
    """Manages all database operations for Scan Agent."""
    
    def __init__(self, db_path: str = None, schema_file: str = None):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file (default: data/scan_agent.db)
            schema_file: Path to SQL schema file (default: config/schema.sql)
        """
        # Use project root paths
        base_dir = Path(__file__).parent.parent.parent
        self.db_path = db_path or str(base_dir / "data" / "scan_agent.db")
        self.schema_file = schema_file or str(base_dir / "config" / "schema.sql")
        self.conn: Optional[sqlite3.Connection] = None
        
        # Initialize database if it doesn't exist
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """Initialize database with schema if it doesn't exist."""
        db_exists = os.path.exists(self.db_path)
        
        if not db_exists:
            print(f"[*] Creando base de datos: {self.db_path}")
            
            # Create database connection
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
            
            # Always use basic schema (avoid SQL parsing issues)
            print(f"[*] Inicializando esquema de base de datos...")
            self._create_basic_schema()
        else:
            # Connect to existing database
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
    
    def _create_basic_schema(self) -> None:
        """Create basic schema if schema.sql is not found."""
        cursor = self.conn.cursor()
        
        # Basic scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                profile_used TEXT NOT NULL,
                duration_seconds INTEGER,
                status TEXT NOT NULL,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                max_cvss_score REAL DEFAULT 0.0,
                files_processed INTEGER DEFAULT 0,
                tools_used TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Basic vulnerabilities table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL,
                description TEXT,
                category TEXT,
                owasp_mapping TEXT,
                cve_id TEXT,
                affected_component TEXT,
                evidence TEXT,
                recommendation TEXT,
                refs TEXT
            )
        """)
        
        # Basic parsed_data table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS parsed_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                data_type TEXT NOT NULL,
                json_data TEXT NOT NULL
            )
        """)
        
        # Basic services table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT,
                service_version TEXT,
                state TEXT,
                banner TEXT,
                extra_info TEXT
            )
        """)
        
        # Basic endpoints table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                status_code INTEGER,
                method TEXT DEFAULT 'GET',
                discovered_by TEXT
            )
        """)
        
        # Basic headers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS headers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                header_name TEXT NOT NULL,
                header_value TEXT,
                is_security_header INTEGER DEFAULT 0
            )
        """)
        
        # Basic targets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                first_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_scans INTEGER DEFAULT 1
            )
        """)
        
        self.conn.commit()
        print("[✓] Esquema básico creado")
    
    def get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def close(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    # =========================================
    # SAVE OPERATIONS
    # =========================================
    
    def save_scan(
        self,
        target_ip: str,
        profile_used: str,
        duration_seconds: int,
        status: str,
        analysis_data: Dict[str, Any],
        parsed_data: Dict[str, Any],
        files_processed: int = 0,
        tools_used: List[str] = None
    ) -> int:
        """
        Save a complete scan to database.
        
        Args:
            target_ip: IP or hostname scanned
            profile_used: Scan profile name
            duration_seconds: Total scan duration
            status: 'completed', 'failed', or 'partial'
            analysis_data: Analyzed vulnerability data
            parsed_data: Raw parsed data from tools
            files_processed: Number of files processed
            tools_used: List of tools used
        
        Returns:
            scan_id: ID of inserted scan
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            # Extract vulnerability counts
            vulns = analysis_data.get('vulnerabilities', [])
            severity_counts = self._count_by_severity(vulns)
            max_cvss = self._get_max_cvss(vulns)
            
            # Insert scan record
            cursor.execute("""
                INSERT INTO scans (
                    target_ip, profile_used, duration_seconds, status,
                    total_vulnerabilities, critical_count, high_count,
                    medium_count, low_count, info_count, max_cvss_score,
                    files_processed, tools_used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target_ip,
                profile_used,
                duration_seconds,
                status,
                len(vulns),
                severity_counts.get('CRITICAL', 0),
                severity_counts.get('HIGH', 0),
                severity_counts.get('MEDIUM', 0),
                severity_counts.get('LOW', 0),
                severity_counts.get('INFO', 0),
                max_cvss,
                files_processed,
                ','.join(tools_used) if tools_used else None
            ))
            
            scan_id = cursor.lastrowid
            
            # Save parsed data as JSON
            cursor.execute("""
                INSERT INTO parsed_data (scan_id, data_type, json_data)
                VALUES (?, ?, ?)
            """, (scan_id, 'parsed', json.dumps(parsed_data)))
            
            # Save analysis data as JSON
            cursor.execute("""
                INSERT INTO parsed_data (scan_id, data_type, json_data)
                VALUES (?, ?, ?)
            """, (scan_id, 'analysis', json.dumps(analysis_data)))
            
            # Save individual vulnerabilities
            for vuln in vulns:
                self._save_vulnerability(cursor, scan_id, vuln)
            
            # Save services if available
            services = parsed_data.get('services', [])
            for service in services:
                self._save_service(cursor, scan_id, service)
            
            # Save endpoints if available
            endpoints = parsed_data.get('endpoints', [])
            for endpoint in endpoints:
                self._save_endpoint(cursor, scan_id, endpoint)
            
            # Save headers if available
            headers_data = parsed_data.get('headers', {})
            if headers_data:
                self._save_headers(cursor, scan_id, headers_data)
            
            conn.commit()
            print(f"[✓] Escaneo guardado en BD con ID: {scan_id}")
            
            return scan_id
            
        except Exception as e:
            conn.rollback()
            print(f"[✗] Error guardando escaneo en BD: {e}")
            raise
    
    def _save_vulnerability(self, cursor: sqlite3.Cursor, scan_id: int, vuln: Dict) -> None:
        """Save individual vulnerability."""
        cursor.execute("""
            INSERT INTO vulnerabilities (
                scan_id, title, description, severity, cvss_score,
                cvss_vector, category, owasp_mapping, cve_id,
                affected_component, evidence, recommendation, refs
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            vuln.get('title', 'Unknown'),
            vuln.get('description', ''),
            vuln.get('severity', 'INFO'),
            vuln.get('cvss_score', 0.0),
            vuln.get('cvss_vector', ''),
            vuln.get('category', ''),
            vuln.get('owasp_category', ''),
            vuln.get('cve_id', ''),
            vuln.get('affected_component', ''),
            vuln.get('evidence', ''),
            vuln.get('recommendation', ''),
            vuln.get('references', '')
        ))
    
    def _save_service(self, cursor: sqlite3.Cursor, scan_id: int, service: Dict) -> None:
        """Save discovered service."""
        cursor.execute("""
            INSERT INTO services (
                scan_id, port, protocol, service_name, service_version,
                state, banner, extra_info
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            service.get('port'),
            service.get('protocol', 'tcp'),
            service.get('service', ''),
            service.get('version', ''),
            service.get('state', 'open'),
            service.get('banner', ''),
            service.get('extra_info', '')
        ))
    
    def _save_endpoint(self, cursor: sqlite3.Cursor, scan_id: int, endpoint: Dict) -> None:
        """Save discovered endpoint."""
        cursor.execute("""
            INSERT INTO endpoints (
                scan_id, url, status_code, method, discovered_by
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            endpoint.get('url', ''),
            endpoint.get('status_code'),
            endpoint.get('method', 'GET'),
            endpoint.get('source', 'unknown')
        ))
    
    def _save_headers(self, cursor: sqlite3.Cursor, scan_id: int, headers: Dict) -> None:
        """Save HTTP headers."""
        for name, value in headers.items():
            cursor.execute("""
                INSERT INTO headers (
                    scan_id, header_name, header_value, is_security_header
                ) VALUES (?, ?, ?, ?)
            """, (
                scan_id,
                name,
                str(value),
                self._is_security_header(name)
            ))
    
    def save_scan_file(self, scan_id: int, file_type: str, file_path: str) -> None:
        """
        Save file reference for a scan.
        
        Args:
            scan_id: Scan ID
            file_type: Type of file (nmap_service, report_html, etc.)
            file_path: Path to file
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        
        cursor.execute("""
            INSERT INTO scan_files (scan_id, file_type, file_path, file_size_bytes)
            VALUES (?, ?, ?, ?)
        """, (scan_id, file_type, file_path, file_size))
        
        conn.commit()
    
    # =========================================
    # QUERY OPERATIONS
    # =========================================
    
    def get_all_scans(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """
        Get all scans ordered by date (most recent first).
        
        Args:
            limit: Maximum number of results
            offset: Offset for pagination
        
        Returns:
            List of scan dictionaries
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM scans
            ORDER BY scan_date DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_scans_by_ip(self, ip_address: str) -> List[Dict]:
        """
        Get all scans for a specific IP address.
        
        Args:
            ip_address: Target IP address
        
        Returns:
            List of scan dictionaries
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM scans
            WHERE target_ip = ?
            ORDER BY scan_date DESC
        """, (ip_address,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_scan_detail(self, scan_id: int) -> Optional[Dict]:
        """
        Get detailed information for a specific scan.
        
        Args:
            scan_id: Scan ID
        
        Returns:
            Dictionary with scan details including vulnerabilities
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Get scan metadata
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan = cursor.fetchone()
        
        if not scan:
            return None
        
        scan_dict = dict(scan)
        
        # Get vulnerabilities
        cursor.execute("""
            SELECT * FROM vulnerabilities
            WHERE scan_id = ?
            ORDER BY cvss_score DESC
        """, (scan_id,))
        scan_dict['vulnerabilities'] = [dict(row) for row in cursor.fetchall()]
        
        # Get services
        cursor.execute("""
            SELECT * FROM services
            WHERE scan_id = ?
            ORDER BY port ASC
        """, (scan_id,))
        scan_dict['services'] = [dict(row) for row in cursor.fetchall()]
        
        # Get endpoints
        cursor.execute("""
            SELECT * FROM endpoints
            WHERE scan_id = ?
        """, (scan_id,))
        scan_dict['endpoints'] = [dict(row) for row in cursor.fetchall()]
        
        # Get parsed/analysis data
        cursor.execute("""
            SELECT data_type, json_data FROM parsed_data
            WHERE scan_id = ?
        """, (scan_id,))
        
        for row in cursor.fetchall():
            data_type = row['data_type']
            scan_dict[f'{data_type}_data'] = json.loads(row['json_data'])
        
        return scan_dict
    
    def get_targets(self) -> List[Dict]:
        """
        Get all unique targets scanned.
        
        Returns:
            List of target dictionaries with scan counts
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM targets
            ORDER BY last_scanned DESC
        """)
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_target_with_scans(self, ip_address: str) -> Optional[Dict]:
        """
        Get target info with all its scans.
        
        Args:
            ip_address: Target IP address
        
        Returns:
            Dictionary with target info and scans list
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Get target info
        cursor.execute("SELECT * FROM targets WHERE ip_address = ?", (ip_address,))
        target = cursor.fetchone()
        
        if not target:
            return None
        
        target_dict = dict(target)
        target_dict['scans'] = self.get_scans_by_ip(ip_address)
        
        return target_dict
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict]:
        """Get most recent scans using the view."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT * FROM v_recent_scans LIMIT {limit}")
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_critical_vulnerabilities(self, limit: int = 50) -> List[Dict]:
        """Get critical and high vulnerabilities."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(f"SELECT * FROM v_critical_vulnerabilities LIMIT {limit}")
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall database statistics.
        
        Returns:
            Dictionary with statistics
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Total scans
        cursor.execute("SELECT COUNT(*) as count FROM scans")
        stats['total_scans'] = cursor.fetchone()['count']
        
        # Unique targets
        cursor.execute("SELECT COUNT(*) as count FROM targets")
        stats['unique_targets'] = cursor.fetchone()['count']
        
        # Total vulnerabilities
        cursor.execute("SELECT SUM(total_vulnerabilities) as total FROM scans")
        stats['total_vulnerabilities'] = cursor.fetchone()['total'] or 0
        
        # Severity counts
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM vulnerabilities
            GROUP BY severity
        """)
        stats['by_severity'] = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Most scanned target
        cursor.execute("""
            SELECT ip_address, total_scans
            FROM targets
            ORDER BY total_scans DESC
            LIMIT 1
        """)
        most_scanned = cursor.fetchone()
        if most_scanned:
            stats['most_scanned_target'] = dict(most_scanned)
        
        return stats
    
    # =========================================
    # UTILITY METHODS
    # =========================================
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _get_max_cvss(self, vulnerabilities: List[Dict]) -> float:
        """Get maximum CVSS score from vulnerabilities."""
        max_score = 0.0
        
        for vuln in vulnerabilities:
            score = vuln.get('cvss_score', 0.0)
            if isinstance(score, (int, float)) and score > max_score:
                max_score = float(score)
        
        return max_score
    
    def _is_security_header(self, header_name: str) -> bool:
        """Check if header is a security-related header."""
        security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'referrer-policy',
            'permissions-policy',
            'cross-origin-embedder-policy',
            'cross-origin-opener-policy',
            'cross-origin-resource-policy'
        ]
        return header_name.lower() in security_headers
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# =========================================
# USAGE EXAMPLE
# =========================================

if __name__ == "__main__":
    # Example usage
    with DatabaseManager() as db:
        # Get statistics
        stats = db.get_statistics()
        print(f"\n📊 Estadísticas de la Base de Datos:")
        print(f"  Total de escaneos: {stats['total_scans']}")
        print(f"  Objetivos únicos: {stats['unique_targets']}")
        print(f"  Total vulnerabilidades: {stats['total_vulnerabilities']}")
        
        # Get all targets
        targets = db.get_targets()
        print(f"\n🎯 Objetivos escaneados: {len(targets)}")
        for target in targets[:5]:
            print(f"  - {target['ip_address']}: {target['total_scans']} escaneos")
        
        # Get recent scans
        recent = db.get_recent_scans(limit=5)
        print(f"\n🕐 Escaneos recientes:")
        for scan in recent:
            print(f"  - {scan['target_ip']} ({scan['profile_used']}) - {scan['scan_date']}")
