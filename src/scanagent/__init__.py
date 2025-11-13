"""
Scan Agent - Vulnerability Scanner and Analyzer
Version 2.1.0

Agente inteligente para análisis automático de vulnerabilidades web.
Incluye capacidades de escaneo, parsing, análisis e informes.
"""

__version__ = "2.1.0"
__author__ = "Scan Agent Team"
__license__ = "MIT"

from .agent import ScanAgent
from .scanner import VulnerabilityScanner
from .parser import ScanParser
from .interpreter import VulnerabilityInterpreter
from .report_generator import ReportGenerator
from .dashboard_generator import DashboardGenerator
from .database import DatabaseManager

__all__ = [
    'ScanAgent',
    'VulnerabilityScanner', 
    'ScanParser',
    'VulnerabilityInterpreter',
    'ReportGenerator',
    'DashboardGenerator',
    'DatabaseManager'
]
