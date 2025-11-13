#!/usr/bin/env python3
"""
Scan Agent - Main Module
=========================
Agente de software para análisis automático de vulnerabilidades web.

Este agente puede:
1. Ejecutar escaneos de vulnerabilidades (NUEVO v2.0)
2. Procesar archivos de salida de herramientas de pentesting
3. Analizar e interpretar vulnerabilidades
4. Generar informes técnicos profesionales

Autor: Scan Agent Team
Versión: 2.0.0
Licencia: MIT
"""

import argparse
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

# Importar módulos del agente
try:
    from scanagent.parser import ScanParser
    from scanagent.interpreter import VulnerabilityInterpreter
    from scanagent.report_generator import ReportGenerator
    from scanagent.scanner import VulnerabilityScanner  # NUEVO v2.0
    from scanagent.database import DatabaseManager  # NUEVO v2.1
    from scanagent.dashboard_generator import DashboardGenerator  # NUEVO v2.1
except ImportError as e:
    print(f"[ERROR] No se pudieron importar los módulos necesarios: {e}")
    print("Asegúrate de ejecutar desde la raíz del proyecto: python3 -m src.scanagent.agent")
    sys.exit(1)


class ScanAgent:
    """
    Agente principal de análisis de vulnerabilidades.
    
    Características:
    - Ejecuta escaneos de vulnerabilidades (v2.0)
    - Procesa múltiples formatos de archivo
    - Interpreta y clasifica vulnerabilidades
    - Genera informes en 4 formatos diferentes
    
    Versión: 2.1.0
    """
    
    VERSION = "2.1.0"
    
    def __init__(self, verbose: bool = False, use_database: bool = True):
        """
        Inicializa el agente con todos sus componentes.
        
        Args:
            verbose: Activar modo verboso para debug
            use_database: Guardar resultados en base de datos (default: True)
        """
        self.verbose = verbose
        self.use_database = use_database
        self.scanner = VulnerabilityScanner(verbose=verbose)  # v2.0
        self.parser = None  # Se inicializará cuando sea necesario
        self.interpreter = None  # Se inicializará cuando sea necesario
        self.report_generator = None
        self.db_manager = DatabaseManager() if use_database else None  # v2.1
        self.dashboard_generator = DashboardGenerator() if use_database else None  # v2.1
        
        # Estadísticas de ejecución
        self.stats = {
            'archivos_procesados': 0,
            'vulnerabilidades_encontradas': 0,
            'tiempo_inicio': None,
            'tiempo_fin': None,
            'scan_id': None  # ID del escaneo en BD
        }
    
    
    def execute_scan(self, target: str, profile: str, outputs_dir: str = "./outputs") -> bool:
        """
        NUEVA FUNCIONALIDAD v2.0: Ejecuta un escaneo de vulnerabilidades.
        
        Args:
            target: IP o dominio del objetivo
            profile: Perfil de escaneo a utilizar
            outputs_dir: Directorio donde guardar resultados
        
        Returns:
            True si el escaneo fue exitoso, False en caso contrario
        """
        self._print_phase("FASE 0: EJECUCIÓN DE ESCANEO")
        
        print(f"[*] Objetivo: {target}")
        print(f"[*] Perfil: {profile}")
        print(f"[*] Directorio de salida: {outputs_dir}\n")
        
        # Ejecutar escaneo
        success, scan_files = self.scanner.run_scan(target, profile, outputs_dir)
        
        if success:
            print(f"\n[✓] Escaneo completado exitosamente")
            print(f"[✓] Archivos generados: {len(scan_files)}")
            for file in scan_files:
                print(f"    - {file}")
            return True
        else:
            print(f"\n[✗] El escaneo falló o fue interrumpido")
            return False
    
    def run(self, target_ip: Optional[str] = None, output_format: str = "all", 
            outputs_dir: str = "./outputs", profile_used: str = "manual") -> bool:
        """
        Ejecuta el flujo completo del agente (parsing → análisis → informes → BD → dashboard).
        
        Args:
            target_ip: IP objetivo (se detecta automáticamente si no se provee)
            output_format: Formato de salida (txt, json, html, md, all)
            outputs_dir: Directorio donde buscar archivos de escaneo
            profile_used: Perfil utilizado para el escaneo (para BD)
        
        Returns:
            True si el proceso fue exitoso, False en caso contrario
        """
        try:
            self._print_header()
            self.stats['tiempo_inicio'] = datetime.now()
            
            # Validar directorio de salida
            outputs_path = Path(outputs_dir)
            if not outputs_path.exists():
                print(f"[ERROR] El directorio {outputs_dir} no existe")
                return False
            
            # FASE 1: PARSING
            self._print_phase("FASE 1: PARSING DE ARCHIVOS")
            parsed_data = self._execute_parsing(target_ip, outputs_dir)
            
            if not parsed_data:
                print("\n[ERROR] No se pudieron parsear los archivos")
                return False
            
            # FASE 2: INTERPRETACIÓN
            self._print_phase("FASE 2: ANÁLISIS E INTERPRETACIÓN")
            analysis = self._execute_interpretation(parsed_data)
            
            if not analysis:
                print("\n[ERROR] No se pudo completar el análisis")
                return False
            
            # FASE 3: GENERACIÓN DE INFORMES
            self._print_phase("FASE 3: GENERACIÓN DE INFORMES")
            reports = self._execute_report_generation(analysis, output_format)
            
            if not reports:
                print("\n[ERROR] No se pudieron generar los informes")
                return False
            
            # FASE 4: PERSISTENCIA EN BASE DE DATOS (v2.1)
            if self.use_database:
                self._print_phase("FASE 4: ALMACENAMIENTO EN BASE DE DATOS")
                self._save_to_database(target_ip, profile_used, parsed_data, analysis, outputs_dir)
                
                # FASE 5: GENERACIÓN DE DASHBOARD (v2.1)
                self._print_phase("FASE 5: GENERACIÓN DE DASHBOARD")
                self._generate_dashboard()
            
            # Finalizar
            self._print_summary()
            return True
            
        except KeyboardInterrupt:
            print("\n\n[!] Proceso interrumpido por el usuario")
            return False
        except Exception as e:
            print(f"\n[ERROR FATAL] {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
    
    def _execute_parsing(self, target_ip: Optional[str] = None, outputs_dir: str = "./outputs") -> dict:
        """
        Ejecuta la fase de parsing de archivos.
        
        Args:
            target_ip: IP objetivo
            outputs_dir: Directorio con archivos de escaneo
        
        Returns:
            Datos parseados o None si falló
        """
        try:
            # Inicializar parser si no existe
            if not self.parser:
                self.parser = ScanParser(outputs_dir)
            
            # Detectar archivos disponibles
            outputs_path = Path(outputs_dir)
            txt_files = list(outputs_path.glob("*.txt"))
            
            if not txt_files:
                print(f"[WARN] No se encontraron archivos .txt en {outputs_dir}")
                return None
            
            print(f"[*] Archivos encontrados: {len(txt_files)}")
            
            # Parsear todos los archivos
            parsed_data = self.parser.parse_all(target_ip)
            
            if not parsed_data:
                return None
            
            # Guardar JSON intermedio
            json_output = Path("parsed_data.json")
            with open(json_output, 'w', encoding='utf-8') as f:
                json.dump(parsed_data, f, indent=2, ensure_ascii=False)
            
            print(f"[✓] Datos parseados guardados en: {json_output}")
            self.stats['archivos_procesados'] = len(txt_files)
            return parsed_data
            
        except Exception as e:
            print(f"[ERROR] Durante el parsing: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None
    
    def _execute_interpretation(self, parsed_data: dict) -> dict:
        """
        Ejecuta la fase de interpretación y análisis de vulnerabilidades.
        
        Args:
            parsed_data: Datos parseados de los archivos
        
        Returns:
            Análisis completo o None si falló
        """
        try:
            # Inicializar interpreter si no existe
            if not self.interpreter:
                self.interpreter = VulnerabilityInterpreter(parsed_data)
            
            analysis = self.interpreter.analyze()
            
            if analysis:
                # Guardar análisis intermedio
                analysis_file = Path("analysis.json")
                with open(analysis_file, 'w', encoding='utf-8') as f:
                    json.dump(analysis, f, indent=2, ensure_ascii=False)
                
                vulns = analysis.get("vulnerabilidades", [])
                self.stats['vulnerabilidades_encontradas'] = len(vulns)
                
                print(f"[✓] Vulnerabilidades detectadas: {len(vulns)}")
                print(f"[✓] Análisis guardado en: {analysis_file}")
            
            return analysis
            
        except Exception as e:
            print(f"[ERROR] Durante la interpretación: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None
    
    def _execute_report_generation(self, analysis: dict, output_format: str) -> list:
        """
        Ejecuta la fase de generación de informes.
        
        Args:
            analysis: Análisis de vulnerabilidades
            output_format: Formato(s) de salida (txt, json, html, md, all)
        
        Returns:
            Lista de archivos generados o None si falló
        """
        try:
            self.report_generator = ReportGenerator(analysis)
            
            generated_files = []
            
            if output_format == "all":
                formats = ["txt", "json", "html", "md"]
            else:
                formats = [output_format]
            
            # Generar cada formato
            for fmt in formats:
                output_file = f"informe_tecnico.{fmt}"
                
                if fmt == "txt":
                    self.report_generator.generate_txt_report(output_file)
                elif fmt == "json":
                    self.report_generator.generate_json_report(output_file)
                elif fmt == "html":
                    # Pasar scan_id si está disponible para renombrar
                    scan_id = self.stats.get('scan_id')
                    self.report_generator.generate_html_report(output_file, scan_id=scan_id)
                elif fmt == "md":
                    self.report_generator.generate_markdown_report(output_file)
                else:
                    print(f"[WARN] Formato desconocido: {fmt}")
                    continue
                
                generated_files.append(output_file)
                print(f"[✓] Informe generado: {output_file}")
            
            return generated_files
            
        except Exception as e:
            print(f"[ERROR] Durante la generación de informes: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None
    
    def _save_to_database(self, target_ip: str, profile_used: str, 
                         parsed_data: dict, analysis: dict, outputs_dir: str) -> None:
        """
        Guarda el escaneo en la base de datos.
        
        Args:
            target_ip: IP objetivo
            profile_used: Perfil utilizado
            parsed_data: Datos parseados
            analysis: Análisis de vulnerabilidades
            outputs_dir: Directorio de outputs
        """
        try:
            if not self.db_manager:
                return
            
            # Calcular duración del escaneo
            duration = 0
            if self.stats['tiempo_inicio'] and self.stats['tiempo_fin']:
                delta = self.stats['tiempo_fin'] - self.stats['tiempo_inicio']
                duration = int(delta.total_seconds())
            
            # Determinar target_ip si no se proporcionó
            if not target_ip:
                target_ip = analysis.get('metadata', {}).get('target_ip', 'unknown')
            
            # Guardar en BD
            scan_id = self.db_manager.save_scan(
                target_ip=target_ip,
                profile_used=profile_used,
                duration_seconds=duration,
                status='completed',
                analysis_data=analysis,
                parsed_data=parsed_data,
                files_processed=self.stats['archivos_procesados'],
                tools_used=['nmap', 'nikto', 'gobuster', 'curl']  # Detectar automáticamente
            )
            
            self.stats['scan_id'] = scan_id
            print(f"[✓] Escaneo guardado en BD con ID: {scan_id}")
            
        except Exception as e:
            print(f"[WARN] No se pudo guardar en BD: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
    
    def _generate_dashboard(self) -> None:
        """
        Genera el dashboard HTML con el histórico de escaneos.
        """
        try:
            if not self.dashboard_generator or not self.db_manager:
                return
            
            # Obtener datos de la BD
            targets = self.db_manager.get_targets()
            all_scans = self.db_manager.get_all_scans(limit=1000)
            
            # Generar dashboard
            dashboard_path = self.dashboard_generator.generate(
                targets=targets,
                all_scans=all_scans,
                output_file="dashboard.html"
            )
            
            print(f"[✓] Dashboard actualizado: {dashboard_path}")
            
        except Exception as e:
            print(f"[WARN] No se pudo generar dashboard: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
    
    def _print_header(self) -> None:
        """
        Finaliza la ejecución y muestra estadísticas.
        """
        self.stats['tiempo_fin'] = datetime.now()
        elapsed = (self.stats['tiempo_fin'] - self.stats['tiempo_inicio']).total_seconds()
        
        print("\n" + "=" * 80)
        print("✅ PROCESO COMPLETADO EXITOSAMENTE")
        print("=" * 80)
        print("\n📊 ESTADÍSTICAS DE EJECUCIÓN:")
        print(f"  • Archivos procesados:         {self.stats['archivos_procesados']}")
        print(f"  • Vulnerabilidades detectadas: {self.stats['vulnerabilidades_encontradas']}")
        print(f"  • Tiempo de ejecución:         {elapsed:.2f} segundos")
        print("\n💡 PRÓXIMOS PASOS:")
        print("  1. Revisa el archivo informe_tecnico.html en tu navegador")
        print("  2. Lee el resumen ejecutivo para priorizar acciones")
        print("  3. Implementa las recomendaciones de corto plazo inmediatamente")
        print("\n" + "=" * 80)
    
    def _print_header(self) -> None:
        """
        Imprime el header del agente.
        """
        print("\n" + "=" * 80)
        print("  ____   ____    _    _   _      _    ____ _____ _   _ _____ ")
        print(" / ___| / ___|  / \\  | \\ | |    / \\  / ___| ____| \\ | |_   _|")
        print(" \\___ \\| |     / _ \\ |  \\| |   / _ \\| |  _|  _| |  \\| | | |  ")
        print("  ___) | |___ / ___ \\| |\\  |  / ___ \\ |_| | |___| |\\  | | |  ")
        print(" |____/ \\____/_/   \\_\\_| \\_| /_/   \\_\\____|_____|_| \\_| |_|  ")
        print("")
        print(f" Agente de Análisis de Vulnerabilidades Web v{self.VERSION}")
        print(" " + "=" * 78)
        print(f" Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(" " + "=" * 78)
        print()
    
    def _print_phase(self, phase_name: str) -> None:
        """
        Imprime el nombre de una fase.
        """
        print("\n" + "-" * 80)
        print(f"🔍 {phase_name}")
        print("-" * 80)
    
    def _print_summary(self) -> None:
        """
        Imprime el resumen final de ejecución.
        """
        self.stats['tiempo_fin'] = datetime.now()
        elapsed = (self.stats['tiempo_fin'] - self.stats['tiempo_inicio']).total_seconds()
        
        print("\n" + "=" * 80)
        print("✅ PROCESO COMPLETADO EXITOSAMENTE")
        print("=" * 80)
        print("\n📊 ESTADÍSTICAS DE EJECUCIÓN:")
        print(f"  • Archivos procesados:         {self.stats['archivos_procesados']}")
        print(f"  • Vulnerabilidades detectadas: {self.stats['vulnerabilidades_encontradas']}")
        print(f"  • Tiempo de ejecución:         {elapsed:.2f} segundos")
        
        if self.use_database and self.stats.get('scan_id'):
            print(f"  • ID de escaneo en BD:          {self.stats['scan_id']}")
            print("\n📁 ARCHIVOS GENERADOS:")
            print("  1. Informe HTML: informe_tecnico.html")
            print("  2. Dashboard: reports/dashboard.html")
            print("\n💡 PRÓXIMOS PASOS:")
            print("  1. Abre reports/dashboard.html para ver el histórico")
            print("  2. Revisa el informe HTML para detalles del último escaneo")
            print("  3. Implementa las recomendaciones de corto plazo inmediatamente")
        else:
            print("\n💡 PRÓXIMOS PASOS:")
            print("  1. Revisa el archivo informe_tecnico.html en tu navegador")
            print("  2. Lee el resumen ejecutivo para priorizar acciones")
            print("  3. Implementa las recomendaciones de corto plazo inmediatamente")
        
        print("\n" + "=" * 80)


def main():
    """
    Función principal del agente.
    """
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(
        description="Scan Agent v2.0 - Agente de análisis automático de vulnerabilidades web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  
  MODO ANÁLISIS (v1.0 - archivos existentes):
  ──────────────────────────────────────────
  python3 agent.py
  python3 agent.py --outputs-dir ./outputs --format html
  python3 agent.py --target-ip 192.168.1.100 --verbose
  
  MODO ESCANEO (v2.0 - NUEVO):
  ────────────────────────────
  python3 agent.py --scan --target 192.168.1.100 --profile quick
  python3 agent.py --scan --target example.com --profile web
  python3 agent.py --scan --target 10.0.0.5 --profile full --outputs-dir ./mi_escaneo
  
  LISTAR PERFILES DE ESCANEO:
  ───────────────────────────
  python3 agent.py --list-profiles
  python3 agent.py --show-profile web
  
  WORKFLOW COMPLETO (escaneo + análisis):
  ───────────────────────────────────────
  python3 agent.py --scan --target 192.168.1.100 --profile standard
  python3 agent.py --outputs-dir ./outputs --format all

Formatos de salida:
  txt   - Informe en texto plano
  json  - Datos estructurados en JSON
  html  - Informe web interactivo (recomendado)
  md    - Documentación en Markdown
  all   - Todos los formatos (por defecto)

Perfiles de escaneo disponibles:
  quick      - Escaneo rápido (5 min)
  standard   - Escaneo estándar (15 min)
  full       - Escaneo completo (30-60 min)
  web        - Escaneo enfocado en aplicaciones web
  stealth    - Escaneo sigiloso (requiere sudo)
  network    - Escaneo de infraestructura de red
  compliance - Escaneo de cumplimiento normativo
  api        - Escaneo de APIs REST/SOAP
        """
    )
    
    # Argumentos de escaneo (NUEVO v2.0)
    scan_group = parser.add_argument_group('Opciones de escaneo (v2.0)')
    scan_group.add_argument(
        '--scan',
        action='store_true',
        help='Ejecutar escaneo de vulnerabilidades'
    )
    scan_group.add_argument(
        '--target',
        help='IP o dominio objetivo para escaneo'
    )
    scan_group.add_argument(
        '--profile',
        help='Perfil de escaneo a utilizar (usa --list-profiles para ver opciones)'
    )
    scan_group.add_argument(
        '--list-profiles',
        action='store_true',
        help='Listar perfiles de escaneo disponibles'
    )
    scan_group.add_argument(
        '--show-profile',
        metavar='PROFILE',
        help='Mostrar detalles de un perfil específico'
    )
    
    # Argumentos de análisis (v1.0)
    analysis_group = parser.add_argument_group('Opciones de análisis')
    analysis_group.add_argument(
        '--outputs-dir',
        default='./outputs',
        help='Directorio donde se encuentran/guardan los archivos de escaneo (default: ./outputs)'
    )
    analysis_group.add_argument(
        '--target-ip',
        help='IP objetivo del análisis (se detecta automáticamente si no se especifica)'
    )
    analysis_group.add_argument(
        '--format',
        choices=['txt', 'json', 'html', 'md', 'all'],
        default='all',
        help='Formato de salida del informe (default: all)'
    )
    
    # Argumentos generales
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Mostrar información detallada del proceso'
    )
    parser.add_argument(
        '--no-db',
        action='store_true',
        help='Deshabilitar almacenamiento en base de datos y dashboard (v2.1)'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'Scan Agent v{ScanAgent.VERSION}'
    )
    
    args = parser.parse_args()
    
    # Crear agente
    agent = ScanAgent(verbose=args.verbose, use_database=not args.no_db)
    
    # Manejar comandos de información
    if args.list_profiles:
        agent.scanner.list_profiles()
        sys.exit(0)
    
    if args.show_profile:
        agent.scanner.show_profile_details(args.show_profile)
        sys.exit(0)
    
    # Modo escaneo
    if args.scan:
        if not args.target:
            print("[ERROR] Debes especificar un objetivo con --target")
            print("Ejemplo: python3 agent.py --scan --target 192.168.1.100 --profile quick")
            sys.exit(1)
        
        if not args.profile:
            print("[ERROR] Debes especificar un perfil con --profile")
            print("Usa --list-profiles para ver los perfiles disponibles")
            sys.exit(1)
        
        # Ejecutar escaneo
        success = agent.execute_scan(
            target=args.target,
            profile=args.profile,
            outputs_dir=args.outputs_dir
        )
        
        if success:
            print("\n[✓] Escaneo completado. Los archivos están en:", args.outputs_dir)
            
            # Ejecutar análisis automáticamente después del escaneo
            print("\n[*] Ejecutando análisis automático...")
            analysis_success = agent.run(
                target_ip=args.target,
                output_format=args.format,
                outputs_dir=args.outputs_dir,
                profile_used=args.profile
            )
            
            if analysis_success and agent.use_database:
                print("\n[✓] Dashboard disponible en: reports/dashboard.html")
            
            sys.exit(0 if analysis_success else 1)
        
        sys.exit(1)
    
    # Modo análisis (comportamiento original v1.0)
    success = agent.run(
        target_ip=args.target_ip,
        output_format=args.format,
        outputs_dir=args.outputs_dir
    )
    
    # Salir con código apropiado
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
